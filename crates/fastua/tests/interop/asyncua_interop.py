#!/usr/bin/env python3
"""Interoperability check against the asyncua (python-opcua) client.

usage: asyncua_interop.py <path to fastua binary> <config dir>

Starts the server in a temporary directory and exercises every security
policy and mode, the certificate trust flow, user name / password and X.509
user authentication, access rights and hot reload. Exits non-zero on failure.
"""
import asyncio, datetime, glob, json, os, shutil, subprocess, sys, tempfile, time
from asyncua import Client, ua
from asyncua.crypto import uacrypto
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PORT = 48555
URL = f"opc.tcp://127.0.0.1:{PORT}"
FAILURES = []


def make_cert(path, name, uri, bits=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri), x509.DNSName("localhost")]), False)
            .add_extension(x509.KeyUsage(True, True, True, True, False, True, False, False, False), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .sign(key, hashes.SHA256()))
    open(f"{path}.der", "wb").write(cert.public_bytes(serialization.Encoding.DER))
    open(f"{path}.pem", "wb").write(key.private_bytes(serialization.Encoding.PEM,
                                                      serialization.PrivateFormat.TraditionalOpenSSL,
                                                      serialization.NoEncryption()))


def check(label, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + label + (f"  ({detail})" if detail else ""))
    if not ok:
        FAILURES.append(label)


def client(work, security=None, cert="client", user=None, password=None):
    c = Client(URL, timeout=5)
    c.application_uri = "urn:example:client"
    if user:
        c.set_user(user)
        c.set_password(password)
    return c, (f"{security},{work}/{cert}.der,{work}/{cert}.pem" if security else None)


async def session(work, security=None, cert="client", user=None, password=None, x509_user=False):
    c, sec = client(work, security, cert, user, password)
    if sec:
        await c.set_security_string(sec)
    if x509_user:
        c.user_certificate = await uacrypto.load_certificate(f"{work}/user.der")
        c.user_private_key = await uacrypto.load_private_key(f"{work}/user.pem")
    await c.connect()
    return c


async def expect_error(label, coro, name):
    try:
        c = await coro
        await c.disconnect()
        check(label, False, "no error")
    except Exception as e:
        check(label, name in type(e).__name__ or name in str(e), type(e).__name__)


async def main(work, cfg):
    machine = ua.NodeId(1000, 2)

    # Unsecured endpoint, anonymous: read-only.
    c = await session(work)
    ns = await c.get_namespace_array()
    check("namespace array", ns[2] == "Machine1", str(ns))
    try:
        await c.get_node(machine).write_value(ua.DataValue(ua.Variant(1, ua.VariantType.Int16)))
        check("anonymous write refused", False)
    except Exception as e:
        check("anonymous write refused", "BadUserAccessDenied" in type(e).__name__)
    await c.disconnect()

    # Untrusted client certificate, then trusted by the administrator.
    await expect_error("untrusted certificate rejected", session(work, "Basic256Sha256,SignAndEncrypt"),
                       "BadCertificateUntrusted")
    rejected = glob.glob(f"{work}/pki/rejected/certs/*.der")
    check("certificate copied to rejected/", len(rejected) == 1)
    for f in rejected:
        shutil.move(f, f"{work}/pki/trusted/certs/")

    for policy in ["Basic256Sha256", "Aes128Sha256RsaOaep", "Aes256Sha256RsaPss"]:
        for mode in ["Sign", "SignAndEncrypt"]:
            c = await session(work, f"{policy},{mode}")
            vals = await c.read_values([c.get_node(ua.ObjectIds.Server_ServerStatus)] * 400)  # multi-chunk
            state = await c.get_node(ua.ObjectIds.Server_ServerStatus_State).read_value()
            check(f"{policy} {mode}", len(vals) == 400 and state == 0)
            await c.disconnect()
    shutil.copy(f"{work}/client4k.der", f"{work}/pki/trusted/certs/client4k.der")
    c = await session(work, "Aes256Sha256RsaPss,SignAndEncrypt", cert="client4k")
    await c.disconnect()
    check("4096-bit client key", True)

    # Users.
    c = await session(work, "Basic256Sha256,SignAndEncrypt", user="operator", password="secret")
    await c.get_node(machine).write_value(ua.DataValue(ua.Variant(42, ua.VariantType.Int16)))
    check("operator can write", await c.get_node(machine).read_value() == 42)
    await c.disconnect()
    c = await session(work, None, user="operator", password="secret")
    check("password over unsecured channel (encrypted token)", await c.get_node(machine).read_value() == 42)
    await c.disconnect()
    await expect_error("wrong password rejected",
                       session(work, "Basic256Sha256,Sign", user="operator", password="nope"), "BadUserAccessDenied")
    c = await session(work, "Basic256Sha256,Sign", user="viewer", password="secret")
    try:
        await c.get_node(machine).write_value(ua.DataValue(ua.Variant(1, ua.VariantType.Int16)))
        check("viewer write refused", False)
    except Exception as e:
        check("viewer write refused", "BadUserAccessDenied" in type(e).__name__)
    await c.disconnect()

    await expect_error("untrusted X.509 user rejected",
                       session(work, "Basic256Sha256,SignAndEncrypt", x509_user=True), "BadIdentityTokenRejected")
    shutil.copy(f"{work}/user.der", f"{work}/pki/users/trusted/certs/user.der")
    c = await session(work, "Basic256Sha256,SignAndEncrypt", x509_user=True)
    await c.get_node(machine).write_value(ua.DataValue(ua.Variant(7, ua.VariantType.Int16)))
    check("trusted X.509 user can write", await c.get_node(machine).read_value() == 7)

    # Hot reload seen through a secure session.
    path = f"{cfg}/Machine/Machine.json"
    d = json.load(open(path))
    d["Subscriptions"][0]["Items"].append({"Name": "NEW", "NodeId": "s=New", "Type": "Double"})
    json.dump(d, open(path, "w"))
    await asyncio.sleep(0.5)
    dt = await c.get_node(ua.NodeId("New", 2)).read_data_type()
    check("hot reload visible", dt == ua.NodeId(11, 0))
    check("value kept across reload", await c.get_node(machine).read_value() == 7)
    await c.disconnect()


if __name__ == "__main__":
    binary, cfg_src = sys.argv[1], sys.argv[2]
    work = tempfile.mkdtemp(prefix="fastua-interop-")
    cfg = f"{work}/cfg"
    shutil.copytree(cfg_src, cfg)
    make_cert(f"{work}/client", "client", "urn:example:client")
    make_cert(f"{work}/client4k", "client4k", "urn:example:client", 4096)
    make_cert(f"{work}/user", "user", "urn:example:user")
    h = subprocess.run([binary, "hash-password"], input=b"secret\n", capture_output=True, check=True).stdout.decode().strip()
    json.dump({"users": [{"name": "operator", "password": h, "write": True}, {"name": "viewer", "password": h}]},
              open(f"{work}/users.json", "w"))
    log = open(f"{work}/server.log", "w")
    server = subprocess.Popen([binary, "--config", cfg, "--pki", f"{work}/pki", "--listen", f"127.0.0.1:{PORT}",
                               "--endpoint", URL, "--users", f"{work}/users.json"], stdout=log, stderr=log)
    try:
        time.sleep(1.0)
        asyncio.run(main(work, cfg))
    except Exception as e:
        FAILURES.append(f"exception: {e!r}")
        print("FAIL exception", repr(e))
    finally:
        server.terminate()
        server.wait()
    if FAILURES:
        print(open(f"{work}/server.log").read()[-3000:])
        print(f"{len(FAILURES)} failure(s): {FAILURES}")
        sys.exit(1)
    print("all interop checks passed")
    shutil.rmtree(work, ignore_errors=True)
