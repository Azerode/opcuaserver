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

    # Subscriptions over the secure session: initial value, changes, deadband.
    class Handler:
        def __init__(self):
            self.values = []

        def datachange_notification(self, node, val, data):
            self.values.append((node.nodeid, val))

    async def write(v):
        await c.get_node(machine).write_value(ua.DataValue(ua.Variant(v, ua.VariantType.Int16)))

    h = Handler()
    sub = await c.create_subscription(10, h)
    await sub.subscribe_data_change([c.get_node(machine), c.get_node(ua.ObjectIds.Server_ServerStatus_State)])
    await asyncio.sleep(0.3)
    check("subscription initial values", (machine, 7) in h.values and len(h.values) == 2, str(h.values))
    for v in (8, 9, 10):
        await write(v)
        await asyncio.sleep(0.05)
    await asyncio.sleep(0.2)
    seen = [v for n, v in h.values if n == machine]
    check("subscription data changes", seen[-3:] == [8, 9, 10], str(seen))
    hd = Handler()
    sub2 = await c.create_subscription(10, hd)
    await sub2.deadband_monitor(c.get_node(machine), 5, 1)
    await asyncio.sleep(0.2)
    for v in (12, 16, 30):
        await write(v)
        await asyncio.sleep(0.05)
    await asyncio.sleep(0.2)
    seen = [v for n, v in hd.values]
    check("absolute deadband", seen == [10, 16, 30], str(seen))
    await sub2.delete()
    await sub.delete()
    await write(7)

    # Hot reload seen through a secure session.
    path = f"{cfg}/Machine/Machine.json"
    d = json.load(open(path))
    d["Subscriptions"][0]["Items"].append({"Name": "NEW", "NodeId": "s=New", "Type": "Double"})
    d["Subscriptions"][0]["Items"].append(
        {"Name": "Level", "NodeId": "s=Level", "Type": "Double", "EURange": {"Low": 0, "High": 200},
         "Historizing": True, "Alarm": {"High": 100, "HighHigh": 150, "Severity": 600}})

    # Events: the reload raises a model change event, sessions raise audit events.
    class Events:
        def __init__(self):
            self.events = []

        def event_notification(self, event):
            self.events.append(event)

    he = Events()
    sub3 = await c.create_subscription(10, he)
    await sub3.subscribe_events(c.nodes.server, ua.ObjectIds.BaseEventType)
    hc = Events()
    sub4 = await c.create_subscription(10, hc)
    await sub4.subscribe_events(c.nodes.server, ua.ObjectIds.AuditCreateSessionEventType)

    json.dump(d, open(path, "w"))
    await asyncio.sleep(0.5)
    dt = await c.get_node(ua.NodeId("New", 2)).read_data_type()
    check("hot reload visible", dt == ua.NodeId(11, 0))
    check("value kept across reload", await c.get_node(machine).read_value() == 7)
    other = await session(work)
    await other.disconnect()
    await asyncio.sleep(0.3)
    names = [str(e.SourceName) for e in he.events]
    check("events: reload and session audit", "Server" in names and "Session/CreateSession" in names
          and "Session/CloseSession" in names, str(names))
    created = [e for e in hc.events]
    check("events: where clause (OfType)", len(created) == 1 and created[0].SourceName == "Session/CreateSession"
          and created[0].RevisedSessionTimeout > 0, str([str(e.SourceName) for e in created]))
    await sub4.delete()
    await sub3.delete()

    # Percent deadband on an AnalogItem (EURange 0..200: 10 % = 20).
    level = c.get_node(ua.NodeId("Level", 2))
    rng = await (await level.get_child("0:EURange")).read_value()
    check("EURange property", rng.Low == 0 and rng.High == 200, str(rng))
    hp = Handler()
    sub5 = await c.create_subscription(10, hp)
    await sub5.deadband_monitor(level, 10, 2)
    await asyncio.sleep(0.2)
    for v in (5.0, 15.0, 30.0, 45.0, 51.0):
        await level.write_value(ua.DataValue(ua.Variant(v, ua.VariantType.Double)))
        await asyncio.sleep(0.05)
    await asyncio.sleep(0.2)
    seen = [v for n, v in hp.values]
    check("percent deadband", seen[-3:] == [5.0, 30.0, 51.0] and 15.0 not in seen, str(seen))

    # Historical access: the writes above were recorded.
    hz = await level.read_attribute(ua.AttributeIds.Historizing)
    check("Historizing attribute", hz.Value.Value is True, str(hz))
    now = datetime.datetime.now(datetime.timezone.utc)
    since = now - datetime.timedelta(minutes=5)
    hist = await level.read_raw_history(since, now + datetime.timedelta(seconds=1), return_bounds=False)
    seen = [d.Value.Value for d in hist]
    check("HistoryRead raw", seen[-5:] == [5.0, 15.0, 30.0, 45.0, 51.0], str(seen))
    # Two values per call, following the continuation points; bounds on.
    details = ua.ReadRawModifiedDetails()
    details.IsReadModified = False
    details.StartTime = since
    details.EndTime = now + datetime.timedelta(seconds=1)
    details.NumValuesPerNode = 2
    details.ReturnBounds = True
    seen, cp, calls = [], None, 0
    while True:
        res = await level.history_read(details, cp)
        calls += 1
        seen += [d.Value.Value for d in res.HistoryData.DataValues if d.StatusCode.is_good()]
        cp = res.ContinuationPoint
        if not cp or calls > 20:
            break
    check("HistoryRead continuation points and bounds", seen[-5:] == [5.0, 15.0, 30.0, 45.0, 51.0], str(seen))

    # Processed history: one interval over the whole range.
    pd = ua.ReadProcessedDetails()
    pd.StartTime = since
    pd.EndTime = now + datetime.timedelta(seconds=1)
    pd.ProcessingInterval = 0
    pd.AggregateType = [ua.NodeId(ua.ObjectIds.AggregateFunction_Average), ua.NodeId(ua.ObjectIds.AggregateFunction_Maximum)]
    pd.AggregateConfiguration = ua.AggregateConfiguration()
    pd.AggregateConfiguration.UseServerCapabilitiesDefaults = True
    hp_ = ua.HistoryReadParameters()
    hp_.HistoryReadDetails = pd
    hp_.TimestampsToReturn = ua.TimestampsToReturn.Source
    hp_.ReleaseContinuationPoints = False  # asyncua's default is True
    for agg in (0, 1):
        rv = ua.HistoryReadValueId()
        rv.NodeId = level.nodeid
        hp_.NodesToRead.append(rv)
    res = await c.uaclient.history_read(hp_)
    got = [r.HistoryData.DataValues[0].Value.Value for r in res]
    check("HistoryRead processed (Average, Maximum)", abs(got[0] - 29.2) < 1e-9 and got[1] == 51.0, str(got))

    # Alarms and conditions: limit alarm on Level, acknowledged through Call.
    ha = Events()
    sub6 = await c.create_subscription(10, ha)
    await sub6.subscribe_alarms_and_conditions(c.nodes.server, ua.ObjectIds.ExclusiveLimitAlarmType)
    await asyncio.sleep(0.2)
    ha.events.clear()
    await level.write_value(ua.DataValue(ua.Variant(120.0, ua.VariantType.Double)))
    await asyncio.sleep(0.3)
    active = [e for e in ha.events if getattr(e, "ActiveState/Id", None) is True]
    check("alarm raised", len(active) == 1 and active[0].Severity == 600
          and str(getattr(active[0], "LimitState/CurrentState").Text) == "High", str(ha.events))
    cond = c.get_node(active[0].NodeId if getattr(active[0], "NodeId", None) else ua.NodeId("__alarm/s=Level", 2))
    await cond.call_method(ua.NodeId(ua.ObjectIds.AcknowledgeableConditionType_Acknowledge),
                           ua.Variant(active[0].EventId, ua.VariantType.ByteString),
                           ua.Variant(ua.LocalizedText("seen"), ua.VariantType.LocalizedText))
    await asyncio.sleep(0.3)
    acked = [e for e in ha.events if getattr(e, "AckedState/Id", None) is True]
    check("alarm acknowledged", len(acked) == 1 and acked[0].Comment.Text == "seen"
          and acked[0].ClientUserId, str(ha.events[-1:]))
    ha.events.clear()
    await c.get_node(ua.ObjectIds.ConditionType).call_method(
        ua.NodeId(ua.ObjectIds.ConditionType_ConditionRefresh),
        ua.Variant(sub6.subscription_id, ua.VariantType.UInt32))
    await asyncio.sleep(0.3)
    types = [e.EventType for e in ha.events]
    check("ConditionRefresh", ua.NodeId(ua.ObjectIds.RefreshStartEventType) in types
          and ua.NodeId(ua.ObjectIds.RefreshEndEventType) in types
          and ua.NodeId(ua.ObjectIds.ExclusiveLimitAlarmType) in types, str(types))
    await sub6.delete()

    # Methods: GetMonitoredItems.
    out = await c.nodes.server.call_method("0:GetMonitoredItems", ua.Variant(sub5.subscription_id, ua.VariantType.UInt32))
    check("GetMonitoredItems", len(out) == 2 and len(out[0]) == 1 and len(out[1]) == 1, str(out))
    await sub5.delete()

    # ServerCapabilities and index ranges.
    limit = await c.get_node(ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerRead).read_value()
    check("ServerCapabilities", limit > 0, str(limit))
    rv = ua.ReadValueId()
    rv.NodeId = ua.NodeId(ua.ObjectIds.Server_NamespaceArray)
    rv.AttributeId = ua.AttributeIds.Value
    rv.IndexRange = "2"
    params = ua.ReadParameters()
    params.NodesToRead = [rv]
    res = await c.uaclient.read(params)
    check("index range read", res[0].Value.Value == ["Machine1"], str(res[0].Value))
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
