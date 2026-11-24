# fastua — Rust OPC UA server

Ultra-light, ultra-fast OPC UA server whose address space is driven by a
directory of JSON files and hot-reloaded on every change.

## Build and run

```bash
cargo build --release                      # target/release/fastua (Rust + aws-lc for cryptography, no OpenSSL)
./target/release/fastua --config config/machines --listen 0.0.0.0:4840
```

For a binary tuned to the exact CPU it runs on:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

CI builds and tests natively on `x86_64` and `aarch64` (`.github/workflows/rust.yml`).

## Configuration directory

Every `*.json` file (searched recursively) is one namespace:

```json
{
  "Name": "Machine1",
  "Namespace": "Machine1",
  "Subscriptions": [
    { "Name": "FLAGS",
      "Items": [ { "Name": "PC", "NodeId": "ns=5;i=1000", "Type": "System.Int16", "Writable": true } ] }
  ]
}
```

- `Namespace` is the namespace URI. The server assigns its index and keeps it
  stable for the life of the process, even if the file disappears and comes back.
- The `ns=` part of `NodeId` is ignored (the server owns namespace indexes);
  `i=`, `s=`, `g=` and `b=` identifiers are supported.
- `Type`: Boolean, SByte, Byte, Int16, UInt16, Int32, UInt32, Int64, UInt64,
  Float, Double, String, DateTime, Guid, ByteString (`System.` prefix optional).
- `Writable` (default `true`) controls the AccessLevel.
- Address space: `Objects/<Name>/<group>/<item>`.

### Hot reload

inotify watches the directory (polling on non-Linux). After a 50 ms quiet
period the whole directory is parsed and a new immutable snapshot is built and
swapped in atomically. Readers never lock. If any file is invalid, the reload
is rejected and the previous snapshot stays live. A variable that keeps its
NodeId and type keeps its current value across reloads.

## Performance design

- Blocking thread per connection, `TCP_NODELAY`, buffers allocated once per
  connection; single-chunk responses are built in place and sent with one syscall.
- Zero-copy decoding, all lengths bounded before allocation.
- Address space references resolved to dense indexes at build time; NodeId lookup through FxHash.
- Variable values in a seqlock: wait-free reads, no shared writes on read.
- Release profile: fat LTO, 1 codegen unit, `panic = "abort"`.

`cargo run --release --example bench` prints the service-layer cost of a Read
and the loopback round-trip latency.

## Security

### Endpoints

By default the server offers seven endpoints. Use `--endpoints` to choose a subset (comma-separated):

| Name | SecurityPolicy | Mode |
|---|---|---|
| `none` | None | None |
| `basic256sha256-sign`, `basic256sha256-encrypt` | Basic256Sha256 | Sign / SignAndEncrypt |
| `aes128-sign`, `aes128-encrypt` | Aes128_Sha256_RsaOaep | Sign / SignAndEncrypt |
| `aes256-sign`, `aes256-encrypt` | Aes256_Sha256_RsaPss | Sign / SignAndEncrypt |

Cryptography is provided by aws-lc-rs: RSA-OAEP, PKCS#1 v1.5 and PSS signatures, AES-CBC, HMAC-SHA256 and P_SHA256. Client keys of 2048 to 4096 bits are accepted.

### Certificates (`--pki DIR`, default `pki`)

```
pki/own/certs/fastua.der        server certificate (created self-signed, RSA 2048, if missing)
pki/own/private/fastua.pk8      private key (mode 0600)
pki/trusted/certs/   pki/trusted/crl/     trusted client certificates / CAs and their CRLs
pki/issuers/certs/   pki/issuers/crl/     intermediate CAs (not trusted by themselves)
pki/rejected/certs/                       rejected client certificates, named by thumbprint
pki/users/trusted/certs/  pki/users/issuers/certs/   certificates for X.509 user login
```

The server re-reads a directory when its modification time changes, so you can trust a client without a restart: move its file from `rejected/certs/` to `trusted/certs/`. Validation checks the chain, trust, validity period, key usage, ApplicationUri and CRL revocation. Each failure returns its specific `BadCertificate*` code. `--trust-all-clients` turns validation off; use it only for development.

### Users

| Token | Enabled by | Rights |
|---|---|---|
| Anonymous | `--anonymous off\|read\|write` (default `read`) | as configured |
| User name / password | `--users FILE` | per user (`"write": true`) |
| X.509 certificate | certificate in `pki/users/trusted/certs/` | `--x509-users read\|write` (default `write`) |

```bash
echo -n 's3cret' | ./target/release/fastua hash-password   # pbkdf2-sha256$600000$...
```

```json
{ "users": [ { "name": "operator", "password": "pbkdf2-sha256$600000$...", "write": true },
             { "name": "viewer",   "password": "pbkdf2-sha256$600000$..." } ] }
```

On a None or Sign channel the password must be encrypted with the server key, as the user token policy requires. A user without write rights sees `UserAccessLevel` without the write bit, and the server answers `BadUserAccessDenied` to a Write.

### Interoperability tests

`crates/fastua/tests/interop/asyncua_interop.py` runs the release binary against the Python asyncua client. It checks every policy and mode, a 4096-bit client key, the certificate trust flow, user name and X.509 users, access rights and hot reload. CI runs it on both architectures.

```bash
pip install asyncua cryptography
python3 crates/fastua/tests/interop/asyncua_interop.py target/release/fastua config/machines
```

## Scope

Implemented: UA TCP (HEL/ACK/ERR, chunking both ways), SecureChannel with
SecurityPolicy None, Basic256Sha256, Aes128_Sha256_RsaOaep and
Aes256_Sha256_RsaPss in Sign and SignAndEncrypt modes (issue/renew, token
lifetime, sequence checks), PKI with CRLs, sessions with anonymous, user name
and X.509 identities, per-user read/write rights, GetEndpoints, FindServers,
Read, Write, Browse, BrowseNext, TranslateBrowsePathsToNodeIds,
RegisterNodes/UnregisterNodes, ServerStatus, NamespaceArray.

Not yet: subscriptions / MonitoredItems, Call, events, the full namespace 0
nodeset, index ranges, ECC policies, audit events.
