# fastua — ultra-fast OPC UA server

fastua is an OPC UA server written from scratch in Rust. It is built for minimum latency and a small footprint. Its address space comes from a directory of JSON files and is hot-reloaded on every change. It runs natively on **x86_64** and **aarch64** Linux.

The original C server (open62541 + json-c) is still in `src/`. See [Legacy C server](#legacy-c-server).

## Features

- **Transport:** UA TCP binary (HEL/ACK/ERR, chunking both ways, pipelined requests).
- **Security:** SecureChannel with SecurityPolicy None, Basic256Sha256, Aes128_Sha256_RsaOaep and Aes256_Sha256_RsaPss, in Sign and SignAndEncrypt modes.
  - Mutual certificate authentication.
  - Token renewal and lifetime, sequence checks.
  - A PKI with chain, CRL and ApplicationUri validation.
  - Cryptography: aws-lc-rs.
- **Users:** anonymous, user name / password (PBKDF2 hashes) and X.509 certificates, with read or read/write rights per user.
- **Services:** GetEndpoints, FindServers, CreateSession / ActivateSession / CloseSession, Read, Write, Browse, BrowseNext, TranslateBrowsePathsToNodeIds, RegisterNodes / UnregisterNodes, ServerStatus, NamespaceArray.
- **Hot reload:** the configuration directory is watched (inotify, polling elsewhere). The new address space is swapped in atomically, readers never lock, and values survive reloads. An invalid file is rejected and the previous configuration stays live.

Not yet: subscriptions / MonitoredItems (in progress), Call, events, the full namespace 0 nodeset, index ranges, ECC policies, the HTTPS transport (`opc.https`).

## Build and run

```bash
cargo build --release
./target/release/fastua --config config/machines --listen 0.0.0.0:4840
```

For a binary tuned to the CPU it runs on:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

Main options (`fastua --help` lists them all):

| Option | Effect |
|---|---|
| `--config DIR` | Namespace files, watched for changes (default `config/machines`). |
| `--listen ADDR:PORT` | Address to bind (default `0.0.0.0:4840`). |
| `--endpoint URL`, `--application-uri URI` | Advertised endpoint URL and ApplicationUri. |
| `--endpoints LIST` | Endpoints to offer: `none`, `basic256sha256-sign`, `basic256sha256-encrypt`, `aes128-sign`, `aes128-encrypt`, `aes256-sign`, `aes256-encrypt` (default: all). |
| `--pki DIR` | Certificate store (default `pki`). A self-signed certificate is created if missing. |
| `--users FILE` | Enables user name / password login. |
| `--anonymous off\|read\|write`, `--x509-users read\|write` | Rights of anonymous users and of certificate users. |
| `--trust-all-clients` | Accepts any client certificate (development only). |
| `--busy-poll US` | Polls each connection for `US` µs before sleeping. Lowest latency, at the cost of one busy core per active connection. |

`echo -n 's3cret' | ./target/release/fastua hash-password` prints a password hash for the users file.

## Configuration

Every `*.json` file in the directory, searched recursively, is one namespace:

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

Variables appear under `Objects/<Name>/<group>/<item>`. Supported types are Boolean, SByte, Byte, Int16, UInt16, Int32, UInt32, Int64, UInt64, Float, Double, String, DateTime, Guid and ByteString. Adding, removing or editing a file takes effect about 50 ms later, without a restart.

## Performance

The numbers below were measured by CI on GitHub runners. Run `cargo run --release --example bench` to reproduce them.

| Measure | x86_64 | aarch64 |
|---|---|---|
| Read of 1 value, service layer | 34 ns | 54 ns |
| Read of 100 values, per value | 11 ns | 19 ns |
| Loopback round trip p50 / p99, blocking | 26 / 56 µs | 25 / 30 µs |
| Loopback round trip p50 / p99, `--busy-poll` | 8.5 / 12 µs | 8.9 / 12 µs |
| Server crypto per Read, Sign | ~290 ns | ~280 ns |
| Server crypto per Read, SignAndEncrypt | ~410 ns | ~410 ns |
| Round trip p50, SignAndEncrypt, `--busy-poll` | 8.8 µs | 9.7 µs |

How it gets there:

- **Threads and I/O:** one blocking thread per connection, with no async runtime.
  - Buffers are allocated once per connection; a response is built in place and sent with one syscall.
  - One `recv` per request.
- **Lookups and decoding:** values live in seqlocks, so reads are wait-free.
  - Numeric NodeIds use a dense index; RequestHeader and ReadValueId are decoded through fixed-layout fast paths.
  - One coarse clock read per request.
- **Security:** HMAC-SHA256 uses states precomputed per channel key and hardware SHA instructions.
- **Build:** release profile with fat LTO, 1 codegen unit and `panic = "abort"`.

Details: [docs/RustServer.md](docs/RustServer.md).

## Security

The certificate store layout, the trust flow (move a file from `pki/rejected/certs/` to `pki/trusted/certs/`, no restart needed) and the users file format are described in [docs/RustServer.md](docs/RustServer.md#security).

## Tests and CI

```bash
cargo test                                   # unit + end-to-end tests
cargo clippy --all-targets -- -D warnings
pip install asyncua cryptography
python3 crates/fastua/tests/interop/asyncua_interop.py target/release/fastua config/machines
```

`.github/workflows/rust.yml` builds, tests, benchmarks and runs the asyncua interoperability suite natively on x86_64 and aarch64.

## Legacy C server

The first implementation (open62541 + json-c) is still in `src/`, built with `make` (needs `cmake` and `libmbedtls-dev`, which `apt-get install build-essential cmake libmbedtls-dev` provides on Debian/Ubuntu). Run it with `./bin/opcuaserver config.json5`.

## License
MIT License

Copyright (c) 2025 Azerode

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
