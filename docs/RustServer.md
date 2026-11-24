# fastua — Rust OPC UA server

Ultra-light, ultra-fast OPC UA server whose address space is driven by a
directory of JSON files and hot-reloaded on every change.

## Build and run

```bash
cargo build --release                      # target/release/fastua (~600 KB, static Rust, no OpenSSL)
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

## Scope (phase 1)

Implemented: UA TCP (HEL/ACK/ERR, chunking both ways), SecureChannel with
SecurityPolicy None (issue/renew, token lifetime, sequence checks), sessions
(anonymous), GetEndpoints, FindServers, Read, Write, Browse, BrowseNext,
TranslateBrowsePathsToNodeIds, RegisterNodes/UnregisterNodes, ServerStatus,
NamespaceArray.

Not yet: encryption (Basic256Sha256, Aes128/Aes256 policies) and user
authentication, subscriptions / MonitoredItems, Call, events, the full
namespace 0 nodeset, index ranges.
