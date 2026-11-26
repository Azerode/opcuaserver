# fastua — ultra-fast OPC UA server

fastua is an OPC UA server written from scratch in Rust. It is built for minimum latency and a small footprint. Its address space comes from a directory of JSON files and is hot-reloaded on every change. It runs natively on **x86_64** and **aarch64** Linux.

## Features

- **Transport:** UA TCP binary (HEL/ACK/ERR, chunking both ways, pipelined requests).
- **Security:** SecureChannel with SecurityPolicy None, Basic256Sha256, Aes128_Sha256_RsaOaep and Aes256_Sha256_RsaPss, in Sign and SignAndEncrypt modes.
  - ECC policies (OPC UA 1.05.04+): ECC_nistP256, ECC_nistP384 and ECC_curve25519, each with AesGcm and ChaChaPoly. They use ephemeral ECDH / X25519 key agreement, HKDF, ECDSA / Ed25519 signatures and AEAD messages, with the SecureChannelEnhancements (channel-bound session signatures, IKM chaining on renewal). A certificate per curve is created in the PKI. Anonymous, X.509 and user name logins work on ECC endpoints; the password travels as an EccEncryptedSecret for an ephemeral key the server sends in CreateSession / ActivateSession.
  - Deprecated ECC_nistP256 and ECC_nistP384 (1.05.00 to 1.05.03, AES-CBC + HMAC-SHA256 / SHA384, no SecureChannelEnhancements) for older clients, offered only when listed in `--endpoints`.
  - Mutual certificate authentication.
  - Token renewal and lifetime, sequence checks.
  - A PKI with chain, CRL and ApplicationUri validation.
  - HTTPS transport (`--https-listen`, `opc.https`, https-uabinary): each request is a POST of its binary encoding over TLS (rustls), with the application certificate; sessions, subscriptions and every service work as over opc.tcp (Read round trip +7 µs on loopback). TLS client certificates (`--https-client-certs`, optional by default) are checked against the trust list and bind the session's application certificate. A session works on every TLS connection of the same client (HTTP clients such as the OPC Foundation stack spread requests and outstanding Publish requests over several connections); a session activated with a client certificate is reachable only from connections presenting that certificate.
  - JSON encoding (https-uajson, Part 6 §5.4 compact form): the same HTTPS endpoint takes `Content-Type: application/json` bodies. They are transcoded to and from UA binary around the service layer from a table of every namespace 0 DataType (`data/types.bin`, generated from the official nodeset), so every service works in JSON and the binary path pays nothing.
  - Cryptography: aws-lc-rs.
- **Users:** anonymous, user name / password (PBKDF2 hashes) and X.509 certificates, with read or read/write rights per user.
- **Services:** GetEndpoints, FindServers, CreateSession / ActivateSession / CloseSession / Cancel, Read and Write (with index ranges), Browse, BrowseNext, TranslateBrowsePathsToNodeIds, RegisterNodes / UnregisterNodes, Call, HistoryRead, HistoryUpdate.
- **Profile:** ServerProfileArray announces the Standard 2017 UA Server profile (self-assessed against OPC 10000-7; not certified with the OPC Foundation CTT). Four independent client stacks check it in CI, the OPC Foundation's own .NET stack among them (see [Interoperability](#interoperability)).
- **Namespace 0:** the complete standard nodeset (5 477 nodes of `Opc.Ua.NodeSet2.xml` 1.05.07), compiled into the binary and merged with the live nodes, with the DataTypeDefinition attribute of every data type. No cost per request.
- **Server object:** ServerStatus with BuildInfo, NamespaceArray, ServerCapabilities with OperationLimits and the 1.05 limits (MaxSessions, MaxSubscriptions, ...) from the configured limits, ServerDiagnostics with a live ServerDiagnosticsSummary (session, subscription and rejected request counters), ServerRedundancy, Auditing, and the GetMonitoredItems and ResendData methods.
- **Subscriptions:** every Subscription and MonitoredItem service.
  - Create / Modify / Delete, SetPublishingMode, Publish, Republish, TransferSubscriptions.
  - SetMonitoringMode and SetTriggering.
  - Index ranges: only the selected elements are compared and reported.
  - DataChangeFilter with triggers, an absolute deadband, and a percent deadband on items that declare an EURange (AnalogItemType).
  - Queues with both overflow policies.
  - Keep-alive, lifetime and retransmission handling.
  - The steady-state hot path allocates nothing.
- **Events:** the Server object is an event notifier.
  - EventFilter select clauses and where clauses (comparisons, Like, Between, InList, And / Or / Not, OfType, bitwise operators), with per clause results.
  - Event queues with both overflow policies and EventQueueOverflow events.
  - Server events: session audit (create, activate, close, timeout), write audit (AuditWriteUpdateEventType with old and new values, for every Write operation), history update audit (AuditHistoryValueUpdate / RawModifyDelete / AtTimeDelete), configuration reloaded (BaseModelChangeEventType) and configuration rejected (SystemEventType).
- **Historical access:** variables marked `Historizing` keep their last values (10 000 by default) in memory.
  - HistoryRead: raw values (with bounds, forward and reverse), modified values, values at given times (interpolated), with continuation points.
  - HistoryUpdate: insert, replace, update, delete a range, delete at times; every change goes to the modified history with its user.
  - Persistence (`--history-dir DIR`): histories survive restarts. A background thread appends each second's new values to one file per variable; writers never touch the disk (+4.5 ns per historized write).
  - Event history (`--event-history N`): the Server object keeps the last N events; HistoryRead with ReadEventDetails returns them through an EventFilter (select and where clauses), forward or reverse, with continuation points.
  - HistoryServerCapabilities describes what is supported.
- **Aggregates:** 37 aggregate functions of Part 13 (averages, time averages, totals, minimum / maximum and their variants, range, count, start / end and bounds, durations in state, transitions, quality durations and percentages, worst quality, standard deviation and variance).
  - HistoryRead with ReadProcessedDetails, any processing interval, forward or reverse, with an AggregateConfiguration.
  - AggregateFilter on MonitoredItems of historized variables: one value per processing interval.
- **Alarms and conditions (Part 9):** an item with an `Alarm` gets a condition: an ExclusiveLimitAlarm (HighHigh / High / Low / LowLow limits with a deadband) or an OffNormalAlarm (a normal value).
  - Every write of the variable evaluates its condition; state changes raise condition events with the Active, Acked, Confirmed, Enabled and LimitState fields.
  - Methods Acknowledge, Confirm, AddComment, Enable, Disable, ConditionRefresh and ConditionRefresh2, through Call.
  - Shelving: TimedShelve, OneShotShelve and Unshelve (and their 1.05 variants with a comment) on the condition's ShelvingState; a timed shelve ends on its own, a one-shot shelve when the alarm returns to normal. Events carry ShelvingState and SuppressedOrShelved.
  - Suppress / Unsuppress, RemoveFromService / PlaceInService (write rights), Silence and Reset (with `"Latching": true` an alarm stays active until reset), each with its 1.05 variant taking a comment. SuppressedOrShelved covers shelving, suppression and out of service.
  - Dialogs: an item with a `Dialog` (`Prompt`, `Options`, `Default`, `Ok`, `Cancel`, signed numeric Type) gets a DialogConditionType. Writing a negative value raises the question; Respond / Respond2 write the chosen option index into the variable and close it.
  - Branches: an alarm active again while its previous occurrence is not acknowledged and confirmed keeps that occurrence as a branch, with its own BranchId and EventId, acknowledged and confirmed on its own and reported by ConditionRefresh.
  - Condition states survive configuration reloads.
- **Hot reload:** the configuration directory is watched (inotify, polling elsewhere). The new address space is swapped in atomically, readers never lock, and values survive reloads. An invalid file is rejected and the previous configuration stays live.

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
| `--endpoints LIST` | Endpoints to offer: `none`, `basic256sha256-sign`, `basic256sha256-encrypt`, `aes128-sign`, `aes128-encrypt`, `aes256-sign`, `aes256-encrypt`, `ecc-<curve>-<cipher>-sign\|encrypt` with curve `nistp256`, `nistp384` or `curve25519` and cipher `aesgcm` or `chachapoly`, the deprecated `ecc-nistp256-sign\|encrypt` and `ecc-nistp384-sign\|encrypt`, and `default` (default: all but the deprecated ones). |
| `--pki DIR` | Certificate store (default `pki`). A self-signed certificate is created if missing. |
| `--users FILE` | Enables user name / password login. |
| `--anonymous off\|read\|write`, `--x509-users read\|write` | Rights of anonymous users and of certificate users. |
| `--trust-all-clients` | Accepts any client certificate (development only). |
| `--busy-poll US` | Polls each connection for `US` µs before sleeping. Lowest latency, at the cost of busy cores. Only as many connections spin as there are free cores, so throughput under many clients does not collapse. |
| `--busy-poll-threads N` | Ceiling on the connections that busy-poll at once (default: cores - 1). |
| `--min-publishing-interval MS`, `--min-sampling-interval MS` | Fastest subscription intervals (default 1 ms, at least 0.05 ms). |
| `--https-listen ADDR:PORT`, `--https-endpoint URL` | Also serve the HTTPS transport (`opc.https`); the endpoint URL defaults to `opc.https://<hostname>:<port>`. |
| `--https-client-certs off\|optional\|required` | TLS client certificates on the HTTPS transport, checked against the application trust list (default: optional). |
| `--history-dir DIR` | Keep the history of historized variables across restarts (written every second). |
| `--event-history N` | Keep the last N events for HistoryRead on the Server object (default 0, off). |
| `--session-diagnostics` | Count requests per session and service for SessionDiagnosticsArray (`EnabledFlag` true). The diagnostics arrays are always readable. |

`echo -n 's3cret' | ./target/release/fastua hash-password` prints a password hash for the users file.

## Configuration

Every `*.json` file in the directory, searched recursively, is one namespace:

```json
{
  "Name": "Machine1",
  "Namespace": "Machine1",
  "Subscriptions": [
    { "Name": "FLAGS",
      "Items": [
        { "Name": "PC", "NodeId": "ns=5;i=1000", "Type": "System.Int16", "Writable": true },
        { "Name": "Level", "NodeId": "s=Level", "Type": "Double", "EURange": { "Low": 0, "High": 200 },
          "Historizing": true, "HistoryCapacity": 50000,
          "Alarm": { "HighHigh": 190, "High": 170, "Low": 20, "Deadband": 2, "Severity": 700 } },
        { "Name": "Door", "NodeId": "s=Door", "Type": "Boolean",
          "Alarm": { "Normal": false, "Message": "Door open" } } ] }
  ]
}
```

Variables appear under `Objects/<Name>/<group>/<item>`. Supported types are Boolean, SByte, Byte, Int16, UInt16, Int32, UInt32, Int64, UInt64, Float, Double, String, DateTime, Guid and ByteString. A numeric item with an `EURange` (`{"Low": .., "High": ..}` or `[low, high]`) becomes an AnalogItemType variable with an EURange property, which percent deadbands use. `Historizing: true` records every write of the item for HistoryRead; `HistoryCapacity` (default 10 000) bounds the values kept. `Alarm` adds a limit alarm (any of `LowLow`, `Low`, `High`, `HighHigh`, ordered, with an optional `Deadband`) or an off-normal alarm (`Normal`), with a `Severity` (default 500), a `Message`, an optional `MaxTimeShelved` (ms) bounding TimedShelve and `Latching`. Adding, removing or editing a file takes effect about 50 ms later, without a restart.

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
| Server crypto per Read, ECC_nistP256_AesGcm SignAndEncrypt | ~135 ns | ~200 ns |
| Server crypto per Read, ECC_nistP256_ChaChaPoly SignAndEncrypt | ~365 ns | ~540 ns |
| Subscription sampling pass, unchanged value | 0.02 ns/item | 0.02 ns/item |
| Subscription sampling pass, 1 % of values changed | 1.1 ns/item | 2.7 ns/item |
| Subscription changed value (sample + queue + encode) | 22 ns/item | 26 ns/item |
| Write → notification p50 / p99, 1 ms intervals | 0.53 / 1.03 ms | 0.52 / 1.05 ms |
| Write → notification p50 / p99, 0.1 ms intervals, `--busy-poll` | 64 / 114 µs | 64 / 113 µs |
| Server event → EventFieldList (where clause, 6 fields) | ~340 ns | ~490 ns |
| Write, variable without history | 8.1 ns | 12.7 ns |
| Write, historized variable | 17 ns | 18 ns |
| HistoryRead raw, 1000 values, per value | 9.7 ns | 15.4 ns |
| Processed read, Average, 100 values per interval, per value | 4.8 ns | 3.7 ns |
| Processed read, TimeAverage, 100 values per interval, per value | 8.2 ns | 6.5 ns |

How it gets there:

- **Threads and I/O:** one blocking thread per connection, with no async runtime.
  - Buffers are allocated once per connection; a response is built in place and sent with one syscall.
  - One `recv` per request.
- **Lookups and decoding:** values live in seqlocks, so reads are wait-free.
  - Numeric NodeIds use a dense index; RequestHeader and ReadValueId are decoded through fixed-layout fast paths.
  - One coarse clock read per request.
- **Security:** HMAC-SHA256 uses states precomputed per channel key and hardware SHA instructions. The ECC policies seal and open each chunk in place with one AEAD call (AES-GCM or ChaCha20-Poly1305), with no padding.
- **Subscriptions:** sampling and publishing are driven by the connection thread, which waits for the next deadline with `ppoll`.
  - Value cells share a change stamp per block of 64: a write stores a value unique to (cell, write) into it, and a sampling pass skips a block of unchanged values with one load.
  - Samples go into fixed 32-byte entries, encoded straight from the value cell into the response.
  - The NotificationMessage is kept for Republish without a copy: the sent response buffer itself is kept and swapped for a recycled one (a copy only with SignAndEncrypt, which encrypts in place).
  - Buffers are recycled, so the steady state allocates nothing (`tests/no_alloc.rs`).
  - A notification leaves at the end of the publishing interval, as the specification requires, so the publishing interval sets the latency.
- **Events:** event items pull from a shared ring only when their subscription is serviced. Subscriptions without event items never look at it, and raising an event costs one atomic load while nobody subscribes.
- **History:** a write checks one flag that sits in the cell's padding. A historized numeric write is staged in a 64-slot lock-free buffer with plain stores, while the writer still holds the cell's seqlock (which makes it the only producer). The ring mutex is taken once per 32 writes, to append the staged batch in one move, and by readers, which drain the buffer first. The ring stops allocating once full. HistoryRead encodes each DataValue straight from the ring under the lock, without copying the values. Continuation points carry the resume position, so they hold no server memory.
- **Aggregates:** computed in place on the ring under the lock: no copy of the window and no allocation per interval. Interpolation at the interval bounds is a binary search; time-weighted areas are summed on the fly.
- **Namespace 0:** compiled from the official nodeset into a 1.2 MB table, decoded when the address space is built (~2 ms per load) and given a direct lookup table like the configured namespaces.
- **Build:** release profile with fat LTO, 1 codegen unit and `panic = "abort"`.

**Against open62541:** CI runs the same load client against fastua and the open62541 server (same machine, same 100 variables, None / Basic256Sha256 / ECC nistP256) and publishes the comparison in the job summary. See [crates/fastua/tests/compare](crates/fastua/tests/compare/README.md).

Details: [docs/RustServer.md](docs/RustServer.md).

## Security

The certificate store layout, the trust flow (move a file from `pki/rejected/certs/` to `pki/trusted/certs/`, no restart needed) and the users file format are described in [docs/RustServer.md](docs/RustServer.md#security).

## Interoperability

CI runs four third-party client stacks against the release binary on x86_64 and aarch64. Each check prints PASS or FAIL; one failure fails the job.

| Client | What it checks |
|---|---|
| [OPC Foundation UA-.NETStandard](https://github.com/OPCFoundation/UA-.NETStandard) 1.5.378 (the reference stack) | GetEndpoints, FindServers; None and every RSA policy in Sign and SignAndEncrypt (multi-chunk responses); user name (wrong password, read-only user, password over None); **opc.https** (https-uabinary): session, Read, Browse, subscription; the whole address space browsed (BrowseNext pages sized by MaxBrowseContinuationPoints) and read through the stack's node model (about 4 900 nodes); DataTypeDefinition of every data type decoded as StructureDefinition / EnumDefinition; type tree; TranslateBrowsePaths; EURange; Write and Read back of every built-in type, type mismatch, non-writable attribute; RegisterNodes; data change and event monitored items with an OfType where clause; alarm Acknowledge through Call; GetMonitoredItems and argument errors; TransferSubscriptions to a second session; HistoryRead raw, continuation points, processed (Count), at time, events; HistoryUpdate insert. |
| [node-opcua](https://github.com/node-opcua/node-opcua) 2.186 | Discovery; None and every RSA policy and mode; user tokens; the whole address space browsed in pages of 7 references and every mandatory attribute of every node read and strictly decoded (56 000 attributes); DataTypeDefinition; ServerStatus and BuildInfo built from their definitions; inverse browse; TranslateBrowsePaths; Write / Read of every built-in type, index range; RegisterNodes; data changes, audit events, alarm and Acknowledge; GetMonitoredItems; HistoryRead raw, continuation point, processed (Maximum), events. |
| [open62541](https://github.com/open62541/open62541) (master) | Every ECC policy (AEAD and deprecated) in both modes with anonymous, X.509 and user name logins and token renewal ([open62541_ecc.c](crates/fastua/tests/interop/open62541_ecc.c)); None and every RSA policy, user rights, TranslateBrowsePaths, Browse / BrowseNext, Write / Read, RegisterNodes, data change and event monitored items, Call, HistoryRead with continuation points ([open62541_services.c](crates/fastua/tests/interop/open62541_services.c)). |
| [asyncua](https://github.com/FreeOpcUa/opcua-asyncio) (Python) | Certificate trust flow (rejected / trusted), RSA policies, 4096-bit keys, user name and X.509 users, subscriptions with absolute and percent deadbands, hot reload, events and where clauses, history (raw, continuation points, processed), alarms and ConditionRefresh, index ranges. |

Fixed thanks to these clients: the Filter of ReadEventDetails is an EventFilter encoded in place, not an ExtensionObject (node-opcua, .NET); legacy encrypted passwords may carry padding after the secret (.NET); an HTTPS session is no longer tied to one TLS connection (.NET).

Not covered by a third-party client: the JSON encoding (https-uajson), which none of these client stacks implement (fastua's own tests cover it). The ECC policies are checked by open62541 only.

## Tests and CI

```bash
cargo test                                   # unit + end-to-end tests
cargo clippy --all-targets -- -D warnings
I=crates/fastua/tests/interop B=target/release/fastua
pip install asyncua cryptography
python3 $I/asyncua_interop.py $B config/machines
# open62541 client (built with UA_ENABLE_ENCRYPTION=OPENSSL)
cc $I/open62541_ecc.c -lopen62541 -lssl -lcrypto -o open62541_ecc
$I/open62541_ecc.sh $B config/machines ./open62541_ecc
cc $I/open62541_services.c -lopen62541 -lssl -lcrypto -o open62541_services
$I/serve.sh $B ./open62541_services
# node-opcua (Node.js 22) and the OPC Foundation .NET stack (.NET 8 SDK)
npm ci --prefix $I/node-opcua && $I/serve.sh $B node $I/node-opcua/interop.mjs
dotnet build -c Release -o dotnet-interop $I/dotnet/Interop.csproj
$I/serve.sh $B dotnet dotnet-interop/fastua-interop-dotnet.dll
```

`serve.sh` starts a fresh server (namespace [tests/interop/config](crates/fastua/tests/interop/config/Plant/Plant.json), every default endpoint, HTTPS, users `operator` / `viewer`, event history) and runs the client against it.

`.github/workflows/rust.yml` builds, tests, benchmarks and runs the four interoperability suites natively on x86_64 and aarch64.

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
