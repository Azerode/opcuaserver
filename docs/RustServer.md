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
      "Items": [
        { "Name": "PC", "NodeId": "ns=5;i=1000", "Type": "System.Int16", "Writable": true },
        { "Name": "Level", "NodeId": "s=Level", "Type": "Double", "EURange": { "Low": 0, "High": 200 },
          "Historizing": true, "HistoryCapacity": 50000 } ] }
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
- `EURange` (numeric types only, `{"Low": .., "High": ..}` or `[low, high]`)
  makes the item an AnalogItemType variable with an EURange property (a
  `Range` structure, browse name `0:EURange`). Percent deadbands use it.
- `Historizing` (default `false`) records every write of the item (see
  [Historical access](#historical-access)); `HistoryCapacity` (default
  10 000) is how many values are kept.
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
- Buffered receive: one `recv` brings a whole request (and any pipelined requests).
- Optional busy polling (`--busy-poll US`): a connection thread polls its socket for
  `US` microseconds before sleeping, which removes the scheduler wake-up from the
  round trip (loopback: ~30 µs → ~7 µs when the client also polls) at the cost of one
  busy core per active connection. It also sets `SO_BUSY_POLL` for NIC-level polling
  (needs `CAP_NET_ADMIN` above `net.core.busy_read`). Best combined with pinning the
  server to dedicated cores (`taskset`, `isolcpus`).
- Adaptive busy polling: a connection spins only while it holds a permit. A sampler
  thread reads the runnable threads (`/proc/loadavg`) every 2 ms and allows as many
  spinners as there are free cores (at most `--busy-poll-threads`, default cores - 1).
  A spinner keeps its permit while requests keep arriving (no atomic per request) and
  gives it back when it sleeps or when the CPUs fill up, so many active clients no
  longer starve the threads doing the work: 16 clients on 4 cores went from 0.5x to
  ~0.95x of the blocking throughput while the single-client latency stays at ~7 µs.
- Zero-copy decoding, all lengths bounded before allocation.
- Address space references resolved to dense indexes at build time; numeric NodeIds of
  dense namespaces looked up in a direct table, others through FxHash.
- Fixed-layout fast paths for the RequestHeader and ReadValueId; one coarse clock read
  per request.
- Variable values in a seqlock: wait-free reads, no shared writes on read.
- Release profile: fat LTO, 1 codegen unit, `panic = "abort"`.

`cargo run --release --example bench` prints the service-layer cost of a Read,
the loopback round-trip latency, the secure channel costs, the subscription
engine cost per item and the write -> notification latency.

## Namespace 0

The address space holds the whole namespace 0 of the specification: the 5 477
nodes of `Opc.Ua.NodeSet2.xml` 1.05.07 (types with their instance declarations,
DataType encodings, EnumStrings and EnumValues, method arguments, the complete
Server object).

- `tools/gen_ns0.py` compiles the nodeset into `data/ns0.bin` (attributes,
  static values in UA binary, references) and `src/ns0_ref_types.rs` (the
  reference type hierarchy). The binary embeds the table: no file to ship.
- Every DataType carries its DataTypeDefinition attribute (StructureDefinition
  or EnumDefinition, 1.04+), so generic clients can decode the structures
  without the deprecated type dictionaries.
- On each build of the address space, fastua first creates the nodes it serves
  live values for (ServerStatus, capabilities, history, alarms...), then merges
  the table: missing nodes and references are added, a node keeps one type
  definition and one supertype. Standard methods that fastua does not implement
  have `Executable = false`.
- Cost: about 2 ms per configuration load, 1.2 MB of binary, and nothing per
  request. Namespace 0 always gets a direct lookup table (130 KB).
- CI regenerates the tables from the tagged nodeset and fails if they differ.
  To move to a newer nodeset, change `NODESET_TAG` and run the script.

### Server diagnostics

`Server/ServerDiagnostics/ServerDiagnosticsSummary` and its twelve counters are
live: current and cumulated sessions and subscriptions, rejected and
security-rejected sessions (failed CreateSession / ActivateSession) and
requests (any other ServiceFault), session timeouts. They are relaxed atomics
touched only when a session or subscription starts or ends, or a request is
rejected, never on a successful Read, Write or Publish. Per-session
diagnostics are not collected (`EnabledFlag` is false, their arrays are empty).

## Subscriptions

Every Subscription and MonitoredItem service is implemented: CreateSubscription,
ModifySubscription, SetPublishingMode, Publish, Republish, TransferSubscriptions,
DeleteSubscriptions, CreateMonitoredItems, ModifyMonitoredItems,
SetMonitoringMode, SetTriggering and DeleteMonitoredItems.

- **Who drives them:** the thread of the connection a session is bound to. It
  waits in `ppoll` for the next request or the next sampling / publishing
  deadline, whichever comes first, with a timer slack of 1 ns. With
  `--busy-poll` it spins up to that deadline instead.
- **Sampling:** items are grouped by sampling interval.
  - Value cells are created in blocks of 64 sharing a change stamp. Every
    write stores a value unique to (cell, write) into the stamp, after the
    value (release store: about 1 ns on the write).
  - A group keeps its items sorted by stamp. A pass loads each block's stamp
    once and skips the block when it did not move, so unchanged values cost
    a few hundredths of a ns each. In a block that moved, each item's change
    counter is compared (plain loads, ordered by the stamp's acquire load).
  - Sampling timers are phase-aligned with the publishing timer, so a change
    waits at most one interval.
- **Queues and filters:**
  - Numeric samples are copied out of the seqlock into 32-byte entries, kept
    inline for the default queue size of 1, and encoded straight into the
    NotificationMessage.
  - Queue sizes, `discardOldest` and the Overflow bit follow Part 4 §5.12.1.5.
  - DataChangeFilter supports the Status, StatusValue and
    StatusValueTimestamp triggers and the absolute deadband.
  - Percent deadbands (Part 8 §5.3.2.2) work on items with an EURange: the
    percentage becomes an absolute deadband of `pct / 100 × (High − Low)`,
    recomputed when a reload changes the range. Items without an EURange
    return `BadFilterNotAllowed`. Aggregate filters return
    `BadMonitoredItemFilterUnsupported`.
- **Publish state machine:**
  - Keep-alives and lifetime counters run per subscription; when a lifetime
    expires, a StatusChangeNotification `BadTimeout` is sent.
  - `MaxNotificationsPerPublish` is honoured, setting `moreNotifications`.
  - Priorities decide which subscription gets the next Publish request.
  - Publish requests time out according to their `timeoutHint`.
  - Acknowledgements are processed on arrival.
  - Unacknowledged messages stay available for Republish (64 per subscription).
    The NotificationMessage is encoded straight into the PublishResponse; once
    sent, that buffer is kept for Republish and the connection continues with
    a recycled one, so nothing is copied (except with SignAndEncrypt, where the
    message is copied out before encryption in place).
- **Moving subscriptions:**
  - TransferSubscriptions moves a subscription to a session with the same user
    identity, optionally resending initial values, and notifies the old session
    with `GoodSubscriptionTransferred`.
  - Subscriptions of a session closed with `deleteSubscriptions = false` can be
    transferred until their lifetime ends.
- **Hot reload:** items follow it. A node that disappears reports
  `BadNodeIdUnknown`.
- **No allocation:** once queues and buffers have grown to size, nothing is
  allocated for numeric values. `tests/no_alloc.rs` checks this with a counting
  allocator over 1000 publish cycles.
- **Methods:** `Server.GetMonitoredItems` and `Server.ResendData` are
  available through Call. Cancel answers the queued Publish requests with the
  given handle with `BadRequestCancelledByClient`.
- **Intervals:** the fastest publishing and sampling intervals default to 1 ms.
  `--min-publishing-interval MS` and `--min-sampling-interval MS` lower them (to
  0.05 ms at least), at the cost of more wake-ups per second.

## Events

The Server object (`i=2253`) is an event notifier: a MonitoredItem on its
EventNotifier attribute with an EventFilter receives every server event.

- **Event types:** BaseEventType, AuditEventType, AuditSecurityEventType,
  AuditSessionEventType, AuditCreateSessionEventType,
  AuditActivateSessionEventType, SystemEventType, BaseModelChangeEventType and
  EventQueueOverflowEventType, with their field declarations, are in
  namespace 0 so clients can build filters by browsing.
- **Events raised:**
  - Session audit: `Session/CreateSession`, `Session/ActivateSession` (also on
    failure, with `Status = false`), `Session/CloseSession` and
    `Session/Timeout`, with SessionId, ClientUserId and the subtype's fields.
  - Write audit: one AuditWriteUpdateEventType per Write operation, successful
    or not (`Status`), with AttributeId, IndexRange, OldValue and NewValue; the
    source is the written node. Only built while someone subscribes to events:
    otherwise a Write pays one relaxed atomic load.
  - History update audit: AuditHistoryValueUpdateEventType (insert / replace /
    update, PerformInsertReplace), AuditHistoryRawModifyDeleteEventType and
    AuditHistoryAtTimeDeleteEventType, with UpdatedNode and
    ParameterDataTypeId. OldValues / NewValues are not filled.
  - Configuration reloaded: BaseModelChangeEventType, severity 100.
  - Configuration rejected: SystemEventType, severity 700, the parse error in
    the Message.
- **Select clauses:** BaseEventType fields and the fields of its subtypes. A
  field the event does not have is a null Variant, as is the ConditionId.
- **Where clauses:** Equals, IsNull, GreaterThan, LessThan,
  GreaterThanOrEqual, LessThanOrEqual, Like (`%`, `_`, `[...]`), Not, Between,
  InList, And, Or, OfType, BitwiseAnd and BitwiseOr, with SQL three-valued
  logic. Cast, InView and RelatedTo return
  `BadFilterOperatorUnsupported`. Errors come back in the EventFilterResult
  with `BadEventFilterInvalid` as the item status.
- **Queues:** a requested size of 0 gives 1000 events. When a queue overflows,
  an EventQueueOverflowEventType event takes the oldest position
  (`discardOldest`) or the newest one.
- **Cost:** events go through a ring of 4096 shared by all sessions. An event
  item reads it only when its subscription is serviced, so subscriptions
  without event items never touch it, and raising an event while nobody
  subscribes costs one atomic load. A slow reader that falls more than 4096
  events behind gets an overflow event.

## Historical access

Variables with `Historizing: true` have the Historizing attribute set and the
HistoryRead (and, when writable, HistoryWrite) AccessLevel bits.

- **Storage:** every write is recorded in a ring of `HistoryCapacity` values
  per variable, ordered by source timestamp (an out-of-order write is inserted
  in place). History lives in memory: it survives configuration reloads that
  keep the variable, not a restart. A reload that turns `Historizing` off keeps
  the data, and turning it back on resumes the same history.
- **HistoryRead, ReadRawModifiedDetails:** forward (start before end) or
  reverse (start after end, or only an end time) reads, start inclusive and
  end exclusive (both inclusive when equal), with `NumValuesPerNode` and
  continuation points. `ReturnBounds` adds the values just outside the range,
  or a `BadBoundNotFound` placeholder. `IsReadModified` returns
  HistoryModifiedData: the values replaced, deleted or inserted by
  HistoryUpdate, with time, type and user.
- **HistoryRead, ReadAtTimeDetails:** the value at each time, sloped
  interpolation for numbers (status with the Interpolated bit), the last value
  with `UncertainDataSubNormal` after the end, `BadNoData` before the start.
- **HistoryUpdate:** UpdateDataDetails (insert, replace, update; per value
  `GoodEntryInserted`, `GoodEntryReplaced`, `BadEntryExists`,
  `BadNoEntryExists`), DeleteRawModifiedDetails (raw or modified values in a
  range) and DeleteAtTimeDetails. It needs a user with write rights and a
  writable variable.
- **Continuation points** carry the node, the kind of read and where to
  resume, so they use no server memory and never run out
  (MaxHistoryContinuationPoints is 0, no limit). A read returns at most
  10 000 values per node (MaxReturnDataValues).
- **HistoryRead, ReadEventDetails:** with `--event-history N` the Server
  object (EventNotifier SubscribeToEvents | HistoryRead) records the last N
  events it notifies (ConditionRefresh replays excluded), even with no
  subscription. The EventFilter select clause picks the fields and its where
  clause the events; the time range works like raw reads (forward, reverse,
  or the newest `NumValuesPerNode` up to an end time). Continuation points
  carry the sequence number of the next event; events dropped from the
  history in between are skipped. AccessHistoryEventsCapability,
  MaxReturnEventValues (10 000) and MaxNodesPerHistoryReadEvents follow the
  option. Recording costs one short mutex and a push per event; a read
  encodes the selected fields straight from the stored events under that
  lock, with no copy.
- **Not yet:** annotations, HistoryUpdate of events.
- **Persistence (`--history-dir DIR`):** each historized variable has a file
  named by a hash of its namespace URI and identifier (so namespace index
  changes do not matter). Writers never touch the disk: a recorded value is
  also pushed into a journal under the history lock they already take (once
  per 32 inline writes). A background thread wakes every second, encodes each
  journal under that lock, appends it to the file and syncs it. HistoryUpdate
  changes, a damaged file (torn last record, other type) or a file holding
  more than twice the capacity make the next pass rewrite the file through a
  temporary file and a rename. At startup the files are read back before the
  server listens; variables added by a reload are restored on the next pass.
  A crash loses at most the last second. The modification log
  (HistoryModifiedData) is not persisted. Cost: 12.8 -> 17.3 ns per
  historized write (dev VM).
- **Cost:** a write of a variable without history checks one flag stored in
  the padding of the cell's first cache line (no measurable change). A
  historized write adds a short uncontended mutex and a push into the ring,
  about 25 ns. HistoryRead encodes each DataValue straight from the ring under
  the lock (about 13 ns per value).

## Aggregates

The functions are Objects of AggregateFunctionType under
`ServerCapabilities/AggregateFunctions` and
`HistoryServerCapabilities/AggregateFunctions`.

- **Functions:** Interpolative, Average, TimeAverage, TimeAverage2, Total,
  Total2, Minimum, Maximum, MinimumActualTime, MaximumActualTime, Range,
  Minimum2, Maximum2, MinimumActualTime2, MaximumActualTime2, Range2,
  AnnotationCount, Count, DurationInStateZero, DurationInStateNonZero,
  NumberOfTransitions, Start, End, Delta, StartBound, EndBound, DeltaBounds,
  DurationGood, DurationBad, PercentGood, PercentBad, WorstQuality,
  WorstQuality2, StandardDeviationSample, StandardDeviationPopulation,
  VarianceSample and VariancePopulation.
- **Intervals:** `[start, start + interval)`, the last one shorter (Partial
  bit) when the range is not a multiple of the interval. A processing
  interval of 0 gives one interval for the whole range. When EndTime is
  before StartTime, intervals go back in time from StartTime.
- **Bounds and interpolation:** each interval sees its raw values and the raw
  values just before and after it. Values at the interval ends are
  interpolated (sloped for numbers, stepped for Boolean and text), and
  extrapolated as Uncertain after the last value
  (`UseSlopedExtrapolation` picks sloped extrapolation).
- **Quality:** `TreatUncertainAsBad`, `PercentDataGood` and `PercentDataBad`
  (by count for the counting aggregates, by duration for the time-weighted
  ones) decide between Good, Uncertain (`UncertainDataSubNormal`) and Bad.
  An interval without data gives `BadNoData`. Results carry the Calculated
  or Interpolated historian bit, MultiValue when a minimum or maximum occurs
  several times. The server default configuration is TreatUncertainAsBad,
  100 % / 100 %, stepped extrapolation; a configuration with
  `PercentDataGood + PercentDataBad < 100` is rejected
  (`BadAggregateConfigurationRejected`).
- **HistoryRead with ReadProcessedDetails:** one aggregate per node
  (`BadAggregateListMismatch` otherwise), `BadAggregateNotSupported` and
  `BadAggregateInvalidInputs` (a numeric aggregate on a String) per node,
  at most 10 000 intervals per call with continuation points.
- **AggregateFilter on MonitoredItems:** the item must be on a historized
  variable (`BadMonitoredItemFilterUnsupported` otherwise), because the
  values come from its history, so every write counts, not only the
  sampled ones. Intervals are aligned on the requested StartTime (now when
  not given) and a result is queued once its interval has ended; the item
  is sampled ten times per interval, so a result leaves at most a tenth of
  an interval late. The AggregateFilterResult returns the start time,
  interval and configuration in effect.

## Alarms and conditions

An item with an `Alarm` gets a condition object `<Name>Alarm`
(`ns=<ns>;s=__alarm/<NodeId>`), referenced from the variable by HasCondition.

- **Types:** ExclusiveLimitAlarmType when the alarm has limits (`LowLow`,
  `Low`, `High`, `HighHigh`, any subset, ordered), OffNormalAlarmType when it
  has a `Normal` value (Boolean or number). ConditionClass is
  ProcessConditionClassType.
- **Evaluation:** every write of the variable evaluates the condition (a
  hook that variables without an alarm never run: one flag test in the
  cell's padding). The most severe limit crossed wins; a limit state is left
  only once the value is `Deadband` back on the normal side. Bad values keep
  the state and only update Quality. A new or more severe state needs a new
  Acknowledge and Confirm.
- **Events:** each state change raises an event of the alarm type on the
  Server object with every field of the type: EventId, ConditionId (the
  NodeId attribute of ConditionType), ConditionName, Retain, EnabledState,
  ActiveState (with EffectiveDisplayName), AckedState, ConfirmedState,
  LimitState/CurrentState, the limits, Quality, LastSeverity, Comment,
  ClientUserId, each with its Id and TransitionTime. Select clauses use
  browse paths such as `ActiveState/Id`.
- **Methods:** Acknowledge and Confirm (EventId and comment), AddComment,
  Enable and Disable (write rights), called on the condition with the
  method of its type. They return `BadEventIdUnknown` for an EventId that
  is not the condition's last one, `BadConditionBranchAlreadyAcked` /
  `Confirmed`, `BadConditionDisabled`, `BadConditionAlreadyEnabled` /
  `Disabled`.
- **ConditionRefresh / ConditionRefresh2** (on ConditionType): sends
  RefreshStart, every retained condition, RefreshEnd to the subscription
  (or one event item) only. RefreshStart and RefreshEnd go through whatever
  the where clause is, so a client filtering on its alarm types still sees
  them.
- **Shelving (Part 9 §5.8.10):** each condition has a ShelvingState object
  (`ns=<ns>;s=__alarm/<NodeId>/ShelvingState`, ShelvedStateMachineType).
  TimedShelve (ShelvingTime in ms), OneShotShelve and Unshelve, plus the
  1.05 TimedShelve2 / OneShotShelve2 / Unshelve2 with a comment, are called
  on it (or on the condition). A timed shelve ends by itself (checked every
  second); a one-shot shelve ends when the alarm returns to normal. Errors:
  `BadConditionAlreadyShelved`, `BadConditionNotShelved`,
  `BadShelvingTimeOutOfRange` (not positive, or above the item's
  `MaxTimeShelved`). Events carry ShelvingState/CurrentState (and Id),
  LastTransition (Id, TransitionTime), UnshelveTime (ms left),
  SuppressedOrShelved and MaxTimeShelved. A shelved alarm still raises its
  events: clients hide it on SuppressedOrShelved.
- **Branches (Part 9 §4.4):** an alarm that becomes active again while its
  previous occurrence is not yet acknowledged and confirmed keeps that
  occurrence as a branch (a more severe limit is the same occurrence). The
  branch is reported at once with its BranchId, keeps its state and its own
  EventIds: Acknowledge, Confirm and AddComment with a branch's EventId act
  on it only. Once acknowledged and confirmed it is reported with Retain
  false and deleted. ConditionRefresh reports retained branches after their
  condition; disabling a condition drops them; at most 64 per condition.
- **Reloads:** condition states survive reloads; new limits or severity
  apply at the next evaluation; a removed alarm disappears.

Not yet: suppression, dialog conditions and the
condition's state variables as browsable nodes (their values travel in the
events).

## Security

### Endpoints

By default the server offers nineteen endpoints. Use `--endpoints` to choose a subset (comma-separated):

| Name | SecurityPolicy | Mode |
|---|---|---|
| `none` | None | None |
| `basic256sha256-sign`, `basic256sha256-encrypt` | Basic256Sha256 | Sign / SignAndEncrypt |
| `aes128-sign`, `aes128-encrypt` | Aes128_Sha256_RsaOaep | Sign / SignAndEncrypt |
| `aes256-sign`, `aes256-encrypt` | Aes256_Sha256_RsaPss | Sign / SignAndEncrypt |
| `ecc-nistp256-aesgcm-sign`, `ecc-nistp256-aesgcm-encrypt` | ECC_nistP256_AesGcm | Sign / SignAndEncrypt |
| `ecc-nistp256-chachapoly-sign`, `…-encrypt` | ECC_nistP256_ChaChaPoly | Sign / SignAndEncrypt |
| `ecc-nistp384-aesgcm-sign`, `…-encrypt` | ECC_nistP384_AesGcm | Sign / SignAndEncrypt |
| `ecc-nistp384-chachapoly-sign`, `…-encrypt` | ECC_nistP384_ChaChaPoly | Sign / SignAndEncrypt |
| `ecc-curve25519-aesgcm-sign`, `…-encrypt` | ECC_curve25519_AesGcm | Sign / SignAndEncrypt |
| `ecc-curve25519-chachapoly-sign`, `…-encrypt` | ECC_curve25519_ChaChaPoly | Sign / SignAndEncrypt |

Cryptography is provided by aws-lc-rs: RSA-OAEP, PKCS#1 v1.5 and PSS signatures, AES-CBC, HMAC-SHA256 and P_SHA256. Client keys of 2048 to 4096 bits are accepted.

The ECC policies follow OPC UA 1.05.04 and later with the SecureChannelEnhancements, as implemented by open62541:

- **OpenSecureChannel:** signed (ECDSA with raw r‖s, or Ed25519), not encrypted. The nonces are ephemeral public keys (P-256: 64 bytes x‖y, P-384: 96, X25519: 32). The client certificate must be on the policy's curve.
- **Keys:** HKDF (SHA-256, SHA-384 for P-384) over the shared secret, with salt = info = length ‖ `opcua-server`/`opcua-client` ‖ sender nonce ‖ receiver nonce. The input keying material is chained across renewals (XOR of the successive secrets).
- **Messages:** AES-GCM (128-bit for P-256 and curve25519, 256-bit for P-384) or ChaCha20-Poly1305, with a 16-byte tag and no padding. The IV is the derived IV masked with the TokenId and the previous sequence number. Sign mode authenticates the whole chunk. Sequence numbers start at 0 and wrap from 2³²−1 to 0.
- **Channel binding:** the server signs its first OpenSecureChannel response together with the client's request signature; that signature is the ChannelThumbprint, prepended to the CreateSession and ActivateSession signatures, which cover certificate hashes instead of certificates. The SignatureData algorithm is left empty.
- **Users:** anonymous, X.509 (a user certificate on the policy's curve) and user name. When the client asks for it (`ECDHPolicyUri` in the request's AdditionalHeader), CreateSession and ActivateSession return a fresh ephemeral key signed with our key (`ECDHKey`). The password comes back as an EccEncryptedSecret: signed by the client's application key, AEAD-encrypted with keys from ECDH with that ephemeral key and HKDF (label `opcua-secret`), and bound to the session's server nonce. Each ephemeral key decrypts one secret.

### Certificates (`--pki DIR`, default `pki`)

```
pki/own/certs/fastua.der        server certificate (created self-signed, RSA 2048, if missing)
pki/own/private/fastua.pk8      private key (mode 0600)
pki/own/certs/fastua_<curve>.der, pki/own/private/fastua_<curve>.pk8
                                ECC certificates and keys (nistP256, nistP384, curve25519), created if missing
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

`crates/fastua/tests/interop/asyncua_interop.py` runs the release binary against the Python asyncua client. It checks every policy and mode, a 4096-bit client key, the certificate trust flow, user name and X.509 users, access rights, hot reload, subscriptions with absolute and percent deadbands, events with a where clause, GetMonitoredItems, ServerCapabilities, index ranges and HistoryRead (raw values, bounds, continuation points, processed Average and Maximum). CI runs it on both architectures.

```bash
pip install asyncua cryptography
python3 crates/fastua/tests/interop/asyncua_interop.py target/release/fastua config/machines
```

`crates/fastua/tests/interop/open62541_ecc.c` checks the ECC policies against the open62541 client (master, built with `UA_ENABLE_ENCRYPTION=OPENSSL`; CI pins the commit). For each of the six policies and both modes: an anonymous session, reads, a browse and a multi-chunk response. Per policy, an X.509 user on the same curve, a user name login and a wrong password. Per curve, a token renewal: 15 s of reads on a 10 s token.

```bash
cc crates/fastua/tests/interop/open62541_ecc.c -lopen62541 -lssl -lcrypto -o open62541_ecc
crates/fastua/tests/interop/open62541_ecc.sh target/release/fastua config/machines ./open62541_ecc
```

## Scope

Implemented: UA TCP (HEL/ACK/ERR, chunking both ways), SecureChannel with
SecurityPolicy None, Basic256Sha256, Aes128_Sha256_RsaOaep,
Aes256_Sha256_RsaPss and the six ECC AEAD policies in Sign and SignAndEncrypt
modes (issue/renew, token
lifetime, sequence checks), PKI with CRLs, sessions with anonymous, user name
and X.509 identities, per-user read/write rights, GetEndpoints, FindServers,
Read (with index ranges on arrays, Strings and ByteStrings), Write (with
index ranges on String and ByteString variables: the new value must have
exactly the selected number of elements), Browse,
HistoryRead and HistoryUpdate (see [Historical access](#historical-access)),
BrowseNext, TranslateBrowsePathsToNodeIds, RegisterNodes/UnregisterNodes,
Cancel, Call, ServerStatus with BuildInfo, NamespaceArray, ServerCapabilities
with OperationLimits, every Subscription and MonitoredItem service (see
[Subscriptions](#subscriptions), MonitoredItems accept an index range: only
those elements are compared and reported, through the Variant path) and events with session audit (see
[Events](#events)), alarms and conditions (see
[Alarms and conditions](#alarms-and-conditions)).

Not yet: the deprecated non-AEAD ECC policies.
