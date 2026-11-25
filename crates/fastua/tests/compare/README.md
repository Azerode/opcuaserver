# Comparative benchmark: fastua vs open62541

The same load client (`examples/compare.rs`, built on `fastua::client`) runs
against both servers, on the same machine, in CI on x86_64 and aarch64. The
report is published in the job summary.

Both servers hold the same 100 writable Int32 variables (fastua:
`config/machine.json`, namespace 2; open62541: `open62541_server.c`,
namespace 1) and offer None, Basic256Sha256 SignAndEncrypt and
ECC_nistP256_AesGcm SignAndEncrypt. fastua runs twice: blocking and with
`--busy-poll 200`. open62541 is pinned (`OPEN62541_SHA` in the workflow) and
built in Release.

Measures, per security mode:

- connection + secure channel + session setup (p50);
- Read of 1 value, blocking and busy-poll client (p50, p99);
- Read of 100 values, Write of 1 value (p50, p99);
- throughput with 64 pipelined Reads;
- throughput with 1, N and 4N concurrent clients (N = cores, mode None).

Run locally:

    cargo build --release --example compare
    cc -O2 tests/compare/open62541_server.c -I<open62541>/include -L<open62541>/lib \
       -lopen62541 -lssl -lcrypto -lpthread -lm -o open62541_server
    tests/compare/run.sh target/release/fastua target/release/examples/compare ./open62541_server out
