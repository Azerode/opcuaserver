#!/usr/bin/env bash
# Comparative benchmark: the same load client against fastua and the
# open62541 server, on the same machine (see README.md).
#
# usage: run.sh <fastua binary> <compare client> <open62541_server binary> [out dir]
set -euo pipefail
fastua=$1 client=$2 o6=$3
here=$(cd "$(dirname "$0")" && pwd)
out=${4:-$(mktemp -d)}
mkdir -p "$out"
work=$(mktemp -d)
pids=()
trap 'for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done; rm -rf "$work"' EXIT

wait_port() {
    for _ in $(seq 200); do
        (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
        sleep 0.05
    done
    echo "server on port $1 did not start" >&2
    return 1
}

# fastua, blocking then busy-poll (namespace index 2 is the configured file).
for mode in blocking busy-poll; do
    port=$([ "$mode" = blocking ] && echo 48600 || echo 48601)
    extra=()
    [ "$mode" = busy-poll ] && extra=(--busy-poll 200)
    "$fastua" --config "$here/config" --pki "$work/pki-$mode" --listen "127.0.0.1:$port" \
        --endpoint "opc.tcp://127.0.0.1:$port" --trust-all-clients --anonymous write \
        --endpoints none,basic256sha256-encrypt,ecc-nistp256-aesgcm-encrypt "${extra[@]}" \
        >"$work/fastua-$mode.log" 2>&1 &
    pids+=($!)
    wait_port "$port"
    "$client" run "127.0.0.1:$port" 2 "$work/pki-$mode/own/certs/fastua.der" \
        "$work/pki-$mode/own/certs/fastua_nistP256.der" "$out/fastua-$mode.tsv"
    kill "${pids[-1]}"; wait "${pids[-1]}" 2>/dev/null || true
done

# open62541 (its own variables are in namespace 1).
mkdir -p "$work/o6"
"$o6" 48602 "$work/o6" >"$work/open62541.log" 2>&1 &
pids+=($!)
for _ in $(seq 200); do [ -f "$work/o6/ready" ] && break; sleep 0.05; done
wait_port 48602
"$client" run 127.0.0.1:48602 1 "$work/o6/server_rsa.der" "$work/o6/server_ecc.der" "$out/open62541.tsv" || {
    cat "$work/open62541.log"; exit 1; }

"$client" report "fastua busy-poll=$out/fastua-busy-poll.tsv" "fastua blocking=$out/fastua-blocking.tsv" \
    "open62541=$out/open62541.tsv" | tee "$out/report.md"
