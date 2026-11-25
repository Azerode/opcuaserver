#!/usr/bin/env bash
# Runs one third party client against a fresh fastua server.
#
# usage: serve.sh <fastua binary> <client command...>
#
# The server runs in a temporary directory with the interop namespace
# (config/Plant.json), every default endpoint, the HTTPS transport, users
# operator / s3cret (read/write) and viewer / s3cret (read only), event history
# and --trust-all-clients (the certificate trust flow is covered by
# asyncua_interop.py). The client gets the endpoints in FASTUA_URL and
# FASTUA_HTTPS_URL and the server's work directory in FASTUA_WORK.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
server=$1
shift
port=${FASTUA_PORT:-48560}
https_port=$((port + 1))
work=$(mktemp -d)
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; rm -rf "$work"' EXIT
cp -r "$here/config" "$work/config"
hash=$(printf s3cret | "$server" hash-password)
printf '{ "users": [ { "name": "operator", "password": "%s", "write": true }, { "name": "viewer", "password": "%s" } ] }' \
    "$hash" "$hash" >"$work/users.json"
"$server" --config "$work/config" --pki "$work/pki" --listen "127.0.0.1:$port" \
    --endpoint "opc.tcp://127.0.0.1:$port" --application-uri "urn:fastua:interop:server" \
    --https-listen "127.0.0.1:$https_port" --https-endpoint "opc.https://127.0.0.1:$https_port" \
    --users "$work/users.json" --trust-all-clients --event-history 1000 >"$work/server.log" 2>&1 &
pid=$!
for _ in $(seq 100); do
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && break
    sleep 0.1
done
status=0
FASTUA_URL="opc.tcp://127.0.0.1:$port" FASTUA_HTTPS_URL="opc.https://127.0.0.1:$https_port" FASTUA_WORK="$work" \
    "$@" || status=$?
if [ "$status" -ne 0 ]; then
    echo "--- server log (tail)"
    tail -n 100 "$work/server.log"
fi
exit "$status"
