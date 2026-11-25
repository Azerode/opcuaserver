#!/usr/bin/env bash
# Interoperability check of the ECC policies against the open62541 client.
#
# usage: open62541_ecc.sh <fastua binary> <config dir> <open62541_ecc client binary>
#
# Starts the server in a temporary directory (client certificates trusted,
# X.509 users allowed) and runs the client; see open62541_ecc.c.
set -euo pipefail
server=$1 config=$2 client=$3
port=48556
work=$(mktemp -d)
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; rm -rf "$work"' EXIT
"$server" --config "$config" --pki "$work/pki" --listen "127.0.0.1:$port" \
    --endpoint "opc.tcp://127.0.0.1:$port" --trust-all-clients --x509-users read >"$work/server.log" 2>&1 &
pid=$!
for _ in $(seq 100); do
    [ -d "$work/pki/users/trusted/certs" ] && (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && break
    sleep 0.1
done
status=0
"$client" "opc.tcp://127.0.0.1:$port" "$work/pki/users/trusted/certs" || status=$?
if [ "$status" -ne 0 ]; then
    echo "--- server log"
    cat "$work/server.log"
fi
exit "$status"
