#!/bin/sh
# M7's exit criterion against the real agent and scanner: a TheySpy server, and a throwaway Linux
# container (the "lab VM") with one indicator seeded in its Chrome history. The agent enrolls, runs
# zero-breach's scanner (checked against its signed hash) and reports; TheySpy must show a
# "contacted" finding and the checks the scanner could not run as gaps, not as clean.
#   sh scripts/e2e-agent.sh
set -eu
port=18797
data=$(mktemp -d)
password=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
TS_HOST=0.0.0.0 TS_PORT=$port TS_DATA_DIR="$data" TS_ADMIN_PASSWORD="$password" TS_BLOCKLISTS_AUTO=false TS_IOC_AUTOCHECK=false TS_FLEET_AUTO=false TS_CVES_AUTO=false \
  node server/index.mjs > "$data/server.log" 2>&1 &
server=$!
cleanup() { kill "$server" 2>/dev/null || true; rm -rf "$data"; }
trap cleanup EXIT
i=0; until curl -fs "http://127.0.0.1:$port/healthz" >/dev/null; do i=$((i + 1)); [ "$i" -gt 30 ] && { cat "$data/server.log"; exit 1; }; sleep 1; done
PORT=$port PASSWORD="$password" node scripts/e2e-agent.mjs
