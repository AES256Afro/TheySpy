#!/bin/sh
# Two TheySpy sites, for real: a second TheySpy server (the "cabin") with a lookup that got past its
# blocking, and scripts/e2e-sites.mjs reading it as a site through a read-only API token.
#   sh scripts/e2e-sites.sh
set -eu
port=18797
data=$(mktemp -d)
password=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
cleanup() { kill "$server" 2>/dev/null || true; rm -rf "$data"; }
trap cleanup EXIT
# The cabin's database, with one indicator lookup Pi-hole did not block (as its live watch records one).
DB="$data/theyspy.db" node --input-type=module -e '
import { openDatabase } from "./server/db.mjs";
const db = openDatabase(process.env.DB);
const at = new Date(Date.now() - 3600_000).toISOString();
db.prepare("INSERT INTO ioc_hit_events (source, query_id, at, indicator, domain, via, client_ip, client_name, status, blocked, found_by, found_at) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)").run("pihole", at, "fearevolve.com", "cdn.fearevolve.com", "query", "192.168.50.20", "cabin-laptop", "FORWARDED", "watch", at);
db.close();'
TS_HOST=127.0.0.1 TS_PORT=$port TS_DATA_DIR="$data" TS_ADMIN_PASSWORD="$password" TS_BLOCKLISTS_AUTO=false TS_IOC_AUTOCHECK=false TS_FLEET_AUTO=false TS_CVES_AUTO=false \
  node server/index.mjs > "$data/server.log" 2>&1 &
server=$!
i=0; until curl -fs "http://127.0.0.1:$port/healthz" >/dev/null; do i=$((i + 1)); [ "$i" -gt 30 ] && { cat "$data/server.log"; exit 1; }; sleep 1; done
SITE_URL="http://127.0.0.1:$port" SITE_PASSWORD="$password" node scripts/e2e-sites.mjs
