#!/bin/sh
# The other DNS servers TheySpy reads, for real: AdGuard Home and Technitium DNS (the images pinned
# below), each with a block rule for one test indicator, then DNS lookups from fixed client
# addresses, then scripts/e2e-dns-sources.mjs hunts, watches and looks up through TheySpy's own
# sources. Every name is under the reserved .example domain (Technitium answers .test itself, before
# its block list), and neither server resolves anything outside: both forward to a closed port.
# The one download is Technitium's query-log app, checked against its SHA-256 before it is installed.
#   sh scripts/e2e-dns-sources.sh
set -eu

adguard_image="adguard/adguardhome:v0.107.65@sha256:d765078d2140b464ce837128a4f536f80b4c9ab7fd5b6833ae690b72fae40897"
technitium_image="technitium/dns-server:15.6.2@sha256:eb48ac5c135f4ab936b536f74f853d53e15ab39ef37fdbc9598a089b90d9f245"
qlog_url="https://download.technitium.com/dns/apps/QueryLogsSqliteApp-v9.1.3.zip"
qlog_sha256="f2e98072de46b87683eabc3a3f44056f0eff95d0de6e6d85e67ebd909744b355"
client_image="busybox:1.37"
net=theyspy-dns-e2e
work=$(mktemp -d)
password=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')

cleanup() {
  docker rm -f theyspy-e2e-adguard theyspy-e2e-technitium >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
cleanup
work=$(mktemp -d)
docker network create --subnet 172.29.54.0/24 "$net" >/dev/null

docker run -d --name theyspy-e2e-adguard --network "$net" --ip 172.29.54.2 -p 127.0.0.1:18101:3000 "$adguard_image" >/dev/null
docker run -d --name theyspy-e2e-technitium --network "$net" --ip 172.29.54.3 -p 127.0.0.1:18102:5380 -e DNS_SERVER_ADMIN_PASSWORD="$password" "$technitium_image" >/dev/null

wait_http() { i=0; until curl -s -o /dev/null -m 2 "$1"; do i=$((i + 1)); [ "$i" -gt 60 ] && { echo "$2 never answered" >&2; docker logs "$3" | tail -20; exit 1; }; sleep 2; done; }
wait_http http://127.0.0.1:18101/ "AdGuard Home" theyspy-e2e-adguard
wait_http http://127.0.0.1:18102/ "Technitium" theyspy-e2e-technitium

# AdGuard Home: first-run setup, an upstream that goes nowhere, and a rule for one indicator.
curl -sf -X POST http://127.0.0.1:18101/control/install/configure -H 'content-type: application/json' \
  -d "{\"web\":{\"ip\":\"0.0.0.0\",\"port\":3000},\"dns\":{\"ip\":\"0.0.0.0\",\"port\":53},\"username\":\"theyspy\",\"password\":\"$password\"}" >/dev/null
wait_http http://127.0.0.1:18101/control/status "AdGuard Home after setup" theyspy-e2e-adguard
ag() { curl -sf -u "theyspy:$password" -H 'content-type: application/json' "$@"; }
ag -X POST http://127.0.0.1:18101/control/dns_config -d '{"upstream_dns":["127.0.0.1:5353"]}' >/dev/null
ag -X POST http://127.0.0.1:18101/control/filtering/set_rules -d '{"rules":["||c2-node.theyspy.example^"]}' >/dev/null
# AdGuard logs nothing for a lookup its upstream cannot answer, so it answers the allowed test names
# itself (by name: a rewrite outranks a block rule, and c2-node must stay blocked).
for name in ads-sync.theyspy.example deep.ads-sync.theyspy.example notads-sync.theyspy.example unrelated.theyspy.example; do
  ag -X POST http://127.0.0.1:18101/control/rewrite/add -d "{\"domain\":\"$name\",\"answer\":\"192.0.2.10\"}" >/dev/null
done

# Technitium: a session token, recursion to nowhere, the query-log app (checked), and a block for one indicator.
token=$(curl -sf "http://127.0.0.1:18102/api/user/login?user=admin&pass=$password" | node -e 'let t="";process.stdin.on("data",(c)=>t+=c).on("end",()=>process.stdout.write(JSON.parse(t).token))')
tq() { curl -sf "http://127.0.0.1:18102/api/$1&token=$token" >/dev/null; }
# Recursion stays on (with it off Technitium refuses before its block list), forwarded to a closed port.
tq "settings/set?recursion=Allow&forwarders=127.0.0.1:5353&forwarderProtocol=Udp"
curl -sfL "$qlog_url" -o "$work/qlog.zip"
echo "$qlog_sha256  $work/qlog.zip" | shasum -a 256 -c - >/dev/null
curl -sf -X POST "http://127.0.0.1:18102/api/apps/install?token=$token&name=Query%20Logs%20(Sqlite)" -F "fileAppZip=@$work/qlog.zip" >/dev/null
tq "blocked/add?domain=c2-node.theyspy.example"

lookup() {
  n=0
  while [ "$n" -lt 8 ]; do
    out=$(docker run --rm --network "$net" --ip "$1" "$client_image" nslookup -timeout=2 "$3" "$2" 2>&1 || true)
    case "$out" in *"timed out"*|*"no servers could be reached"*) ;; *"Server:"*) return 0 ;; esac
    n=$((n + 1)); sleep 2
  done
  echo "$2 never answered $3 from $1: $out" >&2; exit 1
}
sleep 3
sent_at=$(date +%s)
for server in 172.29.54.2 172.29.54.3; do
  lookup 172.29.54.10 "$server" ads-sync.theyspy.example
  lookup 172.29.54.10 "$server" deep.ads-sync.theyspy.example
  lookup 172.29.54.10 "$server" notads-sync.theyspy.example
  lookup 172.29.54.11 "$server" c2-node.theyspy.example
  lookup 172.29.54.11 "$server" c2-node.theyspy.example
  lookup 172.29.54.12 "$server" unrelated.theyspy.example
done
sleep 3

ADGUARD_URL=http://127.0.0.1:18101 TECHNITIUM_URL=http://127.0.0.1:18102 E2E_PASSWORD="$password" E2E_TOKEN="$token" E2E_SENT_AT="$sent_at" \
  node scripts/e2e-dns-sources.mjs
