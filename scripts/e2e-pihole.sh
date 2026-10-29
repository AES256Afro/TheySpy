#!/bin/sh
# Starts an offline Pi-hole 6 (the image BoxPilot's catalog pins), sends DNS lookups from fixed
# client addresses, and runs scripts/e2e-pihole.mjs against it. Nothing leaves the machine: Pi-hole
# has no upstream resolver, and every name is under the reserved .test domain.
#   sh scripts/e2e-pihole.sh
set -eu

image="pihole/pihole:2026.07.2@sha256:f7d1be836e3bc608b56d82fc9904f5a831cdfbc0dc9c6d58f94e4c985c70038b"
client_image="busybox:1.37"
net=theyspy-e2e
port=18053
password=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')

cleanup() {
  docker rm -f theyspy-e2e-pihole >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create --subnet 172.29.53.0/24 "$net" >/dev/null
docker run -d --name theyspy-e2e-pihole --network "$net" --ip 172.29.53.2 -p "127.0.0.1:$port:80" --add-host host.docker.internal:host-gateway \
  -e TZ=Etc/UTC -e FTLCONF_webserver_api_password="$password" -e FTLCONF_dns_upstreams='127.0.0.1#5353' \
  -e FTLCONF_dns_listeningMode=all "$image" >/dev/null

i=0
until [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/api/auth")" = 401 ]; do
  i=$((i + 1)); [ "$i" -gt 90 ] && { docker logs theyspy-e2e-pihole; exit 1; }; sleep 2
done

# A lookup counts only when nslookup ran and Pi-hole answered. Retry otherwise: a timeout never
# reached Pi-hole's log, and reusing a client address right after the last container can fail with
# "address already in use" before nslookup even starts.
lookup() {
  n=0
  while [ "$n" -lt 8 ]; do
    out=$(docker run --rm --network "$net" --ip "$1" "$client_image" nslookup -timeout=2 "$2" 172.29.53.2 2>&1 || true)
    [ -n "${E2E_VERBOSE:-}" ] && echo "lookup $2 <- $1: $(echo "$out" | tr '\n' ' ' | cut -c1-150)" >&2
    case "$out" in *"timed out"*|*"no servers could be reached"*) ;; *"Server:"*) return 0 ;; esac
    n=$((n + 1)); sleep 2
  done
  echo "Pi-hole never answered $2 from $1: $out" >&2; exit 1
}
# The API answers before the DNS server is ready, and before Pi-hole has written its versions file
# (GET /api/info/version fails until then); wait for both.
lookup 172.29.53.13 ready.theyspy.test
i=0
until docker exec theyspy-e2e-pihole test -s /etc/pihole/versions; do
  i=$((i + 1)); [ "$i" -gt 60 ] && { echo "Pi-hole never wrote /etc/pihole/versions" >&2; exit 1; }; sleep 1
done
sent_at=$(date +%s)
lookup 172.29.53.10 ads-sync.theyspy.test
lookup 172.29.53.10 deep.ads-sync.theyspy.test
lookup 172.29.53.10 notads-sync.theyspy.test
lookup 172.29.53.11 ads-sync.theyspy.test
lookup 172.29.53.11 c2-node.theyspy.test
lookup 172.29.53.11 c2-node.theyspy.test
lookup 172.29.53.12 unrelated.theyspy.test

PIHOLE_URL="http://127.0.0.1:$port" PIHOLE_PASSWORD="$password" E2E_SENT_AT="$sent_at" E2E_DOCKER_NETWORK="$net" E2E_LISTS_HOST=host.docker.internal \
  node scripts/e2e-pihole.mjs
