#!/bin/sh
# M10's restore check against the real image, the way BoxPilot backs an app up: stop the container,
# archive its data folder, wipe both, unpack the archive and start a new container on it. Everything
# must come back: settings, API tokens (they still work), devices and findings.
#   sh scripts/e2e-restore.sh [image]   (default theyspy:ci)
set -eu
image=${1:-theyspy:ci}
port=18798
work=$(mktemp -d)
password=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
secret=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
cleanup() { docker rm -f theyspy-restore >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
start() {
  docker run -d --name theyspy-restore --user "$(id -u):$(id -g)" -p "127.0.0.1:$port:8797" -v "$work/$1:/data" \
    -e TS_ADMIN_PASSWORD="$password" -e TS_SESSION_SECRET="$secret" -e TS_IOC_AUTOCHECK=false -e TS_BLOCKLISTS_AUTO=false -e TS_FLEET_AUTO=false -e TS_CVES_AUTO=false \
    "$image" >/dev/null
  i=0; until curl -fs "http://127.0.0.1:$port/healthz" >/dev/null; do i=$((i + 1)); [ "$i" -gt 40 ] && { docker logs theyspy-restore; exit 1; }; sleep 1; done
}
mkdir "$work/data"
start data
PORT=$port PASSWORD="$password" STATE="$work/state.json" node scripts/e2e-restore.mjs before
# A clean stop must close the database: no WAL left for the archive to miss.
docker stop -t 10 theyspy-restore >/dev/null && docker rm theyspy-restore >/dev/null
[ ! -s "$work/data/theyspy.db-wal" ] || { echo "the stop left a write-ahead log behind"; exit 1; }
DB="$work/data/theyspy.db" node scripts/e2e-restore.mjs seed
tar -C "$work" -czf "$work/backup.tgz" data
rm -rf "$work/data"
echo "- archived the data folder and wiped it"
# Into a new folder, as on a fresh machine (and Docker Desktop caches a reused mount path).
mkdir "$work/fresh" && tar -C "$work/fresh" -xzf "$work/backup.tgz"
start fresh/data
PORT=$port PASSWORD="$password" STATE="$work/state.json" node scripts/e2e-restore.mjs after
