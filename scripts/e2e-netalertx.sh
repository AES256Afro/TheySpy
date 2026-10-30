#!/bin/sh
# NetAlertX both ways, for real: a NetAlertX (the image pinned below, bridge mode, no scanning needed)
# with two devices, then scripts/e2e-netalertx.mjs syncs, previews and fills through TheySpy's own code.
#   sh scripts/e2e-netalertx.sh
set -eu
image="ghcr.io/netalertx/netalertx@sha256:ebce55cdbccc0f71544e6997541fe81db803b8c8bec3079435b8cd0a40d49b7e"
token="t_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
cleanup() { docker rm -f theyspy-e2e-netalertx >/dev/null 2>&1 || true; docker volume rm theyspy-e2e-netalertx >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker run -d --name theyspy-e2e-netalertx --read-only --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --cap-add NET_BIND_SERVICE --cap-add CHOWN --cap-add SETUID --cap-add SETGID \
  -v theyspy-e2e-netalertx:/data --tmpfs "/tmp:uid=20211,gid=20211,mode=1700,rw,noexec,nosuid,nodev" -p 127.0.0.1:18212:20212 \
  -e PORT=20211 -e GRAPHQL_PORT=20212 -e APP_CONF_OVERRIDE="{\"API_TOKEN\":\"$token\"}" "$image" >/dev/null
i=0; until [ "$(curl -s -o /dev/null -w '%{http_code}' -m 3 -H "Authorization: Bearer $token" http://127.0.0.1:18212/devices)" = 200 ]; do i=$((i + 1)); [ "$i" -gt 90 ] && { docker logs theyspy-e2e-netalertx | tail -20; exit 1; }; sleep 2; done
NETALERTX_URL=http://127.0.0.1:18212 NETALERTX_TOKEN="$token" node scripts/e2e-netalertx.mjs
