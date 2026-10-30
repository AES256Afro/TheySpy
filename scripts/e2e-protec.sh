#!/bin/sh
# Protec for real: its published image (as BoxPilot pins it), an agent enrolled from inside its
# network namespace (Protec's agent refuses plain HTTP to anything but localhost), a viewer
# credential, and scripts/e2e-protec.mjs reading the inventory through TheySpy's own code.
#   sh scripts/e2e-protec.sh
set -eu
image="ghcr.io/aes256afro/protec:0.7.0@sha256:60d6d3cf2e3d30f4811a9c3b91875a53d3c07fd05333505dae90adbed712c7ca"
cleanup() { docker rm -f theyspy-e2e-protec >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker run -d --name theyspy-e2e-protec -p 127.0.0.1:18765:8765 "$image" >/dev/null
i=0; until curl -fs -m 2 http://127.0.0.1:18765/healthz >/dev/null; do i=$((i + 1)); [ "$i" -gt 60 ] && { docker logs theyspy-e2e-protec | tail -20; exit 1; }; sleep 1; done
admin=$(docker exec theyspy-e2e-protec cat /data/admin-token)
json() { node -e 'let t="";process.stdin.on("data",(c)=>t+=c).on("end",()=>process.stdout.write(String(JSON.parse(t)[process.argv[1]])))' "$1"; }
enrollment=$(curl -sf -X POST http://127.0.0.1:18765/api/enrollments -H "Authorization: Bearer $admin" -H 'content-type: application/json' -d '{}' | json token)
echo "$enrollment" | docker run --rm -i --network container:theyspy-e2e-protec --entrypoint python3 "$image" -m protec.agent --server http://127.0.0.1:8765 --enroll --once --state /tmp/agent.json
viewer=$(curl -sf -X POST http://127.0.0.1:18765/api/credentials -H "Authorization: Bearer $admin" -H 'content-type: application/json' -d '{"name":"theyspy","role":"viewer","hours":1}' | json token)
PROTEC_URL=http://127.0.0.1:18765 PROTEC_VIEWER="$viewer" node scripts/e2e-protec.mjs
