# TheySpy

A self-hosted defender against ad-delivered spyware and ad-intelligence (ADINT) tracking, built in response to Citizen Lab's *Exposing AdFection* (October 2026). It runs on its own as one container, and BoxPilot can install and manage it.

What it will do (see [docs/PLAN.md](docs/PLAN.md)):

- Hunt your Pi-hole query log for spyware and ADINT indicators (zero-breach's set), and block what your lists miss.
- Collect every DNS blocklist, sorted into categories and kept up to date, with per-device **baselines** that show what each level would block on your real traffic.
- Keep a list of every device on your network, and check any one in depth.
- Check a website you run for PHP problems: an unsupported PHP version, its CVEs, a PHP CMS's version and CVEs, and files that should never be public (.env, .git, phpinfo, PHPUnit's eval-stdin.php, config backups). Sites on your network can be checked directly; a public site must be proved yours with a token file or DNS record.
- Gather CVEs and zero-days from 11 feeds and show which apply to your devices, including the one you are reading on.

**Status: 1.0.** All milestones in [docs/PLAN.md](docs/PLAN.md) are done:
- Pi-hole hunting and blocking;
- the blocklist library and baselines;
- the device fleet and targeted checks;
- CVE and zero-day matching (including the device you read on);
- the endpoint agent and MVT import (Evidence locker);
- ad-exposure scores and hardening kits;
- alerts, the weekly briefing, a read-only API and MCP;
- BoxPilot packaging with backup and restore.

Start with [docs/GUIDE.md](docs/GUIDE.md). [SECURITY.md](SECURITY.md) has the threat model and the security review.

## Run it

```bash
docker compose up -d
```

Open `http://<this machine>:8797`. Images are published for amd64 and arm64 (a Raspberry Pi beside Pi-hole works). Without `TS_ADMIN_PASSWORD`, the first start prints a generated owner password once:

```bash
docker compose logs theyspy
```

On BoxPilot, use the catalog entry in [boxpilot/theyspy.yaml](boxpilot/theyspy.yaml).

### Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `TS_ADMIN_PASSWORD` | generated | Owner password. |
| `TS_SESSION_SECRET` | generated | Signs sessions; changing it signs everyone out. |
| `TS_PORT` | `8797` | Port to listen on. |
| `TS_DATA_DIR` | `./data` (`/data` in the image) | Where the database lives. |
| `TS_LOOK` | `auto` | Default look: `auto`, `ops`, `light`, `pihole`, `evidence`, `paper`, `glass`. |
| `TS_BRAND_NAME` / `TS_BRAND_TAGLINE` | `TheySpy` / empty | Name and tagline shown in the app. |
| `TS_ACCENT` | empty | Accent colour such as `#39c6ff`. |
| `TS_COOKIE_SECURE` | `false` | Set `true` when served over HTTPS. |
| `TS_PIHOLE_URL` / `TS_PIHOLE_PASSWORD` | empty | Pi-hole 6's address and an app password. Overrides the Pi-hole Sentinel screen. |
| `TS_PIHOLE_DB` | empty | Path to a read-only `pihole-FTL.db` instead of the API (hunting and watching only). |
| `TS_PIHOLE_WRITE` | unset | `false` forbids changing Pi-hole whatever the screen says; `true` allows it. Unset: the screen decides. |
| `TS_BLOCKLISTS_AUTO` | `true` | Update enabled blocklists every 6 hours and look for new ones daily (new lists only become candidates). |
| `TS_FLEET_AUTO` | `true` | Read Pi-hole's network table every 5 minutes and sweep the networks chosen on the Fleet screen every 30 minutes. |
| `TS_SCAN_RANGES` | private ranges | Comma-separated IPv4 ranges discovery may probe: `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10` by default. |
| `TS_CVES_AUTO` | `true` | CISA KEV hourly, NVD every 2 hours (the last 120 days on the first run), EPSS daily. |
| `TS_NVD_API_KEY` | empty | Optional free NVD key: 50 requests per 30 seconds instead of 5. |
| `TS_NTFY_URL` / `TS_NTFY_TOPIC` / `TS_NTFY_TOKEN` | empty | Where alerts and the weekly briefing go (ntfy). Also settable on the Briefing screen. |
| `TS_IOC_AUTOCHECK` | `true` | Look for a newer indicator set once a day. Updates are only offered for review, never applied by themselves. |

## Develop

```bash
npm install
```

```bash
npm run dev:server
```

```bash
npm run dev
```

The UI runs on 5173 and hands `/api` to the server on 8797. `sh scripts/e2e-pihole.sh` checks Pi-hole Sentinel against a real, offline Pi-hole 6 in Docker; `sh scripts/e2e-agent.sh` runs the real agent and scanner in a throwaway container; `sh scripts/e2e-restore.sh` backs up, wipes and restores the built image. `npm run check` builds, type-checks, tests, lints, checks every look's contrast (and that no colour is hard-coded outside `shared/looks.json`), validates the BoxPilot manifest against BoxPilot's schema when a checkout is at `../BoxPilot` or `BOXPILOT_DIR`, and runs the release checklist.

## Layout

- `server/` Node 24 + Express 5 + `node:sqlite`: config, migrations, auth, jobs, audit, appearance, `iocs/` (indicators), `pihole/` (Pi-hole Sentinel) and `blocklists/` (the blocklist library).
- `src/` React 19 UI. `shared/` holds the look tokens and screen list both sides read.
- `boxpilot/` the BoxPilot catalog manifest. `third_party/zero-breach/` is the vendored indicator set, signatures and reference exports (see its README). `agent/` is the endpoint agent (one Python file).
- `docs/` the plan and the 13 mockups.

## Licence

Apache-2.0.
