# TheySpy

A self-hosted defender against ad-delivered spyware and ad-intelligence (ADINT) tracking, built in response to Citizen Lab's *Exposing AdFection* (October 2026). It runs on its own as one container, and BoxPilot can install and manage it.

What it will do (see [docs/PLAN.md](docs/PLAN.md)):

- Hunt your Pi-hole query log for spyware and ADINT indicators (zero-breach's set), and block what your lists miss.
- Collect every DNS blocklist, sorted into categories and kept up to date, with per-device **baselines** that show what each level would block on your real traffic.
- Keep a list of every device on your network, and check any one in depth.
- Gather CVEs and zero-days from 11 feeds and show which apply to your devices, including the one you are reading on.

**Status: M3 (blocklist library and baselines), after M2 (Pi-hole Sentinel).** Baselines suggest a blocking level — Essential, Balanced, Strict or Lockdown — for the whole network or each device, show which sites each level would block on that device's real DNS traffic (and which might break something), let you keep any site allowed, and apply the level in Pi-hole with one click, for one device through its own Pi-hole group; removing it puts Pi-hole back exactly as it was. Try a level in shadow first (it counts what it would have blocked, changing nothing), or build your own from any categories. The Blocklist library finds DNS blocklists in three directories, keeps the enabled ones current behind safety checks, sorts them into categories, and serves compiled lists Pi-hole can subscribe to. TheySpy connects to Pi-hole 6 (or reads its database file), hunts its DNS history and watches new queries for lookups of zero-breach's AdFection / Candiru indicators, shows which indicator domains Pi-hole already blocks, and adds the rest with your approval — and can take them out again. The Indicators screen keeps the set current from signed releases and exports it for DNS filters, MVT and MISP. Other screens say which milestone fills them.

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

The UI runs on 5173 and hands `/api` to the server on 8797. `sh scripts/e2e-pihole.sh` checks Pi-hole Sentinel against a real, offline Pi-hole 6 in Docker. `npm run check` builds, type-checks, tests, lints, checks every look's contrast (and that no colour is hard-coded outside `shared/looks.json`), and validates the BoxPilot manifest against BoxPilot's schema when a checkout is at `../BoxPilot` or `BOXPILOT_DIR`.

## Layout

- `server/` Node 24 + Express 5 + `node:sqlite`: config, migrations, auth, jobs, audit, appearance, `iocs/` (indicators), `pihole/` (Pi-hole Sentinel) and `blocklists/` (the blocklist library).
- `src/` React 19 UI. `shared/` holds the look tokens and screen list both sides read.
- `boxpilot/` the BoxPilot catalog manifest. `third_party/zero-breach/` is the vendored indicator set, signatures and reference exports (see its README). `agent/` fills in at M7.
- `docs/` the plan and the 13 mockups.

## Licence

Apache-2.0.
