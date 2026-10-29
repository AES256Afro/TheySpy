# TheySpy

A self-hosted defender against ad-delivered spyware and ad-intelligence (ADINT) tracking, built in response to Citizen Lab's *Exposing AdFection* (October 2026). It runs on its own as one container, and BoxPilot can install and manage it.

What it will do (see [docs/PLAN.md](docs/PLAN.md)):

- Hunt your Pi-hole query log for spyware and ADINT indicators (zero-breach's set), and block what your lists miss.
- Collect every DNS blocklist, sorted into categories and kept up to date, with per-device **baselines** that show what each level would block on your real traffic.
- Keep a list of every device on your network, and check any one in depth.
- Gather CVEs and zero-days from 11 feeds and show which apply to your devices, including the one you are reading on.

**Status: M1 (indicators).** On top of M0 (sign-in, jobs, audit log, Appearance), the Indicators screen holds zero-breach's AdFection / Candiru set: where it came from and how it was verified, updates waiting for review, and exports for DNS filters, MVT and MISP. Other screens say which milestone fills them.

## Run it

```bash
docker compose up -d
```

Open `http://<this machine>:8797`. Without `TS_ADMIN_PASSWORD`, the first start prints a generated owner password once:

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

The UI runs on 5173 and hands `/api` to the server on 8797. `npm run check` builds, type-checks, tests, lints, checks every look's contrast (and that no colour is hard-coded outside `shared/looks.json`), and validates the BoxPilot manifest against BoxPilot's schema when a checkout is at `../BoxPilot` or `BOXPILOT_DIR`.

## Layout

- `server/` Node 24 + Express 5 + `node:sqlite`: config, migrations, auth, jobs, audit, appearance.
- `src/` React 19 UI. `shared/` holds the look tokens and screen list both sides read.
- `boxpilot/` the BoxPilot catalog manifest. `third_party/zero-breach/` is the vendored indicator set, signatures and reference exports (see its README). `agent/` fills in at M7.
- `docs/` the plan and the 13 mockups.

## Licence

Apache-2.0.
