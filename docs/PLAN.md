# TheySpy — Plan and Milestones

TheySpy is a self-hosted defender for one home or small-office network. It answers four questions:

1. **Has anything here talked to known spyware or ad-intelligence (ADINT) infrastructure?** (Pi-hole query log + endpoint scans against the AdFection / Candiru indicator set.)
2. **Which devices are on my network, and are they healthy?** (Fleet status, plus a targeted check of any one device.)
3. **Which CVEs and zero-days apply to my devices, including the one I am looking at the dashboard from?**
4. **How exposed am I to ad-delivered targeting, and what do I change to reduce it?**

It runs on its own (one container, one SQLite file, no other service required) and ships a BoxPilot catalog manifest so BoxPilot can install, update, back up and restore it.

---

## 1. Why now

| Source | What it says | What TheySpy does about it |
| --- | --- | --- |
| Citizen Lab, *Exposing AdFection* (15 Oct 2026) | Ad code calls a server that checks the device's advertising ID and IP. Targets get JavaScript that loads a browser exploit; everyone else gets an empty reply. Zero-click. Delivered by Discover-Tech's Controlium platform; spyware attributed to Candiru (Integrity Labs). | Block ad delivery at the gateway, hunt for IOC contact in DNS history, scan endpoints for traces, flag browsers and OSes with known exploited bugs. |
| Citizen Lab defender guidance (the screenshot) | Block ads and tracking on devices and at the gateway; opt out of ad targeting (MDM); move to browsers with less tracking and GPC; watch ad-impression traffic for malicious requests. | Each recommendation becomes a check with a pass/fail state on the Exposure page (M8). |
| Reuters, 27 Oct 2026 (Raphael Satter) | TrendAI (Trend Micro) found "Shadow-Earth-79", per sources Discover-Tech, was the No. 1 bidder on Starlink traffic in 100+ countries, likely to geolocate or surveil users. | Detect when the network's public IP belongs to Starlink (AS14593) and raise the IP-targeting risk; recommend egress that hides the satellite IP for browsing. |
| `interplains/zero-breach` | Read-only, offline endpoint scanner for AdFection/Candiru traces. 405 indicators (292 domains, 111 IPs, hashes), evidence-graded findings, defanged output, STIX 2.1 / MISP / hosts / Adblock / dnsmasq exports, SHA-256-verified IOC updater. | Reused as TheySpy's indicator source and endpoint scanner (see §3). |

---

## 2. Principles

- **Standalone first.** Every feature works with only TheySpy running. Pi-hole, BoxPilot, BaselineWatch, Protec and NetAlertX are optional connectors that add data, never requirements.
- **Evidence, not vibes.** Every finding carries an evidence tier (zero-breach's: `on-disk`, `persistence`, `contacted`, `dns-record`, `configured`, `referenced`), a source and a citation. A check that could not run is shown as a gap, never as clean.
- **Defanged by default.** Indicators render as `example[.]com` / `203.0.113[.]5` everywhere, including exports and notifications, so a forwarded report never resolves an IOC.
- **Read-only unless approved.** Pushing a denylist to Pi-hole, starting an active port scan, or changing anything on another system is an explicit action with a preview.
- **Scan only what you own.** Active scans are limited to configured private ranges (RFC 1918 / ULA) by default; anything else needs an explicit allowlist entry.
- **A clean result is not a clearance.** The UI says so, and links to Access Now's Digital Security Helpline and Amnesty's Security Lab when a finding is serious.

---

## 3. What is reused from zero-breach

zero-breach code is Apache-2.0 and its indicator data is CC0, so both can be vendored with `NOTICE` and `LICENSE` kept intact under `third_party/zero-breach/`.

| zero-breach piece | Used in TheySpy as |
| --- | --- |
| `iocs/adfection_iocs.txt` (tier, confidence, citation per entry) | Seed of the IOC store. Tier and citation are kept on every row. |
| `scan/update-iocs.py` behaviour (HTTPS fetch, SHA-256 check against published hash, diff, dry-run then apply) | Re-implemented in the IOC updater job; the diff is shown in the UI before applying. GPG verification added (zero-breach leaves it manual). |
| `build/emit_denylist.py` formats | Pi-hole push uses the reviewed domain list (291 domains), not raw tiers. Hosts / Adblock / dnsmasq downloads offered from the IOC page. |
| `build/emit_stix.py`, `emit_misp.py` | IOC and finding exports; STIX bundle is also what MVT consumes for phone checks. |
| `dist/zero-breach.py` (single file, stdlib only, network guard, exit codes 0/2/1) | The endpoint scanner inside `theyspy-agent`. The agent runs it unmodified, verifies its signature/hash first, and uploads the JSON report. |
| Evidence tiers and "gaps are not clean" rule | Adopted as TheySpy's finding model. |
| `third_party/candiru` YARA-X rules | Optional deep scan in the agent (separate venv, pinned hashes, same as upstream). |

Upstream stays the source of truth: TheySpy tracks zero-breach releases and pulls IOC updates from its published URL with hash verification.

---

## 4. Architecture

```
                        ┌──────────────────────────── TheySpy container ─────────────────────────────┐
 Browser (any device) ─▶│  Web UI (React)   ◀──▶   API server (Node 24, Express 5)   ◀──▶  SQLite      │
   └ This-Device probe  │                              │                                            │
                        │   Scheduler / job runner ────┼─▶ Feed collectors (KEV, NVD, OSV, EPSS,   │
                        │                              │     CVE List V5, vendor + zero-day feeds)  │
                        │                              ├─▶ IOC engine (zero-breach set, updater)    │
                        │                              ├─▶ Pi-hole connector (v6 REST / v5 FTL db)  │
                        │                              ├─▶ Discovery (ARP, nmap -sV, mDNS, SSDP)    │
                        │                              ├─▶ Matcher (CPE / purl / version ranges)    │
                        │                              └─▶ Notifier (ntfy, Gotify, webhook, email)  │
                        │   /api/v1 (read-only JSON)   /mcp (MCP server for BoxPilot agents)       │
                        └────────────────────────────────────────────────────────────────────────────┘
        ▲ enroll token                        ▲ REST                          ▲ optional
 theyspy-agent (Win/macOS/Linux)        Pi-hole / AdGuard Home         BaselineWatch, Protec, NetAlertX
  └ zero-breach.py + inventory          (query log, network table,
                                          denylist, gravity search)
 Phones: MVT results import (STIX from TheySpy) + manual profile
```

**Stack** (matches BoxPilot and BaselineWatch so the same habits apply): Node ≥ 24, ESM `.mjs`, Express 5, `node:sqlite`, React 19 + Vite + TypeScript, vitest. The image adds `python3` (for zero-breach), `nmap` and `arp-scan`. Network mode `host` with `NET_RAW` + `NET_ADMIN` so ARP discovery sees the LAN; the process runs as a non-root user with file capabilities on `nmap`/`arp-scan` only.

### 4.1 Components

| Component | Responsibility | Key details |
| --- | --- | --- |
| **IOC engine** | Store, version, match and export indicators. | Domain (exact + suffix), IP / CIDR, SHA-256, JA3/JA4 later. Tiered confidence. Defang on render. Sources: zero-breach (default), user-added, STIX/MISP import. |
| **Pi-hole Sentinel** | Turn Pi-hole into a sensor and an enforcement point. | v6 API: `POST /api/auth`, `GET /api/queries` (retro-hunt by domain/client/time), `GET /api/network/devices` and `/api/clients` (device source), `GET /api/search/{domain}` (is this IOC already blocked by gravity?), `POST /api/domains/deny/exact` and `/api/lists` (push denylist with preview). v5 fallback: read-only mount of `pihole-FTL.db`. Live mode polls the query log every 30 s. AdGuard Home and Technitium connectors later using the same interface. |
| **Blocklist library** | Find, fetch, categorise, version and publish every DNS blocklist. | See §6.1. Auto-discovers candidates from FilterLists, AdGuard HostlistsRegistry and Firebog; poisoning/breakage gates; serves compiled per-category lists for Pi-hole/AdGuard to subscribe to. |
| **Baselines** | Suggested blocking levels per device, group or network, with an impact preview. | See §6.2. Lockdown / Strict / Balanced / Essential; replays recent DNS to list the sites each would block; shadow mode; enforced through Pi-hole groups. |
| **Discovery & fleet** | Know every device and its state. | Sources merged by MAC: ARP sweep, Pi-hole network table, DHCP leases (optional), mDNS/SSDP/UPnP banners, `nmap -sV` (gives CPEs), agent reports, NetAlertX import. OUI vendor lookup offline. States: online, offline, new, changed (MAC/OS/ports). |
| **Targeted check** | Everything about one IP / MAC / hostname / CVE / domain on one page. | Ping + ports + service versions, CPE → CVEs, Pi-hole history for that client against IOCs, last agent scan, exposure score, timeline. |
| **Vuln intel aggregator** | One deduplicated store of CVEs and zero-days. | See §5. Every CVE row records which feeds mention it, KEV status, EPSS, "exploited in the wild" claims with source, and affected-product ranges. |
| **Matcher** | Decide which CVEs apply to which device. | Inputs: CPEs from nmap and agents, purls from agent package inventory, OS/browser versions from agents and from the This-Device probe. Range matching on CPE match criteria (NVD) and OSV ranges. Each match has a confidence (`exact version`, `range`, `product only`). |
| **This-Device check** | Answer "which CVEs apply to the device viewing this dashboard?" | Browser asks `navigator.userAgentData.getHighEntropyValues(['platformVersion','fullVersionList','architecture','model'])`; falls back to UA parsing (Safari freezes the macOS version, so the page asks to confirm or run the agent). Also tests: GPC on? Ad domains blocked (probe images on known ad/ADINT hosts, cross-site and same-site)? DNS going through Pi-hole? Public IP ASN (Starlink?). Nothing is stored unless the user clicks "Save as device". |
| **Exposure score** | One number per device and for the network, built from the Citizen Lab guidance. | Factors: gateway ad-blocking on, device ad-blocking, ad-ID opted out (agent/MDM/manual), GPC browser, browser/OS patched against KEV items, IOC contact, Starlink/IP-targetable egress, agent scan age. Each factor is a visible check with a fix. |
| **Agent** | Endpoint evidence and inventory. | Single Python file wrapping `zero-breach.py` (hash-verified) + OS/browser/app version inventory. Enrolls with a one-time token, posts JSON over HTTPS, never receives commands beyond "scan now". |
| **Notifier & digest** | Tell you when it matters. | URL scheme like BaselineWatch's `BW_NOTIFY_URL` (ntfy, Gotify, webhook, mailto). Triggers: IOC hit, new device, KEV item matching a device, zero-day for an installed product, agent finding ≥ `contacted`. Daily or weekly digest. |
| **API & MCP** | Let BoxPilot's agents and other tools read it. | `/api/v1` read-only JSON (devices, findings, CVEs, IOCs, exposure). `/mcp` read-only tools. Write actions stay in the UI behind approval. |
| **Appearance & branding** | Every mockup ships as a product screen, and every mockup's style ships as a look. | See §4.2. |

### 4.2 Appearance and branding

All thirteen mockups become real screens; none is dropped. Their visual styles become **looks** under Settings → Appearance, the same way BoxPilot offers its thirteen looks:

| Look | Comes from | Feel |
| --- | --- | --- |
| Per screen | — | Each screen keeps the look it was designed in |
| Ops | Command Center, Fleet, Targeted Check, CVEs | Dark navy, cyan |
| Daylight | This Device, Ad Exposure | Clean light |
| Sentinel | Pi-hole Sentinel | Deep green, Pi-hole lime |
| Evidence | Evidence Locker | Charcoal and amber, forensic |
| Briefing | Weekly Briefing | Editorial paper, serif |
| Glass | In BoxPilot | Frosted panels over a gradient |

- **One token set.** Every look is only CSS custom properties (background, panel, line, text, muted, accent, and the five severity colours) plus at most a font pair and a background. Components never hard-code colours, so a new look is one block of tokens. Each look is checked for WCAG AA contrast on text and severity badges in CI.
- **Branding:** product name, tagline, logo (glyph, or an uploaded SVG/PNG stored under `/data/branding` and included in backups), and an accent override with a contrast check. The name is used in the sidebar, page titles, the briefing masthead, notifications and exports.
- **Layout:** any screen can be the home screen; comfortable or compact density; the emailed/printed briefing keeps the paper look unless set to match.
- **Scope:** the owner sets defaults for everyone (`TS_LOOK`, `TS_BRAND_NAME`, `TS_BRAND_TAGLINE`, `TS_ACCENT`, settable from BoxPilot's Config). Each browser can override them locally, so a phone and a wall screen can differ.

### 4.3 Data model (SQLite)

`devices`, `device_identities` (mac, ip, hostname, source, seen_at), `observations` (port/service/cpe), `inventory_items` (purl/cpe, version, source), `iocs` (value, type, tier, confidence, citation, source, active), `ioc_hits` (ioc, device, evidence_tier, source, first/last seen, count), `cves`, `cve_sources`, `cve_affects` (cpe/purl + ranges), `exploitation` (cve, source, claim, date), `matches` (device, cve, confidence, status: open/accepted/fixed), `scans` (kind, target, started/ended, result, gaps), `agent_reports`, `exposure_checks`, `blocklist_sources` (url, directory, syntax, licence, maintainer, status: candidate/enabled/quarantined/stale/dead), `blocklist_versions` (hash, count, added, removed, fetched_at), `blocklist_entries` (domain, version), `domain_categories` (domain, category, list_count), `baselines`, `baseline_assignments` (device or group), `baseline_exceptions`, `impact_previews` (baseline, scope, window, result), `alerts`, `jobs`, `settings`, `audit_log`.

---

## 5. CVE and zero-day sources

| Feed | Gives | Cadence |
| --- | --- | --- |
| CISA KEV (JSON) | Known exploited CVEs, due dates, ransomware use | Hourly |
| NVD API 2.0 (+ optional API key) | Descriptions, CVSS, CPE match criteria | Incremental, `lastModStartDate` |
| CVE List V5 (CVEProject GitHub) | Canonical records, CNA data, fills NVD backlog gaps | Hourly delta |
| OSV.dev | Package-ecosystem ranges (npm, PyPI, Go, Debian, Ubuntu, Alpine…) | On inventory change + daily |
| GitHub Advisory Database | Reviewed advisories with ranges | Daily |
| FIRST EPSS | Exploit probability per CVE | Daily |
| Vendor: Apple security releases, Microsoft MSRC CVRF, Chrome Releases, Mozilla MFSA, Android bulletin, Samsung, Ubiquiti, Synology, QNAP | "May have been actively exploited" language, fixed versions | Hourly RSS/JSON |
| Google Project Zero "0days In-the-Wild" sheet | Curated zero-day list with root-cause links | Daily |
| Research: Citizen Lab, Amnesty Security Lab, Google TAG/GTIG, Lookout, Kaspersky GReAT, TrendAI | Spyware campaign reports → IOC sets + linked CVEs | Daily RSS, manual IOC import with review |
| Optional BaselineWatch `/api/v1` | Already-normalised CVE timeline and watchlist | If configured |

**Zero-day flag** = CVE is in KEV, or a vendor bulletin says exploited, or it is in P0 ITW, or a research report ties it to a campaign. The flag shows which source said so and when.

---

## 6. Blocklist library and baselines

### 6.1 Collect every blocklist, categorised, and keep it current

**Discovery: finding new lists automatically.** A daily job reads machine-readable directories and records anything new as a *candidate*. A candidate is never enabled automatically.

| Directory | What it provides | How it is read |
| --- | --- | --- |
| FilterLists.com API (`api.filterlists.com/lists`, `/lists/{id}`, `/tags`, `/syntaxes`, `/licenses`, `/maintainers`) | 500+ lists with syntax, tags, licence, maintainer and download URLs | Keep only DNS-usable syntaxes (hosts, domains, Adblock domain rules); map its tags to TheySpy categories |
| AdGuard HostlistsRegistry (`assets/filters.json`) | DNS lists with `purpose:*` tags, `recommended` flag, `timeAdded`, and `obsolete`/`deprecated` markers | New `filterKey` = candidate; `deprecated` = flag the enabled copy |
| Firebog (`v.firebog.net/hosts/lists.php?type=tick\|nocross\|all`) | Curated lists in ticked (safe), non-crossed and all tiers | Ticked lists get a "curated" badge |
| Followed publishers (HaGeZi, OISD, StevenBlack, 1Hosts, Block List Project, URLhaus, ThreatFox, Phishing Army…) | New variants and renames | GitHub releases / commits (optional token) |
| Research IOC repos (Citizen Lab, Amnesty Security Lab, zero-breach) | Spyware and ADINT domains | Through the IOC engine (§3) with tier and citation kept |

**Updating: the pipeline for enabled lists.**
1. Fetch with `If-None-Match` / `If-Modified-Since`, at the list's own cadence (most every 6–24 h).
2. Parse hosts, plain domains, Adblock `||domain^`, dnsmasq and RPZ into one normalised domain set. Drop IPs, comments and invalid names, and convert IDNs to punycode.
3. Snapshot each version with its hash, entry count, and added/removed diff, so you can see what changed and when.
4. **Poisoning and breakage gates.** These quarantine an update until you review it:
   - Entry count moves more than ±50%.
   - A new entry matches the *never-block* set: the Tranco top 1k sites your network actually uses, your own domains, Pi-hole and BoxPilot hosts, OS update, CA, OCSP and NTP endpoints, and anything you pinned.
   - The download fails its published checksum.
5. Health flags: *stale* (unchanged for over 180 days), *dead* (three failed fetches), *deprecated* (by its directory), *licence changed*.
6. Compile per category and per baseline (below).

**Categories.** Each source list is mapped to one or more TheySpy categories from its directory tags, and you can override them. Every domain inherits the categories of the lists that contain it. A domain's confidence is how many independent lists carry it.

| Group | Categories | Default |
| --- | --- | --- |
| Security | Spyware & ADINT · Malware & C2 · Phishing & scams · Cryptomining · Newly registered domains (≤ 30 d) · DGA / parked | On |
| Privacy | Ads · Trackers & analytics · Ad-tech bidders (RTB/SSP/DSP) · Telemetry (OS, Smart TV, IoT vendor) · Fingerprinting · DoH / VPN bypass endpoints | Depends on baseline |
| Content | Social media · Adult · Gambling · Dating · Piracy · Games | Off unless chosen |

**Publishing.** TheySpy serves the compiled lists at `http://<theyspy>:8797/lists/<category|baseline>.<hosts|txt|adblock|dnsmasq|rpz>`. Pi-hole and AdGuard Home subscribe to these URLs once, and their normal gravity updates then pull TheySpy's latest compiled version. Lists are tagged so TheySpy can remove exactly what it added.

### 6.2 Baselines: suggested blocking levels, with "what would this block for me?"

A baseline is a named bundle of categories, list choices and settings. It can apply to **one device**, a **group** (phones, IoT, kids, work), or the **whole network**. Each device gets a *suggested* baseline with the reason, for example: "IoT camera → Lockdown: it only ever talks to 6 domains", or "Pixel 9 → Strict: contacted an ADINT indicator".

| Baseline | Blocks | Expect |
| --- | --- | --- |
| **Lockdown** (most severe) | Everything in Strict, plus social media, newly registered domains ≤ 30 days, all vendor telemetry, DoH/VPN bypass. IoT devices are **allowlist-only**: they may reach only the domains learned in a 14-day window. | Things will break. Meant for at-risk people's devices and for IoT. |
| **Strict** (very strong) | Aggressive ads and trackers (HaGeZi Pro++ class), ad-tech bidders, all telemetry, malware, phishing, cryptomining, NRD ≤ 14 days, spyware/ADINT IOCs | Some sites need an allow entry. |
| **Balanced** (recommended) | Standard ads and trackers (OISD big / HaGeZi Normal class), ADINT bidders, malware, phishing, spyware IOCs | Rare breakage. |
| **Essential** (light) | Security only: malware, phishing, spyware/ADINT IOCs | Nothing visible breaks; ads still show. |

Every tier, even Essential, blocks spyware/ADINT infrastructure. That follows Citizen Lab's point that there is no consistently safe way to be exposed to targeted ads.

**Impact preview.** Before applying a baseline, TheySpy replays the device's or network's recent DNS traffic (last 7, 14 or 30 days from Pi-hole/AdGuard) against the baseline's compiled set and shows:
- **Sites that would be blocked**, grouped by site (registrable domain via the Public Suffix List). For each: query count, which devices, first and last seen, category, and the lists responsible.
- **Newly blocked vs already blocked** today, and the share of queries blocked before and after.
- **Breakage risk** per site: *high* when it is a first-party domain the device opens directly and often (e.g. `www.` or the apex of a site visited daily), or when community allowlists know it breaks things; *low* for third-party tracker calls inside other sites.
- One click to **keep allowing** a site for that device, group or baseline. The exception is stored, and every later preview counts it.

**Shadow mode.** Run a baseline in *observe* for a week. TheySpy logs what it *would* have blocked from live traffic without blocking anything, then shows the real impact before you enforce it.

**Enforcement.** Pi-hole v6 groups do the per-device work: TheySpy creates a group per baseline, assigns clients (`/api/groups`, `/api/clients`), and attaches the baseline's compiled list to that group (`/api/lists`). Changes go preview → approve → apply, with a snapshot so rollback restores Pi-hole exactly. Without Pi-hole, the same baselines export as files for any DNS server. Impact preview then uses opt-in agent data instead (DNS cache and browser-history *domains* only, counted locally).

---

## 7. Deploying with BoxPilot

TheySpy ships `boxpilot/theyspy.yaml` (schemaVersion 2) for `BoxPilot/catalog/`. Draft:

```yaml
schemaVersion: 2
id: theyspy
name: TheySpy
category: Security
icon: "🕵️"
description: "Hunts for spyware and ad-intelligence traffic in your Pi-hole log, keeps a list of every device on your network, and shows which CVEs and zero-days apply to each one."
website: https://github.com/AES256Afro/TheySpy
risk: medium            # active LAN scanning + Pi-hole write access when the owner allows it
network: host           # ARP discovery needs the LAN
capAdd: [NET_RAW, NET_ADMIN]
image:
  reference: ghcr.io/aes256afro/theyspy:0.1.0@sha256:<digest>
  version: "0.1.0"
ports:
  - { id: web, label: Dashboard, container: 8797, host: 8797, exposure: lan }
volumes:
  - { id: data, label: Database, IOC sets and scan history, container: /data, path: data }
env:
  - { name: TZ, label: Time zone, type: timezone, default: Etc/UTC }
  - { name: TS_ADMIN_PASSWORD, label: Owner password, type: password, secret: true, generate: true }
  - { name: TS_SESSION_SECRET, label: Session signing secret, type: password, secret: true, generate: true }
  - { name: TS_SCAN_RANGES, label: Networks to scan, default: "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12" }
  - { name: TS_PIHOLE_URL, label: Pi-hole address (optional), default: "" }
  - { name: TS_PIHOLE_PASSWORD, label: Pi-hole app password (optional), type: password, secret: true, default: "" }
  - { name: TS_PIHOLE_WRITE, label: Allow pushing denylists to Pi-hole, type: boolean, default: "false" }
  - { name: TS_NVD_API_KEY, label: NVD API key (optional), type: password, secret: true, default: "" }
  - { name: TS_NOTIFY_URL, label: Notification URL (optional), type: password, secret: true, default: "" }
  - { name: TS_BASELINEWATCH_URL, label: BaselineWatch address (optional), default: "" }
  - { name: TS_LOOK, label: Default look, default: auto, options: [auto, ops, light, pihole, evidence, paper, glass] }
  - { name: TS_BRAND_NAME, label: Name shown in the app, default: TheySpy }
  - { name: TS_BRAND_TAGLINE, label: Tagline (optional), default: "" }
  - { name: TS_ACCENT, label: Accent colour (optional), description: "A hex colour such as #39c6ff; empty uses the look's own.", default: "" }
signIn: { path: /login, port: web, passwordEnv: TS_ADMIN_PASSWORD }
health: { kind: healthcheck, timeoutSeconds: 180 }
```

Port 8797 is unused in the current catalog (BaselineWatch is 8790, Protec 8765). Field names such as `network` and `capAdd` must be checked against BoxPilot's schema validator (`npm run check`) before the catalog PR; if the schema has no capability field yet, that is a BoxPilot change (an ADR-001 catalog extension) to land first.

**What BoxPilot then manages:** install/uninstall, signed image updates with health-gated rollback, tested backups of `/data`, logs, metrics, firewall exposure, and the Today page. TheySpy exposes a `/api/v1/summary` that a BoxPilot agent template ("Spyware watch") reads for the morning digest; any change it suggests (e.g. "push 12 new IOC domains to Pi-hole") becomes an approval card, never an automatic action.

**Standalone** without BoxPilot: `docker compose up -d` with the same env vars, or `npm start` on any Linux box.

---

## 8. Protecting TheySpy itself

It holds a map of your network and secrets for Pi-hole, so it is a target too.

- Owner password + optional passkey; viewer role is read-only. Sessions signed with a rotatable secret.
- Pi-hole credential is an app password, stored encrypted at rest, never returned by the API.
- Agent enrollment tokens are single-use and per-device; agent reports are signed with a per-device key.
- No outbound traffic except listed feed hosts (allowlist in settings, shown on the About page). Feed downloads are hash- or signature-checked where publishers provide one.
- The This-Device probe page loads nothing third-party except the deliberate ad-block test images, and only when the user presses "Run check".
- Releases: reproducible image build, SBOM, cosign signature, pinned digests (same pattern as BoxPilot catalog).

---

## 9. Milestones

Sizes are relative (S ≈ 1 week of evenings, M ≈ 2, L ≈ 3+). Each milestone ends with `npm run check` green, a tagged image, and the BoxPilot manifest bumped.

### M0 — Foundation (S)
**Status (29 Oct 2026): done.** The image builds, runs as `node`, and passes its Docker healthcheck; `docker compose` keeps data in the named volume `theyspy-data`.
- Repo layout (`server/`, `src/`, `agent/`, `third_party/zero-breach/`, `boxpilot/`, `docs/`), CI on Linux/macOS, Dockerfile, compose file.
- SQLite schema + migrations, settings, owner auth, job runner with audit log, `/healthz`.
- App shell (sidebar, routing) with the design tokens and all seven looks from the mockups, Settings → Appearance (look, name, tagline, logo, accent, home screen, density), owner defaults from env, per-browser overrides.
- Every screen from the mockups present as a route, empty until its milestone fills it.
- **Exit:** container starts, login works, a no-op job runs and shows in the audit log; switching look restyles every screen with no hard-coded colours left (lint rule); all looks pass the contrast check; BoxPilot manifest validates against BoxPilot's schema.

### M1 — Indicator engine (S)
**Status (29 Oct 2026): done.** 405 indicators seeded from the bundled set, checked against zero-breach's signed v0.1.8 manifest. Updates come from signed releases (Ed25519 signature on `SHA256SUMS.txt`, verified in-process against the pinned key, so no `gpg` is needed) or from `main` (hash only, labelled as such). Every update is a pending version until the owner applies it. All seven exports match zero-breach's own files byte for byte.
- Vendor zero-breach IOCs with licence files; importer keeps tier, confidence, citation.
- IOC updater: fetch, SHA-256 verify, GPG verify, diff preview, apply.
- Defang renderer; exports: hosts, Adblock, dnsmasq, plain, STIX 2.1, MISP.
- **Exit:** 405 indicators imported; an update with a tampered hash is refused; exports byte-match zero-breach's own for the same input.

### M2 — Pi-hole Sentinel (M)
**Status (29 Oct 2026): done** (0.3.0). Pi-hole 6 API and pihole-FTL.db (Pi-hole 5 or 6) sources; hunts merge the in-memory log and the long-term database by query id; a 30-second live watch; coverage per indicator domain and its subdomains; pushes are Pi-hole wildcard regex entries commented `TheySpy:`, and a rollback removes only those. `scripts/e2e-pihole.sh` proves the exit criterion against a real, offline Pi-hole 6 in CI.
- v6 connector (auth, queries, network devices, search, deny list, lists) and v5 FTL-db reader.
- Retro-hunt: full query history vs IOCs → `ioc_hits` with `dns-record` evidence, per client.
- Coverage check: which IOC domains Pi-hole would already block (gravity search) and which it would not.
- Push denylist (preview → approve) tagged `TheySpy:` so removal is clean. Live watch every 30 s.
- **Exit:** against a test Pi-hole seeded with synthetic queries for test IOCs, every hit is found with correct client and time; push and roll back leave Pi-hole exactly as before.

### M3 — Blocklist library and baselines (L)
- Directory readers (FilterLists API, AdGuard HostlistsRegistry, Firebog, followed GitHub publishers) → candidates with licence, maintainer, syntax, tags.
- Fetcher with conditional GET, multi-syntax parser, version snapshots and diffs, health flags, poisoning/breakage gates with a quarantine review screen.
- Category taxonomy, tag mapping, per-domain categories and confidence; compiled outputs served at `/lists/…` in five formats.
- Baselines (Lockdown, Strict, Balanced, Essential, plus custom), suggested baseline per device, impact preview over 7/14/30 days, per-scope exceptions, shadow mode, Pi-hole group enforcement with rollback.
- **Exit:** a cold start finds ≥ 300 DNS-usable candidates; an update that suddenly adds a top-1k domain your network uses is quarantined, not published; the impact preview on a synthetic 7-day log matches a brute-force recomputation exactly; applying Strict to one device changes only that device's resolution, and rollback restores Pi-hole byte-for-byte.

### M4 — Network discovery and fleet (M)
- ARP sweep, Pi-hole network table, mDNS/SSDP listeners, `nmap -sn` / `-sV` on demand, OUI lookup.
- Device registry merged by MAC; online/offline/new/changed states; rename, tag, owner, "trusted".
- Fleet page and **targeted search** (IP / MAC / hostname / CIDR) with scan profiles: quick (ping+ARP), standard (top 100 ports + versions), deep (all ports + scripts, owner-only).
- Scope guard: only configured private ranges unless allowlisted.
- **Exit:** on a lab LAN every device appears within one sweep; a scan outside `TS_SCAN_RANGES` is refused; a new MAC triggers a "new device" alert.

### M5 — CVE and zero-day aggregator (L)
- Collectors for KEV, NVD 2.0, CVE List V5, OSV, GHSA, EPSS, vendor bulletins, P0 ITW, research RSS.
- Dedupe by CVE ID; source provenance; zero-day flag with evidence; backfill + incremental sync with rate limits.
- Feed page with filters (KEV, zero-day, EPSS ≥ x, vendor, "applies to my devices").
- **Exit:** cold start fills KEV fully and the last 120 days of NVD in under 30 min without an API key; a CVE added to KEV shows up within one hour with the correct due date.

### M6 — Matching and This-Device check (M)
- CPE/purl/version-range matcher with confidence levels; per-device CVE list; accept-risk / mark-fixed workflow.
- This-Device page: UA-CH probe, UA fallback with confirm, GPC test, ad-domain probe, DNS-through-Pi-hole test, public IP ASN (offline ASN table; Starlink AS14593 flagged).
- **Exit:** a Chrome build one version behind a KEV fix is flagged on This-Device with the KEV entry; a patched one is not; Safari shows "version not readable — confirm or run agent".

### M7 — Endpoint agent and phones (M)
- `theyspy-agent` for Windows/macOS/Linux: verifies and runs `zero-breach.py`, collects OS/browser/app inventory, uploads signed report; scheduled or on demand.
- Evidence locker: findings with tiers, gaps, defanged indicators, STIX export per finding.
- Phones: export TheySpy STIX for MVT, import MVT results; manual profile (OS version, ad-ID state, browser) for devices without an agent.
- **Exit:** a lab VM seeded with a test indicator in browser history produces a `contacted` finding on the dashboard; a failed check appears as a gap, not clean.

### M8 — Ad-exposure scoring and hardening (M)
- Exposure score per device and for the network from the factors in §4.1, each with its fix.
- Generated hardening kits: Apple configuration profile (limit ad tracking / personalised ads), Android steps (delete advertising ID), Windows (advertising ID off via policy), browser GPC/uBlock guidance, Pi-hole list recommendations (OISD, HaGeZi TIF + zero-breach denylist).
- Starlink/IP-targetable egress advice and a re-check after changes.
- **Exit:** applying the kit on a test device moves its score from red to green and each factor flips with evidence.

### M9 — Alerts, digest, API, MCP (S)
- Notifier (ntfy, Gotify, webhook, email), quiet hours, per-trigger toggles.
- Daily/weekly digest (also the printable briefing view).
- `/api/v1` + `/mcp` read-only.
- **Exit:** each trigger fires once (no duplicates on restart); an MCP client can list devices, findings and matching KEV items.

### M10 — BoxPilot packaging and management (S)
**Brought forward (29 Oct 2026):** tagged versions publish a signed image to `ghcr.io/aes256afro/theyspy`; 0.2.0 is pinned by digest in `boxpilot/theyspy.yaml` and proposed to BoxPilot in AES256Afro/BoxPilot#603. Still to do here: the backup hook and restore test, the "Spyware watch" agent template and approval cards, and the medium-risk manifest when M4 needs host networking.
- Final catalog manifest + compose template, health check, backup hook (SQLite online backup), restore test.
- BoxPilot agent template "Spyware watch" reading `/api/v1/summary`; approval cards for Pi-hole pushes.
- Catalog PR to `AES256Afro/BoxPilot`.
- **Exit:** install from the BoxPilot catalog on a fresh Ubuntu Server, back up, wipe, restore → same devices and findings; an update with a broken image rolls back by itself.

### M11 — Hardening and 1.0 (M)
- Threat model of TheySpy, outbound allowlist enforcement, secrets at rest, rate limits, CSP.
- Reproducible build, SBOM, cosign, release checklist (modelled on zero-breach's `release_check.py`).
- Docs: install, Pi-hole setup, agent rollout, "what a finding means", when to call Access Now.
- **Exit:** external review of the scanning and Pi-hole write paths; 1.0 tag.

### Later
AdGuard Home / Technitium / OPNsense (Unbound) connectors · Zeek/Suricata import for ad-impression traffic inspection · JA4 fingerprints · NetAlertX two-way sync · Protec inventory import · multi-site.

---

## 10. Risks and open questions

- **IOC staleness.** Public indicators get burned and rotated fast; zero-breach itself warns a clean scan is not a clearance. TheySpy leans on gateway ad-blocking (prevention) more than IOC matching (detection).
- **Version visibility.** Safari and many IoT devices hide exact versions; matches there are `product only` and say so.
- **Scanning breaks things.** Some IoT gear falls over under `-sV`. Default profile is gentle; deep scans are opt-in per device.
- **Pi-hole in Bridge mode** sees one client. TheySpy's per-device DNS attribution needs Pi-hole in Host mode (as BoxPilot's Pi-hole notes already explain).
- **BoxPilot schema** may lack `capAdd`; confirm before M10.
- **Open:** do you want TheySpy to absorb BaselineWatch's CVE timeline (one fewer app) or consume it as an optional source (current plan)?

---

## 11. Dashboard mockups

Thirteen screens in [`mockups/`](mockups/index.html), all with made-up data. All of them ship as product screens, and their styles ship as looks (§4.2):

1. Command Center — posture at a glance
2. Fleet — every device on the network
3. Targeted Check — one device, full dossier
4. Pi-hole Sentinel — DNS hunting and enforcement
5. Vuln Intel — CVE and zero-day aggregator
6. This Device — what applies to the screen you are holding
7. Exposure — the Citizen Lab guidance as a scorecard
8. Evidence Locker — zero-breach findings and exports
9. Weekly Briefing — printable editorial digest
10. In BoxPilot — app card, Today digest and phone view
11. Blocklist Library — every list, categorised, with candidates, quarantine and diffs
12. Baselines — four blocking levels and the sites each would block on your traffic
13. Appearance & branding — every mockup's style as a look, plus name, logo, accent, home screen and density (working: choices restyle all the mockups)
