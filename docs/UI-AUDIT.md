# TheySpy — the interface audit (Stage 2)

Stage 1 ([AUDITS.md](AUDITS.md)) reads the code. This reads the product: what the owner sees, in
what order, and whether it makes sense. Same loop: each category is swept at least three times and
leaves once a sweep finds nothing. The mock-ups it led to are in [mockups-v2/](mockups-v2/index.html).

| Category | Sweeps | Clean in a row | State |
| --- | --- | --- | --- |
| Readability | 1 | 0 | in the loop |
| Usability | 1 | 0 | in the loop |
| Visual | 1 | 0 | in the loop |
| Quality of life | 0 | – | not started |
| Features the platform should have | 1 | 0 | in the loop (first pass below) |
| Optimisation | 0 | – | not started |

## Sweep 1 — 7 Nov 2026, at 1.9.0

Method: a fresh install (empty database, generated password) opened on a 1280×820 desktop and a
375×812 phone; every one of the sixteen screens, then the thirteen original mock-ups for what each
screen was meant to be. A fresh install is the honest test — it is what every owner sees first, and
it is the state no screen was looked at in.

**The one-sentence version:** the parts are finished and the whole is not. Thirteen screens each
work, but the product has no front door, no first-run path, no single place to learn about one
device, and its default styling changes with every click. The home screen says “M4”.

### Readability

| # | Finding | Where |
| --- | --- | --- |
| R1 | **The home screen is an internal milestone label.** `/` opens Overview, which is a `PlaceholderScreen`: a 44-pixel accent-coloured “M4”, “Arrives in milestone M4”, and a pointer to `docs/PLAN.md §9`. BoxPilot is the same with “M10”. The owner does not have the plan and should never need it. Everything an overview needs already exists — `summary.mjs` composes the sections, `exposure.overview()` the scores, `readmodel` the exploited list, `fleet.recentEvents()` the changes — so this is the only screen whose data shipped before its face. | `src/App.tsx`, `src/screens/Placeholder.tsx`, `shared/screens.json` |
| R2 | Milestone vocabulary leaks elsewhere: Appearance says a logo upload “arrives with the branding store in M10”; `screens.json` ships `milestone` and `mockup` fields to the browser; Sites is marked “Later” though it shipped in 1.6.0. | `src/screens/Appearance.tsx`, `shared/screens.json` |
| R3 | Every screen opens with a two-line paragraph under its title explaining what the screen is (Fleet, Exposure with a Citizen Lab quotation, Sites, Evidence, Intel…). On a phone that paragraph plus the title is most of the first screenful, on every screen, every visit. An explanation belongs in the empty state and behind a “what is this?”, not above the content for ever. | all screens |
| R4 | **Zero is drawn as alarm.** Fleet opens on four KPI cards reading 0 / 0 / 0 / 0; Exposure's network score reads “0” with a red “2 of 3 checks known” badge; Intel shows “0 — — —”. A fresh install looks like a failing one, and a failing one looks the same as a fresh one. A number with no verdict next to it is not a reading. | Fleet, Exposure, Intel |
| R5 | Pagination for nothing: Intel shows “Previous · page 1 of 1 · Next” over an empty result. | Intel |
| R6 | Six words for “refresh”: Read Pi-hole now, Sweep now, Check for updates, Discover now, Update lists, Read now. Each is accurate; together they read as six products. | Fleet, Indicators, Blocklists, Sites |

### Usability

| # | Finding | Where |
| --- | --- | --- |
| U1 | **There is no first-run path.** A new install shows sixteen screens, every one empty, each with a hint that points at another screen (“Connect Pi-hole on the Pi-hole Sentinel screen and press Read Pi-hole now”). The order that makes the product work — connect Pi-hole, read its network table, choose a network to sweep, check coverage, add an agent — is in PLAN.md and in nobody's head. | everywhere |
| U2 | **Baselines is a server error on a fresh install.** The screen renders only “Something went wrong on the server.” `scopes()` calls `sentinel.source()`, which throws a `PiholeError` carrying no status when Pi-hole is not connected, so the route answers 500. The screen whose job is to say “connect Pi-hole first” is the one that breaks. This is a Stage 1 bug found by Stage 2; it goes to M14 as B21. | `server/blocklists/baselines.mjs:181`, `server/blocklists/routes.mjs:177` |
| U3 | Sixteen sidebar entries in three groups whose names do not predict contents: Indicators is under Protect but Pi-hole Sentinel (which uses them) under Watch; Sites under Watch; Baselines, Blocklists and Exposure all under Protect though two are about lists and one about devices. Nobody can guess where a thing is, so everybody reads all sixteen. | `shared/screens.json`, `src/Sidebar.tsx` |
| U4 | **One device lives in five places.** Fleet has its record, Exposure its checklist, Evidence its findings and agent, Intel its CVEs, Targeted check its ports and DNS activity — five device tables, five selectors, no link between them except the browser's back button. The question the owner actually asks is “what about *this* phone?” | Fleet, Exposure, Evidence, Intel, Check |
| U5 | The phone layout is the weakest, on the product that most wants to be opened on a phone (This device exists for it). The sidebar becomes a horizontal strip of all sixteen links with the group labels hidden and the brand taking the first third; Fleet then stacks four zero cards before anything else; Exposure's quotation takes the first screen. | `src/styles.css` (760px rules) |
| U6 | **The default look changes with every click.** “Per screen” is the default, so Pi-hole is green, This device and Exposure are white, Evidence is amber-on-charcoal with monospace headings, Briefing is serif on paper, BoxPilot is frosted glass. Each was designed as a mock-up in its own style; as a product it feels like six apps, with a white flash between two of them. The gallery's conceit became the product's default. | `src/looks/looks.ts` (`appearanceDefaults.look = "auto"`), `shared/screens.json` |
| U7 | A long action shows only a button label change (“Reading…”, “Sweeping…”) and then one line of job log in a banner. No progress, no link to the job on Activity, no way to leave and come back — and (AUDITS B20) the poll keeps running after leaving. | Fleet, Blocklists, Pi-hole, Indicators, Baselines |
| U8 | “Trust” is never explained. Fleet counts “Not trusted — devices you have not marked as yours” and offers Trust / Stop trusting, but nothing says what trusting changes (it stops merge suggestions and the “new” badge; it does not change blocking or alerts). | Fleet |

### Visual

| # | Finding | Where |
| --- | --- | --- |
| V1 | Everything is a card of the same weight: KPI tiles, forms, tables, side notes and banners all sit in identical 1-pixel-bordered panels with the same padding, so nothing is primary and the eye has no order to follow. The original mock-ups had the same flatness; it reads fine with made-up data and poorly with none. | `src/styles.css` `.card` |
| V2 | Three encodings for one idea. Status is a coloured dot in Fleet, a ✓ ! ✕ ? – glyph in Exposure, an uppercase tier badge in Indicators and Evidence, and a coloured KPI number on the overview tiles. Each is fine alone; together they have to be re-learned per screen. | Fleet, Exposure, Indicators, Evidence |
| V3 | Empty states disagree about what empty means. Fleet shows an amber warning banner; Evidence shows a muted “No indicator found on any device” that reads as good news on an install that has never scanned anything (it is a gap, and the product's own rule is that a gap is never shown as clean); Targeted check shows nothing at all under its box. | Fleet, Evidence, Check |
| V4 | Width is not used. At 1280 pixels Fleet's five-column table runs across 900 and is mostly whitespace; Targeted check is a search box over an empty page; the right rails are fixed at 320 whatever is in them. Compact density only shrinks padding. | `src/styles.css` |
| V5 | Type hierarchy: uppercase 11–12px muted labels (`h3`) carry most of the structure, so the labels compete with the body and the real headings (`h2`, 15px) barely outrank body text. In the Evidence look the headings are also monospace, which fights the table of monospace values beneath. | `src/styles.css` `h2`, `h3` |

### Features: what no longer fits, and what is missing

Remove or demote:

- **The BoxPilot screen.** A placeholder for approvals, agents and backups that BoxPilot itself draws from `/api/v1/summary`. The integration is the endpoint; the screen is a mock-up of someone else's product. Remove it and its sidebar entry.
- **“Per screen” as the default look.** Keep it as a choice for people who liked the gallery; default to one look.
- **`milestone` and `mockup` in the shipped screen list.** Documentation fields; move them to docs.
- **The four-way profile control on Targeted check** (Quick / Standard / Deep / DNS only) in front of the box. Most checks are “what is this address?”; the profile is a detail for after the answer.

Add — these are what would make it feel finished, in the order I would build them:

1. **A home screen with a verdict** (mock-up A). One sentence, then the four questions in order of harm, then the list of what could not be checked. Every number is already computed.
2. **A device page** (mock-up B). One place for a device: evidence, exposure, bugs, DNS activity, ports, history, as tabs. The five device tables collapse into one list.
3. **A first-run checklist that is also the permanent structure** (mock-up D). The ten checks TheySpy computes (three network, seven device) as steps with failing / unknown / passing. On day one it is onboarding; in month ten it is the same screen.
4. **One look by default,** with the sidebar cut to five places and “More”.
5. **A global search** from the Targeted check box: a device name, address, MAC, CVE or domain from anywhere, with the same keys on every screen (mock-up E's bar).
6. **Alert links that land on the item,** not the screen: an ntfy tap for the Pixel's lookup should open that lookup on that device.
7. **“Could not check” as a first-class list.** The product's rule that a gap is never shown as clean deserves one place where every current gap is listed, with what would close it.

### The five mock-ups

[mockups-v2/](mockups-v2/index.html). Each is a different answer to “what is the first thing the
owner sees, and how do they get from there to the thing they need to do?” — not five colour
schemes. All five share one look and one sidebar grammar (five places and More), and all use data
shapes the server already produces.

| | Idea | Who it is for | What it costs |
| --- | --- | --- | --- |
| **A · Verdict first** | Home is one sentence, four questions in order of harm, then what could not be checked. | The owner who looks once a day. | Cheapest: one new screen over existing endpoints. |
| **B · The device is the page** | Evidence, exposure, bugs, DNS and ports are tabs of a device; five screens fold into one. | The owner who thinks “my phone, my NAS”. | A device route and a tab shell; the five screens become tabs, so it removes more than it adds. |
| **C · The ledger** | Home is time: what happened, in order, an action on every line; counts in a rail; the briefing is a filter of it. | The owner who reads the week like a log. | A unified events feed over audit, hits, KEV adds, pushes and list updates. |
| **D · Guided** | The ten checks are the navigation; each is failing / unknown / passing; the sidebar is progress. | The first week; the household member who did not set it up. | Reorganises existing factors; strongest first-run, weakest for daily use. |
| **E · Console** | One dense table per thing tracked, an inspector that follows the selection, keys for every action. | The wall screen; the terminal owner. | A table shell and an inspector; the least change to what exists, the most to how it is used. |

**My recommendation:** build **A as the home, B as the device page, and D's failing / unknown /
passing structure as every empty state.** A gives the product a front door. B removes four device
tables and answers the question people actually ask. D is onboarding without an onboarding wizard —
the same screen on day one and day three hundred. C's ledger is the right shape for Activity and
the briefing once those exist, and E's inspector is a good second pane for B's device list on wide
screens. One look by default, five sidebar places, the rest under More.

That is a milestone, not a sweep fix. Proposed as **M15 — The face** in [PLAN.md](PLAN.md) once M14
has landed (the two must not edit the plan at once).

### Not findings

- The Indicators and Blocklist library screens are the finished ones: a verdict (“signed by”,
  “matches signed v0.1.8”), the numbers that matter, and the actions in order. The rest should look
  like them.
- Sign-in is fine: one field, the right hint, nothing else.
- Compact density works as described; it is just not the fix for V4.
