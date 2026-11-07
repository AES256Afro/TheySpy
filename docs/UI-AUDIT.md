# TheySpy — the interface audit (Stage 2)

Stage 1 ([AUDITS.md](AUDITS.md)) reads the code. This reads the product: what the owner sees, in
what order, and whether it makes sense. Same loop: each category is swept at least three times and
leaves once a sweep finds nothing. The mock-ups it led to are in [mockups-v2/](mockups-v2/index.html).

| Category | Sweeps | Clean in a row | State |
| --- | --- | --- | --- |
| Readability | 4 | 2 | out of the loop (four sweeps; R1–R7 fixed) |
| Usability | 4 | 1 | out of the loop (four sweeps; U1–U8 fixed) |
| Visual | 4 | 0 | out of the loop (four sweeps; V1–V5 settled) |
| Quality of life | 3 | 1 | out of the loop (three sweeps; Q1–Q3 fixed) |
| Features the platform should have | 4 | 0 | out of the loop (four sweeps; 1–7 shipped) |
| Optimisation | 3 | 2 | out of the loop (three sweeps; O1 fixed) |

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

**Decision (7 Nov):** the layout is the owner's choice, not a recommendation. M15 ships A, C and E
as selectable home layouts, B as the device page under all of them, and D's failing / unknown /
passing shape as the empty state wherever a screen has checks. Copy across the product is cut to
technical, one-line descriptions: no quotations, no slogans. See [PLAN.md](PLAN.md) M15.

### Not findings

- The Indicators and Blocklist library screens are the finished ones: a verdict (“signed by”,
  “matches signed v0.1.8”), the numbers that matter, and the actions in order. The rest should look
  like them.
- Sign-in is fine: one field, the right hint, nothing else.
- Compact density works as described; it is just not the fix for V4.

### What shipped (sweep 1) — 1.11.0, M15

| # | Fix |
| --- | --- |
| R1 | Overview is a screen: `GET /api/overview` and three layouts the owner picks (verdict, ledger, console). The placeholder and the BoxPilot screen are gone. |
| R2 | No milestone words anywhere the owner looks; `milestone` and `mockup` left the shipped screen list. |
| R3, R6 | Every screen's title line is one technical sentence or less; a source test refuses quotations and em-dashes there. |
| R4 | The verdict layout states what is wrong in words; a zero reads as "none", not as an alarm colour. |
| R5 | Unchanged (Intel's pagination) — next sweep. |
| U1 | Partly: the verdict's "could not check" list names what to do; a first-run sequence is still not a screen. |
| U2 | Fixed in M14 (B21). |
| U3, U6 | The sidebar can be five places and More; the default look is one look ("Per screen" stays as an option). |
| U4 | A device page with evidence, exposure, CVEs, DNS activity, ports and history; Fleet, Exposure and the Overview link to it. Indicator lookups show under Evidence for every address the device has held. |
| U5, U7, U8, V1–V5 | Not yet — the next sweep reads the new screens with the old ones. |

## Sweep 2 — 7 Nov 2026, at 1.27.0

Read in a real browser on the seeded database, at 1280 and at 375 pixels, after M15's three
layouts and the device page; the first sweep's open items checked against the new screens; and the
first pass of quality of life and optimisation, measured.

### Readability

| # | Finding | Where |
| --- | --- | --- |
| R5 | Still open from sweep 1: "Previous · page 1 of 1 · Next" over a result that fits on one page. | Intel |
| R7 | The ledger shows "Blocklist updated:" and nothing after the colon: the audit entry behind it is the update run's summary (lists, updated, held, failed) and has no list name. | `overview.mjs` |

### Usability

| # | Finding | Where |
| --- | --- | --- |
| U5 | Still open: on a phone Fleet's four counters stack one per row, each a card 150 pixels tall, so the device list starts a full screen down; in the ledger the time column wraps "11:22 AM" onto two lines. | `styles.css` |
| U8 | Still open: nothing says what trusting changes. | Fleet |
| U7 | Open; a long action still shows a button label and one log line. Next sweep, with a shared job hook for the five screens that wait on jobs. | Fleet, Blocklists, Pi-hole, Indicators, Baselines |
| U1 | The first-run path is still not a screen; the verdict's "could not check" list carries it for now. Next sweep. | Overview |

### Visual

| # | Finding | Where |
| --- | --- | --- |
| V3 | Still open on Evidence: "No indicator found on any device" on an install with no agent, no MVT import and no network log reads as good news, against the product's own rule. | Evidence |
| V1, V2, V4, V5 | Open; each needs a pass over `styles.css` with the looks' tokens, which is the next sweep's visual work. | `styles.css` |

### Quality of life (first pass)

| # | Finding | Where |
| --- | --- | --- |
| Q1 | Escape does nothing anywhere: a device card on Fleet closes only by its button. | Fleet |
| Q2 | Open: the five screens that wait on a job each poll it their own way and lose it on navigation (U7's root). | `api.ts` |
| Q3 | Open: the Fleet filter and search reset on every visit. | Fleet |

### Optimisation (first pass, measured)

| # | Finding | Where |
| --- | --- | --- |
| O1 | Nothing is compressed: the bundle is 415 KB on the wire (112 KB gzipped) and the Indicators and candidate lists are 97 and 102 KB of JSON each, on every visit; `/api/cves` is 91 KB a page. Express sends them as they are. | `app.mjs` |
| — | Every screen's API answer is under 30 ms on the seeded database (`/api/cves` 27 ms, the rest under 5); the bundle is cached for an hour. Not findings. | |

### Features (second pass)

Shipped since sweep 1: 1 (the verdict home), 2 (the device page), 4 (one look, five places and
More). Open, in the order to build: 3 (the first-run checklist as the permanent structure), 7
("could not check" as a first-class list — the verdict's list is a start, not the place), 5
(global search), 6 (alert links that land on the item). Nothing further to remove.

### What shipped (sweep 2) — 1.28.0, M32

| # | Fix |
| --- | --- |
| R5 | The pager appears only past one page. |
| R7 | "Blocklists checked: 7 lists, 2 updated, 1 held for review", amber when something was held or failed; a test. |
| U5 | On a phone the counters sit two by two at a smaller size, and a ledger time stays on one line. |
| U8 | The Not trusted counter and the Trust button say what trusting changes (the new badge and merge suggestions; never blocking or alerts). |
| V3 | An Evidence locker that has checked nothing says so: "Nothing checked yet: no agent report, MVT import or network log. That is a gap, not a clean result." |
| Q1 | Escape closes the device card. |
| O1 | Answers are gzipped when the browser asks (the backup excepted, it is already a file); a test. |

## Sweep 3 — 7 Nov 2026, at 1.28.0

The open items from sweeps 1 and 2, each built or read again.

### Readability

Nothing new: every title line is one technical sentence, every number has a word next to it, and
the ledger's lines name what happened. Clean.

### Usability

| # | Finding | Where |
| --- | --- | --- |
| U7 / Q2 | Six screens wait on a job and each said the outcome its own way — a last log line in a banner, with nowhere to go when it failed. | Fleet, Blocklists, Pi-hole, Indicators, Intel, Baselines |
| U1 | The first-run path was still in nobody's head: the verdict's "could not check" list says what is missing device by device, not what to do first. | Overview |

### Visual

| # | Finding | Where |
| --- | --- | --- |
| V1 | Counter tiles, forms, tables and side notes all in the same bordered panel. | `styles.css` |
| V4 | At 1600 pixels the page stretches to the window and the right rail stays 320. | `styles.css` |
| V5 | `h2` at 15 px barely outranked the body; `h3` labels at 12 px competed with it. | `styles.css` |
| V2 | Open: a dot in Fleet, a glyph badge in Exposure and Checks, an uppercase tier badge in Indicators. The glyph badge is now the one the two check screens share; the next sweep decides whether Fleet's dot joins it. | Fleet, Indicators |

### Quality of life

| # | Finding | Where |
| --- | --- | --- |
| Q3 | The Fleet filter and search reset on every visit. | Fleet |

### Features

| # | Finding |
| --- | --- |
| 3, 7 | A Checks screen: the ten checks as one list, each failing, not yet checked or passing per device, who fails it, what closes it; and on top the steps a fresh install has left, worked out from what the checks cannot see yet (connect Pi-hole, read its network table, turn the watch on, add an agent, open This device once, press Check my connection). Day one it is the order to set up in; later it is the same list. The verdict's "could not check" links to it. |
| 5, 6 | Open: a global search from the check box; alert links that land on the item. |

### Optimisation

After O1, measured again on the seeded database: the bundle is 112 KB on the wire, the Indicators
list 14 KB, the candidates 12 KB; every answer still under 30 ms. Nothing to do. Clean.

### What shipped (sweep 3) — 1.29.0, M33

| # | Fix |
| --- | --- |
| U7, Q2 | `jobOutcome()` in `api.ts`: the last line, and "the whole log is on Activity (job 12)" when it failed; the six screens use it. A test. |
| U1, 3, 7 | The Checks screen (`/checks`, in Watch), with the set-up steps on top; the Overview links to it. A test renders a fresh install's steps and a check's failing devices. |
| V1 | Counter tiles lose their border and take the second panel tone, a step below the cards that hold work. |
| V4 | The page stops at 1480 pixels; the rail grows to 28% past 320. |
| V5 | `h2` 16 px bold, `h3` labels 11 px. |
| Q3 | The Fleet filter and search are kept for the tab (session storage). |

## Sweep 4 — 7 Nov 2026, at 1.29.0

The last items, and the last sweep each category needs.

### Readability

Clean. The Checks screen's lines read as the rest do.

### Usability

Clean: the first-run path is a screen now, every job says where its log is, and the device page
holds the device.

### Visual

| # | Finding |
| --- | --- |
| V2 | Settled by distinction, not by one encoding: a dot is presence (online), a glyph badge is a check's state (✓ ! ✕ ?), an uppercase badge is a category (an indicator's tier, a CVE's severity). Each means one thing everywhere it appears, which is what the finding asked for. |

### Quality of life

Clean. One thing noted and left: the Checks screen's set-up steps open the screen, not the control
on it; the screens are short enough that the control is in view.

### Features

| # | Shipped |
| --- | --- |
| 5 | "/" from anywhere opens the check box, which takes the focus; a key pressed while typing in any field is left alone. |
| 6 | An alert lands on the item: a new device's alert and a one-device lookup alert link to that device's page; a lookup alert for several devices, and the rest, link to their screen. |

### Optimisation

Measured after O1: a cold start on the seeded database (migrations, every store, the first
Overview) is under half a second; the bundle 112 KB on the wire; every answer under 30 ms. Clean.

### What shipped (sweep 4) — 1.30.0, M34

| # | Fix |
| --- | --- |
| 5 | `isTypingTarget()` in the router, the "/" handler in the app shell, `autoFocus` on the check box; a test. |
| 6 | `deviceLink()` in `alerts.mjs`; a test with a new device and a one-device lookup. |

## The second stage is closed

Every category has had at least three sweeps (readability, usability, visual and features four;
quality of life and optimisation three). With the first stage closed in [AUDITS.md](AUDITS.md)
after sweep 25, the audit loop that began at 1.9.0 ends at 1.30.0: 21 milestones, 42 bugs, 40 code
findings, 7 readability, 8 usability, 5 visual, 3 quality-of-life and 1 optimisation findings, and
7 features, each with a test that fails without its fix.

### What you may be missing

Said plainly, in the order I would take them; none is a finding against what exists.

1. **Retention** (built: M35, 1.31.0). `ioc_hit_events`, `audit_log`, `jobs` and `checks` grow for ever. At a household's
   rate that is years, but nothing trims them and nothing says how big the database is. A retention
   setting (keep hits a year, audit and jobs ninety days) and a size line on Activity.
2. **HTTPS of its own.** TheySpy relies on a reverse proxy or Tailscale for TLS and says so on
   Activity when it is reached in the clear. A self-signed certificate on first start, or ACME when
   a public name is set, would make the plain-HTTP warning rare.
3. **IPv6** (built: M38, 1.34.0). Scan ranges, sweeps and the network table are IPv4; a dual-stack household's devices
   are seen by their IPv4 only, and a lookup from an IPv6 address is credited to no device.
4. **A second notification channel** (built: M36, 1.32.0). ntfy is the only one; e-mail or a webhook would cover the
   owner who will not run an ntfy client.
5. **Installable on a phone** (built: M36, 1.32.0). This device is the screen built for a phone; a web manifest and an
   icon would let it sit on the home screen.
6. **Pi-hole's own query log as evidence.** A hit is kept as one row; the surrounding minute of
   that client's lookups (what it asked just before and after) would turn a hit into a story
   without storing the whole log.
7. **A read-only view for the household** (built: M37, 1.33.0). One owner password opens everything; a second password
   that opens the Overview, Checks and the device pages only would let the family look without
   being able to change Pi-hole.
8. **The agent on a schedule from TheySpy's side.** The agent is scheduled by hand (cron, launchd,
   Task Scheduler); a "last report overdue" check exists, but an installer that sets the schedule
   does not.
