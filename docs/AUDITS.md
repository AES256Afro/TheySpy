# TheySpy — audit ledger

A rolling review of the code, run in sweeps. Each sweep covers one category and records what it
found. **A category that goes three sweeps in a row without a finding leaves the loop** and is not
swept again unless something changes that area.

| Category | Sweeps | Clean sweeps in a row | State |
| --- | --- | --- | --- |
| Code (structure, hygiene, dead weight) | 15 | 3 | out of the loop (left after sweep 15) |
| Bugs (correctness) | 15 | 0 | in the loop |
| Security | 5 | 3 | out of the loop (left after sweep 5) |

Sweep 1's findings are fixed in 1.8.0 (M12); sweep 2's in 1.9.0 (M13); sweep 3's in 1.10.0 (M14);
sweep 4's in 1.12.0 (M16); sweep 5's in 1.13.0 (M17); sweep 6's in 1.14.0 (M18); sweep 7's and sweep 8's
in 1.15.0 (M19, which took both because sweep 8 ran before M19 shipped); sweep 9's in 1.16.0 (M20);
sweep 10's in 1.17.0 (M21); sweep 11's in 1.18.0 (M22); sweep 12's in 1.19.0 (M23);
sweep 13's in 1.20.0 (M24); sweep 14's in 1.21.0 (M25); sweep 15's in 1.22.0 (M26). Security left
the loop after sweep 5 and code after sweep 15 (clean in sweeps 13, 14 and 15). Bugs has found
something in every sweep but 10, and is the one category left.

Sweep 16 (bugs only, now) continues the fourth pass with what no sweep has read since the first:
`shared.mjs`, `params.mjs`, `fleet/addresses.mjs`, the network-log parsers in `netlogs.mjs`, the
report ingest in `agents.mjs`, `agent/theyspy-agent.py`, `src/api.ts`, `src/App.tsx`,
`src/names.ts`, `src/screens.ts`, `src/looks/looks.ts`, `shared/contrast.mjs`, and the Baselines,
Sites, Appearance and Activity screens; then every route's query and body parameters against
`params.mjs`, since B37 was one that was missed.

Stage 2 categories (readability, usability, visual, quality-of-life, platform features,
optimisation) start once Stage 1's categories have all left the loop.

---

## Sweep 1 — 5 Nov 2026, at 1.7.1

Read in full: `app.mjs`, `auth.mjs`, `index.mjs`, `config.mjs`, `db.mjs`, `jobs.mjs`, `audit.mjs`,
`secrets.mjs`, `egress.mjs`, `ratelimit.mjs`, `pacing.mjs`, `integrations.mjs`, `agents.mjs`,
`sites.mjs`, `web/scan.mjs`, `fleet/routes.mjs`, `fleet/addresses.mjs`, `fleet/discovery.mjs`
(scope guard), `blocklists/routes.mjs`. Swept across the tree: dynamic SQL, `child_process`,
`eval`, XSS sinks, prototype-chain lookups, unbounded buffers, numeric route parameters.

**Baseline:** `npm run check` is green — 225 tests pass. (Inside the sandbox 21 of them fail with
`listen EPERM`; re-run with local port binding allowed, all three files pass.) No SQL is built from
untrusted input: the handful of interpolated statements take table and status names from frozen
lists. No `eval`, no `new Function`, no `innerHTML`, no `dangerouslySetInnerHTML`, no shell
interpolation. The sweep scope guard (`/22` or smaller, inside `TS_SCAN_RANGES`, 8 targets at most),
the website check's address pinning, the agent's HMAC-and-replay check and the CSRF header rule all
hold up to reading.

### Security

| # | Finding | Where | Severity |
| --- | --- | --- | --- |
| S1 | A JSON-RPC batch bypasses the per-token budget. `perToken.hit` is charged once per HTTP request, but a POST to `/mcp` may carry an array of messages, all run through `Promise.all`. One request with 300 `check_domain` calls is 300 passes over Pi-hole's history against a 120-per-minute budget. | `server/integrations.mjs` | medium |
| S2 | Sealed credentials are not protected in a backup unless `TS_SESSION_SECRET` is set outside the database. When it is not, the generated secret is written to `settings`, so the backup holds the ciphertext and its key together. SECURITY.md states the condition; the app never says which case this install is in. | `server/auth.mjs`, `server/backup.mjs` | medium |
| S3 | `secretBox` seals without associated data, so a sealed value is interchangeable with another sealed under the same key. **Corrected while fixing it:** the first write of this said the Pi-hole password would open as the ntfy token, which was wrong — each caller already gets its own key from `deriveKey("<purpose>")`, so values do not cross between modules. The real case is inside one key: every agent's signing secret is sealed under the same key, so moving one row's blob into another row let one agent sign as another, and the same for each site's token. Needs write access to the database, so it only widens an existing compromise. | `server/secrets.mjs` | low |
| S4 | No response size cap on any outbound reader except the website check. `cves/store`, `cves/advisories`, `cves/lookup`, `fleet/oui`, `fleet/netalertx`, `pihole/client`, `pihole/connectors`, `blocklists/directories`, `protec` and `sites` all buffer whole bodies with `.text()` / `.json()`. `blocklists/library.mjs` already has the right helper (`readCapped`); it is not shared. | several | medium |
| S5 | The owner's session crosses the network in the clear by default: `TS_HOST` is `0.0.0.0` and `TS_COOKIE_SECURE` defaults to false, with no warning when the request did not come from loopback. | `server/config.mjs`, `server/app.mjs` | low |

### Bugs

| # | Finding | Where | Severity |
| --- | --- | --- | --- |
| B1 | Lookup tables are read through the prototype chain, so inherited names pass as entries. Verified: `compiledLists["constructor"]` and `kits["constructor"]` are both truthy. `/lists/<token>/constructor.txt` and `/api/exposure/kits/constructor` answer 500 where they should answer 404, and in `pacing.mjs` `hostBudgets[host]` for a single-label host sets `state.next` to `NaN`, which switches pacing off for that host for the life of the process. | `blocklists/routes.mjs`, `exposure.mjs`, `pacing.mjs` | low |
| B2 | A malformed number in a path or query becomes a 500. Verified: `GET /api/audit?limit=abc` binds `NaN` to a SQL `LIMIT` and SQLite answers "datatype mismatch"; `GET /api/v1/indicator-lookups?days=abc` throws `RangeError` out of `new Date(NaN).toISOString()`. The same shape is in `/api/jobs/:id`, `/api/fleet/devices/:id`, `/api/evidence/*/:id`, `/api/briefing/tokens/:id` and `/api/iocs/versions/:id`. | `app.mjs` and every router | low |
| B3 | `migrate()` accepts a `user_version` higher than it knows and does nothing. BoxPilot's rollback path (M10) puts an older image on a database a newer one migrated, where the old code writes against a schema it does not know, with no error. | `server/db.mjs` | medium |
| B4 | An agent report's verdict counts every gap (`gaps: gaps.length`) but only the first 40 are stored, so the verdict and the Evidence locker disagree on a noisy scan. | `server/agents.mjs` | low |
| B5 | The error handler can throw: `Number(error.status ?? error.statusCode ?? 500)` reaches `res.status(NaN)` for any thrown value carrying a non-numeric `status`. | `server/app.mjs` | low |

### Code

| # | Finding | Where |
| --- | --- | --- |
| C1 | A stale duplicate checkout sits inside the working tree at `TheySpy/` — a whole clone pinned at 0.9.0, with its own `.git` and `.env`. It is clean and has nothing unpushed, it doubles every search hit in the repository, and `git add -A` here would try to take it in. Nothing to keep. |
| C2 | Per-address state never shrinks: `failures` (auth), `blocked` (integrations) and `reported` (egress) are `Map`s with no eviction. Small, but they are the only per-address memory in the process. |
| C3 | `createRateLimit.hit` walks the entire map on every call once it holds more than 10,000 keys — the cost per request rises exactly when the process is under load. |
| C4 | `const read = …` in two of `index.mjs`'s scheduler blocks shadows the module-level `read` (the read model). |
| C5 | `hostsOf()` allocates every address in whatever range it is handed; only its callers enforce `/22`. The guard belongs in both places. |
| C6 | `createRateLimit.middleware()` closes over `this`, so it breaks when destructured off the object. |

### Not findings, recorded so a later sweep does not re-litigate them

- `cves/store.mjs` `list()` leaves `%` and `_` unescaped in a `LIKE` search term while `product`
  strips them. Inconsistent, harmless: the term is parameterised and the worst case is a broader
  match the owner asked for.
- `/mcp` echoes the client's `protocolVersion` back verbatim. Loose against the MCP spec, no effect
  on TheySpy.
- `isDomain` accepts a trailing hyphen in a label. It only ever gates a read of Pi-hole's history.
- `extraHosts` in `index.mjs` reads `sentinel` before its `const` is evaluated. It is a closure,
  called long after start, so there is no temporal dead zone in practice.

### What shipped

All of sweep 1 is fixed in **1.8.0**, each with a test that fails without its fix (checked by
stashing the fix and running the test):

| # | Fix |
| --- | --- |
| S1 | `/mcp` caps a batch at 20 messages and charges the token's budget for every call in it (`createRateLimit.hit(key, cost)`). |
| S2 | `GET /api/security` tells the owner when the key to the stored passwords is in the database a backup copies; Activity shows it, and SECURITY.md and the guide say how to fix it. |
| S3 | `secretBox` seals as `v2:` with the row it belongs to as associated data (`agent:<id>`, `site:<id>`); `v1:` values still open, so nothing has to be re-entered. |
| S4 | `readCapped` / `readCappedBytes` / `readCappedJson` in `server/shared.mjs`, used by every outbound reader. 32 MB, 50 MB for a blocklist, counted as the bytes arrive. |
| S5 | The same `/api/security` note when the session cookie crossed a network in the clear. |
| B1 | `Object.hasOwn` before reading `compiledLists`, `kits`, `hostBudgets`, `knownSoftware` and `jobKinds`. |
| B2 | `server/params.mjs` (`intParam`, `intQuery`), used by every router; decimal digits only, so `0x10` is not an id either. |
| B3 | `migrate()` refuses a `user_version` above what it knows and says to restore the backup. |
| B4 | A report writes at most 40 gap rows and the last one counts the rest, so the verdict and the Evidence locker agree. |
| B5 | The error handler believes a status only if it is an integer in 400–599. |
| C1 | The stale 0.9.0 clone at `TheySpy/` is gone. |
| C2 | The blocked-address map is swept once a minute; the rate limiter's keys are dropped a window at a time. |
| C3 | …which is also the fix for the 10,000-key sweep on every request. |
| C4 | The two shadowed `read`s in `index.mjs` are `syncProtec` and `readSites`. |
| C5 | `hostsOf()` refuses a range over 1,024 addresses itself. |
| C6 | `createRateLimit.middleware()` no longer depends on `this`. |

## Sweep 2 — 5 Nov 2026, at 1.8.0

Read in full: `pihole/sentinel.mjs`, `pihole/client.mjs` (write paths), `blocklists/library.mjs`,
`blocklists/baselines.mjs` (apply and undo), `netlogs.mjs`, `agent-routes.mjs`, `iocs/openpgp.mjs`,
`src/api.ts`, `src/App.tsx`, `src/SignIn.tsx`, `agent/theyspy-agent.py`. Swept: third-party data
reaching `href`, response buffering, partial-failure paths, what is reachable without a session.

**Baseline:** the designs sweep 1 could not see hold up well. `baselines.apply()` keeps an undo
stack and unwinds it on any failure; `openpgp.mjs` refuses every shape it does not fully understand
and verifies against a pinned key, so the issuer subpacket (which is not covered by the signature)
cannot be used to swap keys; the DNS connectors synthesise stable query ids, so the watch's
90-second poll overlap really does deduplicate; `sites.mjs` bounds every field another site sends.

### Security

| # | Finding | Where | Severity |
| --- | --- | --- | --- |
| S6 | Four routes need no session and have no budget: `/api/agent/scanner`, `/api/agent/zero-breach.py`, `/api/agent/iocs.txt` and `/agent/theyspy-agent.py`. Anyone who can reach TheySpy can read the **active** indicator set — which includes anything the owner added or imported — and so learn exactly what TheySpy hunts for, and can pull 281 KB of scanner per request unmetered. SECURITY.md tells the owner "every screen and API call needs the owner session", which is not true of these. | `server/agent-routes.mjs` | medium |
| S7 | The agent checks the scanner against a hash it fetched from the same server on the same connection, so the check is self-referential: it proves the server was consistent, not that this is zero-breach's signed scanner. M7 and the file's own comment say the agent "re-checks its hash". A TheySpy that is compromised — or impersonated, see S8 — can serve any Python and the agent runs it with `sys.executable`. The agent is one vendored file against a known release, so the hash can simply be pinned in it. | `agent/theyspy-agent.py` | medium |
| S8 | The agent takes an `http://` server address at enrolment without a word. The enrolment token, the signing secret the server hands back, and every report afterwards then cross the network in the clear — on the same LAN the product exists to distrust. | `agent/theyspy-agent.py` | medium |
| S9 | A URL from third-party data goes into `href` without a scheme check: a blocklist directory's `homepage` (FilterLists, AdGuard, Firebog — about 1,300 candidates) and a research feed's `<link>`. **Not exploitable today**: the CSP's `script-src 'self'` blocks `javascript:` navigation. Defence in depth, and a one-line check. | `src/screens/Blocklists.tsx`, `src/screens/Intel.tsx` | low |

### Bugs

| # | Finding | Where | Severity |
| --- | --- | --- | --- |
| B7 | **The never-block list protects exact names, but the lists are published as rules that block subdomains.** `compile()` drops a protected name itself, then the output is written as `||name^` (Adblock), `address=/name/0.0.0.0` (dnsmasq) and `*.name CNAME .` (RPZ) — all of which cover children. So a list containing a *parent* blocks the protected child anyway: `||apple.com^` takes out `captive.apple.com`, `time.apple.com` and `ocsp.apple.com`; `||lencr.org^` takes out Let's Encrypt's OCSP responders; `||gstatic.com^` takes out Android's captive-portal check. Every compiled list's header says those names "are left out". `matchNames()` in the same file already does the suffix walk this needs. | `server/blocklists/library.mjs`, `server/blocklists/routes.mjs` | medium |
| B8 | A half-applied push cannot be rolled back. `push()` adds the entries, re-lists to confirm, and only then writes the `pihole_pushes` row — so a throw in between (Pi-hole reporting entries it does not list, or any DB error) leaves entries in Pi-hole with no record, and the rollback the product promises has nothing to work from. `baselines.apply()` in the same codebase already does this correctly with an undo stack. | `server/pihole/sentinel.mjs` | medium |
| B9 | A session that expires while a tab is open leaves the UI stuck. `signedIn` is read once from `/api/session` on mount and no 401 afterwards ever flips it, so every screen shows "Sign in first" in its error banner and the only way back is a manual reload or knowing to press Sign out. This app is meant to be left open on a wall screen; sessions last 14 days and a restart with a rotated `TS_SESSION_SECRET` ends them all at once. | `src/App.tsx`, `src/api.ts` | medium |
| B10 | The owner's own Pi-hole is paced as if it were a public feed. `coverage()` makes 582 sequential searches (291 indicator domains, each checked for itself and a subdomain) and the default budget is a 250 ms gap and 1,000 requests an hour — so one check takes over two minutes, and a second check in the same hour fails with "TheySpy's hourly budget for 192.168.… is used up". The same default covers AdGuard, Technitium, OPNsense, NetAlertX, Protec and the other sites: all machines the owner runs. | `server/pacing.mjs`, `server/pihole/sentinel.mjs` | medium |
| B11 | The agent reports nothing when it fails early. `scan()` fetches the scanner manifest and makes its temp directory *outside* its `try`, so a failure there propagates out of `run()` and no report is posted — the device silently keeps its last verdict instead of recording a gap, which is the one thing this product's finding model forbids. | `agent/theyspy-agent.py` | medium |
| B12 | The agent's cleanup is `os.remove` per entry, so a subdirectory the scanner left raises `IsADirectoryError` inside `finally`, hiding the real error and leaving the temp directory behind. `shutil.rmtree` is the fix. | `agent/theyspy-agent.py` | low |

### Code

| # | Finding | Where |
| --- | --- | --- |
| C7 | `ioc_hit_events.source` is written as the literal `'pihole'` for all five DNS source modes, so an AdGuard, Technitium or OPNsense lookup is recorded as Pi-hole's, and a column that exists to tell them apart never varies. |
| C8 | Two places subscribe Pi-hole to a compiled list with different rules: `sentinel.subscribe()` checks the address against `/lists/<token>/[a-z]+\.(txt\|…)$`, while `baselines.apply()` calls `addAdlist` inline — and a baseline address (`baseline-strict--device-…`) would fail the stricter check. One of them is the rule. |
| C9 | The network-log import buffers everything: a 64 MB upload (which the route's own comment invites — "a day of a home network's DNS, TLS and HTTP is tens of megabytes") becomes a 64 MB body, then JS strings, then every event as an object before a single row is written. Several hundred megabytes of heap for one request, in a container BoxPilot sizes modestly. It should parse and write line by line. |
| C10 | `netlogs` only skips a duplicate finding while the old one is `status = 'open'`, so a finding the owner dismissed comes back on the next import; `agents` has no such filter and never re-raises. One of the two is wrong. |
| C11 | Malformed OpenPGP input raises `RangeError` out of `readUInt16BE`/`readUInt32BE` rather than `SignatureError`, so a corrupt signature on an indicator update is reported as an internal error instead of "that signature is not valid". Every other refusal in that file is a `SignatureError`. |
| C12 | `waitForJob` polls for six minutes with nothing able to cancel it (no unmount check), and `api()` sets no timeout, so a hung request leaves a screen "busy" for ever. |

### Not findings, recorded so a later sweep does not re-litigate them

- The quarantine gates (`size changed`, `would newly block a protected name`) are both guarded by
  `if (previous …)`, so a list's **first** version is never quarantined. `compile()` filters
  protected names at publish time regardless, so this is a gap in what the owner is *told*, not a
  hole — and B7 is the part that actually matters.
- `verifyDetached` reads the issuer from the unhashed subpacket area, which the signature does not
  cover. It only labels the signature; verification is against the pinned key, so there is nothing
  to exploit.
- `express.raw({ type: "application/json" })` on the report route leaves `req.body` unparsed for any
  other content type, which fails the signature check. Correct, if indirect.
- The 64 MB and 8 MB parsers on the evidence routes do run after `requireOwner` (the M11 fix is
  intact): the early exemption middleware only skips the 64 kb parser.

### What shipped (sweep 2)

All of sweep 2 is fixed in **1.9.0**, each with a test that fails without its fix (checked by
stashing the fix and running the test):

| # | Fix |
| --- | --- |
| S6 | `/api/agent/scanner`, `/api/agent/zero-breach.py` and `/api/agent/iocs.txt` need an enrolled agent's signature over `GET <path>` (ten-minute window, revocation honoured); all four agent routes are rate-limited. SECURITY.md now has a table of every route that answers without the owner session and what each gives away. |
| S7 | The agent checks the scanner against `SCANNER_SHA256` pinned in its own file — zero-breach's released hash — and refuses a server offering a version it does not know, naming where to get a newer agent. A test ties the pin to `verifiedScanner()` so the two cannot drift. |
| S8 | The agent refuses an `http://` server at enrolment and at run, saying what would be readable; `--insecure` allows it with a warning for a link that is private by other means. |
| S9 | `safeLink()` in `src/api.ts`; the blocklist directory's homepage and a research feed's link go through it. |
| B7 | `compile()` returns the protected names whose parent a list blocks, and the three formats that cover subdomains emit an exception for each (`@@||name^`, `server=/name/#`, `name CNAME rpz-passthru.`). The parent stays blocked. `txt` and `hosts` match exactly and say so in their header. |
| B8 | `push()` writes its `pihole_pushes` row before touching Pi-hole and narrows it to what Pi-hole lists, so a part-applied push is still rollbackable; a failure is audited as `pihole.denylist_push_failed`. |
| B9 | `whenSessionEnds()` — any 401 after sign-in puts the sign-in screen back, except on `/api/login`, where a 401 means the password was wrong. |
| B10 | `isOwnNetworkHost()` (moved to `fleet/addresses.mjs` with `isPublicAddress`) plus the connectors the owner configured: neither is paced. 1,200 Pi-hole searches now cost nothing and hit no budget. |
| B11 | The agent's manifest fetch and temp directory are inside its `try`, so an early failure comes back as a report with a gap. A report that cannot be delivered says so plainly instead of raising. |
| B12 | `shutil.rmtree`, so a directory the scanner left does not raise in `finally` and hide the real error. |
| C7 | `ioc_hit_events.source` is the DNS source the lookup was read from, not the literal `'pihole'`. |
| C8 | `blocklists/addresses.mjs` holds the one rule for a compiled list's name and address; the route and the Pi-hole subscribe check both use it. |
| C9 | `readNetworkLog()` hands each event to a callback and the import writes as it reads, so a day of logs is no longer turned into every event as an object first. **Partly done:** the 64 MB body is still buffered by `express.json`, which needs a streaming upload to fix — left for a later sweep, and recorded here rather than quietly. |
| C10 | A finding the owner dismissed is not raised again by the next import of the same logs, matching the agent's side. |
| C11 | Every refusal in `openpgp.mjs` is a `SignatureError`, including a truncated packet. |
| C12 | `waitForJob(id, stopped)` stops when the screen that asked has gone. |

## Sweep 3 — 5 Nov 2026, at 1.9.0

Read in full: `fleet/registry.mjs`, `fleet/targeted.mjs`, `fleet/discovery.mjs`, `cves/match.mjs`,
`cves/devices.mjs`, `exposure.mjs`, `alerts.mjs`, `digest.mjs`, `thisdevice.mjs`,
`blocklists/parse.mjs`, `iocs/parse.mjs`, and the thirteen screens. Swept: how a device's identity
survives a merge and a DHCP change, what every per-device query keys on, what a failed run leaves
behind, and whether sweep 2's own fixes are actually wired up.

**Baseline:** `npm run check` is green — 260 tests. Both parsers are the strongest code in the
sweep: `iocs/parse.mjs` refuses invisible characters, bare dots and 0.0.0.0, caps at 20,000
indicators and reproduces Python's `str.strip()` rather than JavaScript's; `blocklists/parse.mjs`
canonicalises to punycode and drops IPs and localhost names. `canonical()` and `parentsOf()` do what
B7 needs. `compareVersions` handles pre-release markers and `9.6p1 > 9.6` correctly. The one-time
`/this-device` token is 48 bits, single-use and expires in ten minutes.

**Every finding below was reproduced against the real modules before being written down.**

### Security

Nothing. The routes these modules add are all behind `requireOwner`; no third-party string reaches
an HTTP header in `alerts.deliver` (the only interpolated title is the site name the owner typed);
`identify()` returns product names from a fixed list, so nothing attacker-chosen reaches a lookup
table; the ntfy address is rejected if it carries credentials. Security's streak is 1.

### Bugs

| # | Finding | Where | Severity |
| --- | --- | --- | --- |
| B13 | **Exposure reports a device that reached an unblocked indicator as clean, once its address changes.** Every per-device factor keys on the device's *primary* address — `hits.filter((h) => h.clientIp === d.ip)` and `exploited.filter((e) => e.deviceIp === d.ip)` — while hits are stored per `client_ip` for ever. Reproduced: a laptop that looked up an ADINT C2 that Pi-hole did not block reads `fail` ("It reached an indicator address that Pi-hole did not block"), and after an ordinary DHCP lease change the same device, same database, same hit, reads **`pass` — "No lookups of indicator addresses in Pi-hole's history."** The hit is still there, under an address `device_addresses` records as that device's. This is the invariant the product is built on ("a gap is never shown as clean") failing in the one place the owner goes to see whether a device is safe. The Fleet screen already admits the problem in prose: "or Pi-hole sees it under another address". | `exposure.mjs`, `readmodel.mjs` | **high** |
| B14 | **Merging two records destroys the identity of the one folded in, and the device comes straight back as new.** `merge()` moves addresses and events and keeps what the owner typed, but never touches `mac`, `vendor`, `hostname` or `first_seen`. Reproduced: merging a laptop known by MAC (seen since 1 Aug, vendor Apple, hostname macbook) into its Tailscale-only record leaves a device with `mac: null`, `vendor: null`, `hostname: null` and `firstSeen` moved forward three months — and the next observation of that MAC creates a *third* device, so the duplicate the owner merged away is recreated. The Fleet screen's "Merge into…" offers every device, with nothing to say which direction is safe. | `fleet/registry.mjs`, `src/screens/Fleet.tsx` | **medium** |
| B15 | **Pi-hole's network table fabricates an address change every five minutes.** `fromPiholeNetwork` stamps every address a MAC has ever held with `Math.max(a.lastSeen, d.lastQuery)`, so all of them arrive with the device's newest query time; `observe()` then sees each in turn as "the latest" and writes an `ip_changed` event between them. Reproduced: one device with three historical addresses produces two false `ip_changed` events per sync — and the sync runs every 5 minutes, so about 576 fictional address changes a day for one device. Its address history also claims all three were "last seen" now, and its current address ends up whichever Pi-hole listed last. `a.lastSeen` is right there and correct. | `fleet/discovery.mjs` | **medium** |
| B16 | **A Standard check forgets the open ports only a Deep check looks for.** After the port scan, `clearClosed` deletes every service row older than this check — but Standard probes 67 ports and Deep 1,067. Reproduced: Deep finds 22 and 777 open; a later Standard check, which never probes 777, leaves the device showing only 22. An open port is silently dropped because a *narrower* check did not ask about it. Same shape as B13: not looking is recorded as not there. | `fleet/targeted.mjs` | **medium** |
| B17 | **A check that fails is listed as a check that ran, and opens blank.** `run()` inserts the `checks` row before anything can fail, and only the success path writes `finished_at` and `result`. Reproduced: a check of an address outside `TS_SCAN_RANGES` throws, and its row keeps `finished_at = null` for ever. "Recent checks" never renders `finishedAt`, so it sits there looking normal; opening it spreads an absent result over the row, leaving `kind` as `"ip"`, which matches none of the four result branches — so the panel renders empty, with no error and no reason. | `fleet/targeted.mjs`, `src/screens/Check.tsx` | **medium** |
| B18 | **The weekly briefing reports 501 lookups of a spyware address as "1 lookup".** `hits()` returns one row per (indicator, domain, via, client) group with a `lookups` total; the digest filters those groups by `lastSeen` and then prints `hits.length` — the number of *groups* — as the number of lookups. Reproduced: 501 lookups of one C2 since July, one of them this week, printed as "1 lookup of indicator addresses by 1 device(s)". The window is wrong in the other direction too: a group whose last hit is in the week drags its whole history into the "not fully blocked" test. The briefing is the one thing TheySpy sends the owner unasked, so its numbers are the ones that matter most. | `digest.mjs` | **medium** |
| B19 | The briefing truncates its exploited-software line at the first full stop. `digest` recovers the device list from a composed alert message with `a.message.split(".")[0]`, and device names are hostnames. Reproduced: `CVE-2026-12345 (on laptop.local, nas.lan)` is printed as `In software you run: CVE-2026-12345 (on laptop.` — mid-hostname, unbalanced bracket, second affected device dropped. The data exists structurally; it is being recovered from prose. | `digest.mjs` | low |
| B20 | **Sweep 2's C12 is not actually fixed.** M13 added `waitForJob(id, stopped)` and a test for it, but not one of the eight real call sites passes `stopped` — the only caller that does is the test. So every screen still polls `/api/jobs/:id` every 600 ms for a full six minutes after the owner has navigated away, which is exactly the symptom C12 described. **Correction to this ledger:** sweep 2's "What shipped" claims C12 as done; it shipped the capability and no wiring. Verified by a test that exercised the parameter directly instead of the behaviour through a screen. | `src/screens/*.tsx` | low |

### Code

| # | Finding | Where |
| --- | --- | --- |
| C13 | `exposure.overview()` calls `sentinel.hits()` once per device, and `hits()` is a full `GROUP BY` over every indicator hit ever recorded. The Ad exposure screen's only endpoint therefore runs that aggregate N times for N devices, plus four more per-device queries each. `exploited` is correctly hoisted out of the loop in the same function, so the pattern was understood; `hits()` was missed. |
| C14 | `learnNames` asks Tailscale's MagicDNS (100.100.100.100) to reverse every device's address every six hours whether or not Tailscale is in use, at a 1,500 ms timeout with one try and eight in parallel. On a network with no Tailscale that is pure dead time on every sync, and nothing remembers that the answer was "no" last time. |
| C15 | `audit.onRecord` fires `void alerts.raise(alert)`. `raise` is `async`, so a throw in its first statement (the alert insert) becomes a rejected promise rather than a synchronous throw — which means the `try/catch` that wraps the listener, whose comment says "a listener must not break the log", does not catch it. An insert failure there is an unhandled rejection in a process that writes from HTTP, jobs and the watch loop at once. The other half is the opposite problem: a synchronous throw inside `fromAudit` *is* caught, by an empty `catch`, so a malformed detail loses the notification with no trace at all. |
| C16 | The NetAlertX and Protec cards both `return null` while their state is null, and both load it with `.catch(() => {})`. If either endpoint errors the whole section vanishes from the Fleet screen with no message — the owner cannot tell a broken integration from one they never set up. |
| C17 | Lookup tables are still read through the prototype chain in five places sweep 1's B1 did not reach: `serviceProducts[s.product]` and `sourceWords[item.source]` (`cves/devices.mjs`), `priorities[row.priority]` and the tag map (`alerts.mjs`), `eventText[e.kind]`, `sourceLabel`, `sourceTitle` and `networkBadge` (`src/screens/Fleet.tsx`). None is reachable today — every key comes from a fixed list in the codebase — but `serviceProducts["constructor"]` returns a function whose `.length` is 1, which would pass the `matchable` test and then fail to iterate. B1 fixed this class; these are the rest of it. |
| C18 | `fleet.suggestions()` is O(n²) over devices and recomputes `given(b)` inside the inner loop, so the name-normalising work is done about n²/2 times rather than n. It runs on every `GET /api/fleet`, which the Fleet screen polls every 60 seconds. |
| C19 | `/this-device` validates `confirmedVersion` against `/^[\d.]{1,30}$/` but takes the Client Hints `fullVersionList` version unchecked, and that one is what reaches `software.lookup` and the stored profile. Both come from the same POST body; only one is checked. |
| C20 | The Ad exposure table renders a factor that is *absent* exactly like one that does not apply (both become a muted "–"), so a check the server stopped returning would read as "does not apply" rather than "not known yet". |

### Not findings, recorded so a later sweep does not re-litigate them

- `trustPiholeClients` sets `acknowledged = 1` as well as `trusted = 1`, clearing the "new" badge on
  devices the owner has not looked at, while `consolidate`'s auto-trust sets only `trusted`. The
  owner did press a button that names those devices, so this is defensible; noted because the two
  paths differ.
- `parentsOf("a.b.co.uk")` includes `co.uk`, since only the last label is dropped rather than the
  public suffix. It can only ever add an exception for a name no blocklist carries.
- An RPZ `name CNAME rpz-passthru.` line in a *source* list is skipped rather than honoured as an
  exception. Correct for a blocklist (it is not a block rule), but it means TheySpy ignores
  exceptions upstream lists ship.
- `iocs/parse.mjs` drops empty columns before counting them (`.filter((part) => part !== "")`), so
  `value<TAB><TAB>cc<TAB>primary` parses here as three columns. Whether zero-breach's loader does the
  same could not be checked — its source is not in this repository — so the "accepts exactly what
  zero-breach accepts" claim is unverified on this point, not known to be wrong.
- `defang()` leaves an IPv6 indicator unchanged, because the letters in its hex make it look like a
  domain and it has no dot to move. Nothing auto-links a bare IPv6 address, so there is nothing to
  defang against.
- `Activity`'s one-second poll is gated on a job actually running and is cleared on unmount.

### What shipped (sweep 3)

All of sweep 3 is fixed in **1.10.0** (M14), each with a test that fails without its fix (checked by
running the test before the fix, or with the wiring removed):

| # | Fix |
| --- | --- |
| B13 | `fleet.deviceByAddress()` and `fleet.addressesOf(id)` over every address a device has held; the exposure factors, the exploited-CVE match (now by device id), the This device probe and the per-device activity read all use them. A device whose lease changed after an unblocked indicator lookup still reads `fail`. |
| B14 | `merge()` keeps the survivor's MAC, vendor and hostname where it has them and takes the other's where it does not; `first_seen` is the earlier of the two. The same MAC seen again is the merged device, not a new one. |
| B15 | `fromPiholeNetwork` stamps each address with its own `lastSeen`, falling back to the device's `lastQuery` only for an address with none. One MAC with three historical addresses writes no `ip_changed` event. |
| B16 | `clearClosed` deletes only rows for ports this profile probed (`port IN json_each(?)`), so a Standard check keeps what Deep found, with the date it was last confirmed. |
| B17 | A throw after the `checks` row exists writes `finished_at` and a `{ kind: "failed", error }` result; `recent()` says `failed` and `error`; the Check screen marks it "did not run" and opens to the reason. |
| B18 | `sentinel.hitsSince(iso)` counts the window's own lookups per client; the briefing sums those, and "not blocked" is decided on this week's lookups alone. |
| B19 | `alerts.detail` (one migration) carries a kev_match's `{ cveId, devices }` list; the briefing renders it. No `split(".")`. |
| B20 | `useStopped()` in `src/api.ts`; all eight `waitForJob` call sites pass it. Tested through the Check screen: a job that never finishes stops being polled once the screen is unmounted. |
| C13 | `overview()` reads `sentinel.hits()` once and hands it to each device's factors. |
| C14 | A sync in which MagicDNS answered for no address sets `fleet_magicdns_silent_at`; it is not asked again for a day. An answer clears it. |
| C15 | The audit listener logs an alert it cannot build and handles a `raise()` that rejects, instead of swallowing the first and leaking the second. |
| C16 | The NetAlertX and Protec cards render a banner with the error when their settings cannot be read. |
| C17 | `Object.hasOwn` before `serviceProducts`, `sourceWords`, `priorities`, the ntfy tag map, `eventText`, `sourceLabel`, `sourceTitle` and `networkBadge`. |
| C18 | `suggestions()` normalises every device's names once, before the pair loop. |
| C19 | A Client Hints version must match `/^[\d.]{1,30}$/`, as `confirmedVersion` must; otherwise the user agent is read instead. |
| C20 | An exposure factor the server did not report renders as `?` ("This check was not reported"), not as "does not apply". |
| B21 | **Found by the Stage 2 sweep** ([docs/UI-AUDIT.md](UI-AUDIT.md), U2), fixed here: on a fresh install `GET /api/blocklists/baselines` answered 500, because `scopes()` asked Pi-hole for its clients before checking that anything was connected, and the Baselines screen showed only "Something went wrong on the server." It now answers 200 with the network scope, no devices and `pihole: false`; the screen's own "connect Pi-hole first" notice then shows. |

## Sweep 4 — 7 Nov 2026, at 1.11.0

Read in full: `web/scan.mjs`, `cves/store.mjs`, `cves/lookup.mjs`, `cves/advisories.mjs`,
`fleet/services.mjs`, `fleet/explain.mjs`, `fleet/oui.mjs`, `fleet/netalertx.mjs`, `protec.mjs`,
`backup.mjs`, `summary.mjs`, `readmodel.mjs`, `jobs.mjs`, `src/looks/looks.ts`; the registry's M14
changes; and the M15 code (`overview.mjs`, `Overview.tsx`, `Device.tsx`) as new code gets read.
Swept: what the previous two milestones' fixes assumed, whether each landed everywhere its bug
lived, and what the home screen now costs.

**Baseline:** `npm run check` green at 279 tests. The website check's authorisation is sound: a
name is resolved once, every request is pinned to those addresses (no rebinding between the check
and the probes), only same-origin redirects are followed, bodies are capped, and a public site must
publish an HMAC token the owner cannot guess. `cves/store.mjs` resumes an interrupted NVD load from
the page it reached, retries slow pages, and sets a refused API key aside. `jobs.mjs` marks jobs
stranded by a restart as interrupted instead of running for ever. `backup.mjs` checks its copy
before handing it over.

**Every finding below was reproduced against the real modules, except where it says "by construction".**

### Security

Nothing. The two owner-configured endpoints (NetAlertX, Protec) keep only an origin, refuse
credentials in the URL, and send their token only to that origin; the website check cannot be
pointed at a third party. Security's streak is 2.

### Bugs

| # | Finding | Where | Severity |
| --- | --- | --- | --- |
| B22 | **A device is blamed for a lookup made by whoever held its address before it.** M14's B13 keys evidence on every address a device has ever held, without *when* it held it. On a home network DHCP reuses addresses across devices over months. Reproduced: an old tablet at 192.168.1.30 looks up an unblocked indicator in January and is not seen again; a new laptop takes .30 in November and Ad exposure shows the laptop as `fail` — "It reached an indicator address that Pi-hole did not block" — for the tablet's lookup. The Overview's `deviceByAddress()` has the same shape ("the latest holder wins"), so it would credit the laptop with any hit at .30 in the window, including one made before it joined. The data to do this right is already stored: `device_addresses` has `first_seen` and `last_seen` per device per address, and every hit has `at`. Attribution must be by *who held the address at the time*. B13 fixed the false clean; this is the false alarm it opened. | `exposure.mjs`, `overview.mjs`, `fleet/routes.mjs` (`/devices/:id/hits`), `fleet/registry.mjs` | **high** |
| B23 | **A website check that fails is still a check that never finished.** M14's B17 fix lives in `targeted.mjs`'s `run()`, but a website address is handed to `web.scan()`, which inserts its own `checks` row and writes `finished_at` only on success. Reproduced: a site on this network that refuses the connection throws "Could not reach …" and leaves `finished_at: null`, and `recent()` reports it as `failed: false` — the new field says the opposite of the truth. **Correction to this ledger:** sweep 3's "What shipped" claims B17 done; it is done for one of the two inserts. Same lesson as B20: the test exercised the module the fix was in, not the path the bug was reported on. | `web/scan.mjs` | medium |

### Code

| # | Finding | Where |
| --- | --- | --- |
| C21 | `readmodel.exploited()` runs one `products LIKE '%vendor:product%'` scan over the whole `cves` table per inventory item per device. Measured: **1,396 ms** for 30 devices with 5 recognised services each over 40,000 CVEs (a few months of NVD). The Overview calls it twice per load — once itself, once inside `exposure.overview()` — and polls every 60 s, so an open home screen costs about 3 s of CPU a minute on the box; `summary.mjs` and the MCP tools call it too. A `(product, cve_id)` table or an index over the JSON would make it a lookup; at the least it should run once per compose and be cached for the poll interval. |
| C22 | The device page fetches the whole exposure overview and the whole findings list to show one device, so opening one device costs what the Exposure and Evidence screens cost together (and C21 again). Both need a per-device endpoint. |
| C23 | `Overview.tsx` defines the `Q` row component inside `Verdict`'s render, so React sees a new component type on every poll and remounts the four rows each minute. Harmless today (they hold no state), and the wrong shape. |
| C24 | `jobs.drain()` is fired with `void` and `runOne` catches only the job's own throw: a failing `finish.run` or `audit.record` in the catch path rejects the drain promise with nothing listening — the shape M14 fixed in `alerts.mjs` (C15). By construction. |
| C25 | Kind guesses are substring tests in list order. Reproduced: a network `garage-switch` is a "Games console", `nest-cam` and `nest-doorbell` are "Smart speaker", a device called `console` is a "Router". Specific words must come before generic ones, and `cam` before `nest`. |
| C26 | B1/C17's remainder: `links()[machine.id]` and `packageSoftware[name]` in `protec.mjs` read a plain object by a key from Protec's JSON. Protec is the owner's own, and its ids are UUIDs; one `Object.hasOwn` each, for consistency with the rest. |
| C27 | `overview.describe()`'s default branch prints the raw audit action (`iocs.seeded`, `blocklists.updated hagezi-normal`) on the home screen. Technical is the brief; unlabelled is not. Either every action worth showing gets a line, or the default is dropped. |

### Not findings, recorded so a later sweep does not re-litigate them

- `cves/lookup.mjs` does not cache a failed NVD lookup, so a device page opened while NVD is down
  waits one paced request per recognised service. Bounded (60 s each, one at a time) and the
  honest behaviour; a negative cache would hide a real outage.
- `syncNvd` resumes from `previous.progress`, which after a completed window still names that
  window with `done = total`, so a run that fails before its first new page re-fetches one old
  page. One wasted request; correct result.
- `protec.sync()` with an address and no credential reports the network error, not "no credential":
  checked, and the message is right because the request is made and fails; it only looks like a
  credential problem in the reader's head.
- NetAlertX addresses are not checked against `TS_SCAN_RANGES` before entering the fleet, unlike
  Pi-hole's and ARP's. Not verified what NetAlertX sends for an offline device; noted for sweep 5.
- `services.checkPort` sends an HTTP `HEAD` to a silent port it cannot name. One request, no
  credentials; within what the screen says it does.
- `src/looks/looks.ts`: nothing. Tokens are written as custom properties, never interpolated into
  CSS text.

### What shipped (sweep 4) — 1.12.0, M16

All of sweep 4 is fixed in **1.12.0**, each with a test that fails without its fix:

| # | Fix |
| --- | --- |
| B22 | `fleet/attribution.mjs`: `holderAt(holders, ip, at)` — a lease stays with the device that had it until another device is seen with the address; before the first known holder, nobody. `attributeHits()` groups hit events per device the way `sentinel.hits()` groups them per address. Exposure, the Overview, `/devices/:id/hits` and the read model all credit a hit by *when* it happened. A source that knows when it first saw a device (`firstSeenAt`, from Pi-hole's network table) backdates the holding, so a fresh install's history has holders. Exit test: the January tablet's lookup stays the tablet's after the laptop takes the address; the laptop reads `pass`; the laptop's own lookup from that address is the laptop's. |
| B23 | `web.scan()` writes `finished_at` and a failed result on any throw after its insert; `recent()` reports it `failed: true`. The test drives the website path through `checker.run()`. |
| C21 | `cve_products (product, cve_id)`, filled as CVEs arrive and backfilled by the migration; `cves.exploitedFor(product)`; the Overview computes the exploited list and the hits once and hands both to `exposure.overview()`. |
| C22 | `GET /api/fleet/devices/:id/exposure` and `/findings`; the device page uses them. |
| C23 | `Q` is a component of its own. |
| C24 | `drain()` catches the runner's own failure, records `job.runner_failed` and marks the job failed; a test makes the audit write throw and checks there is no unhandled rejection. |
| C25 | Guesses are specific-first with word boundaries: `garage-switch` is a network switch, `nest-cam` a camera, `console` nothing. |
| C26 | `Object.hasOwn` in `protec.mjs`. |
| C27 | Every audit action the home screen shows has a line; the rest are not shown. |

## Sweep 5 — 7 Nov 2026, at 1.12.0

Read in full: `integrations.mjs` (the token store, `/api/v1` and `/mcp`), `sites.mjs`,
`iocs/updater.mjs`, `iocs/store.mjs`, `pihole/client.mjs`, `pihole/connectors.mjs`,
`blocklists/directories.mjs`, `blocklists/baselines.mjs`, `agents.mjs`'s MVT import and profile
paths, `netlogs.mjs`, and `src/screens/Pihole.tsx`, `Baselines.tsx`, `Blocklists.tsx`, `Check.tsx`.
Swept: every place another machine's data enters (five DNS servers, three list directories, GitHub,
other TheySpy sites, NetAlertX, Protec, MVT files, network logs), and whether M16's time-bounded
attribution reached everywhere evidence is keyed on an address.

**Baseline:** `npm run check` green at 289 tests. The MCP server charges every call in a batch,
blocks an address after thirty wrong tokens, and stores tokens as hashes. `sites.mjs` clips,
bounds and defangs every field another site sends. The indicator updater fetches from two pinned
hosts over HTTPS only, follows no redirects, verifies the release manifest's Ed25519 signature
against the bundled key and the file's hash against the manifest. `baselines.apply()` undoes a
part-applied change in Pi-hole. `pihole/client.mjs` returns every session it opens.

**Every finding below was reproduced against the real modules.**

### Security

Nothing, for the third sweep running. Every inbound token is hashed and rate-limited; every outbound
request goes to an origin the owner typed or a host pinned in code; every third-party body is
capped, parsed defensively and bounded before it is stored or shown. **Security leaves the loop.**

### Bugs

| # | Finding | Where | Severity |
| --- | --- | --- | --- |
| B25 | **The network-log import credits a lookup to whichever device holds the address *first in the list*, whatever the time.** `deviceOf()` builds a map from `fleet.list()` by current `ip`; two devices that have held the same address both sit at it, and the later one in the list (the older device) overwrites. Reproduced both ways: a January lookup from 192.168.1.30 lands on the old tablet (right, by luck), and a lookup made today by the new laptop at .30 *also* lands on the old tablet. M16's `holderAt()` is the fix and is one import away. The same map names TLS fingerprints, and the JA4 baseline is per address, so a new device inherits the previous holder's "known" fingerprints. Pi-hole Sentinel's table names each row after the address's *current* holder (`names[h.clientIp]`), the same class on the screen. | `netlogs.mjs`, `src/screens/Pihole.tsx`, `pihole/routes.mjs` | **medium** |
| B24 | A site with more than twenty (device, indicator) pairs that got past its blocking raises `sites.indicator_lookups` on every 15-minute refresh. The snapshot keeps `gotThrough.slice(0, 20)` and the next refresh's "new since last time" is computed against those twenty, so the twenty-first onward are new every time. Reproduced: 25 pairs, three refreshes, three audit entries. The ntfy alert's key deduplicates, so the owner's phone is spared; the audit log, the Overview's last-24-hours and the briefing's alert count are not. | `sites.mjs` | low |

### Code

| # | Finding | Where |
| --- | --- | --- |
| C28 | `listName()` calls `decodeURIComponent` on each path segment; a malformed percent-sequence in one Firebog URL throws `URIError` out of `readFirebog()`, and that directory's whole read is lost for the run. Reproduced. |
| C29 | `iocs/updater.get()` reads a body up to the shared 32 MB cap and only then refuses one over its own 5 MB limit; `readCappedBytes` takes `maxBytes`. |
| C30 | `importMvt` takes the module name from the uploaded file's name without a length bound; it becomes `source_ref` and `location`. Everything else in that path is bounded. |

### Not findings, recorded so a later sweep does not re-litigate them

- Technitium's API takes its token as a query parameter; that is Technitium's design, and the
  request goes only to the origin the owner typed.
- `baselines.observe()` skips a query whose synthesised id is below the mark *and* whose time is at
  or before it; for the three connectors the ids are hashes, so the first condition is noise and the
  effective rule is "same second as the last counted query". A shadow count can miss a lookup in
  that second. Negligible, and the Pi-hole path has monotonic ids.
- `syncNvd` and the updater keep their earlier non-findings.
- `cves/lookup` queues NVD requests one at a time with the pause NVD asks for; the device page
  waits on it when nothing is cached. Honest, bounded, unchanged.

### What shipped (sweep 5) — 1.13.0, M17

| # | Fix |
| --- | --- |
| B25 | `netlogs.importLogs()` credits each event to `holderAt(addressHolders, client, at)`; fingerprints are named by the holder at their last sighting; `/api/pihole/hits` carries `device` (the holder at the row's last sighting) and the Sentinel table shows it, saying "held the address at the time". The JA4 baseline itself is still per address: that is a schema change, left for a later milestone and said here. |
| B24 | A site's snapshot keeps the keys of every got-through pair (bounded at 500) beside the twenty rows it shows, and "new since last reading" is computed against the keys. |
| C28 | `listName()` keeps a segment it cannot decode as it is. |
| C29 | The updater passes its 5 MB limit to `readCappedBytes`, so an oversized body is refused as it arrives. |
| C30 | `importMvt` bounds the module name at 80 characters. |

## Sweep 6 — 7 Nov 2026, at 1.13.0

Read in full: `blocklists/library.mjs`, `pihole/match.mjs`, `pihole/sources.mjs`, `auth.mjs`,
`config.mjs`, `index.mjs`'s schedulers, `src/names.ts`, `src/api.ts`, and `Indicators.tsx`,
`Evidence.tsx`, `Intel.tsx`, `Briefing.tsx`, `Activity.tsx`, `ThisDevice.tsx` (Appearance and Sites
were read for the interface audit). With this sweep every module and screen has been read at least
once. Swept: what the library keeps and throws away, what the schedulers do with failure, and
whether anything the product promises in prose is contradicted by what it does.

**Baseline:** `npm run check` green at 295 tests. `auth.mjs` is as sweep 1 found it. The library's
gates hold: a redirect off HTTPS is refused, bodies are capped at 50 MB, and `compile()` excepts a
protected name whose parent a list blocks (B7). The database source streams Pi-hole's `queries`
table rather than loading it.

**Every finding below was reproduced against the real modules.**

### Bugs

| # | Finding | Where | Severity |
| --- | --- | --- | --- |
| B27 | **The names the network looks up most are kept off every compiled list — and on an unblocked network those are the trackers.** `rememberPopular()` takes Pi-hole's top 200 *allowed* names and `neverBlockSet()` exempts them from every compilation, so the lists meant to block `app-measurement.com` and `doubleclick.net` cannot, precisely because every device already talks to them. Reproduced: with those two among the popular names, the compiled ads/trackers list omits both. The exemption was meant to stop a *security* list from taking out a site the household uses; as written it stops the ad lists from doing their job, and it refreshes itself on every update, so what it protects can never become blocked. A busy name should be a reason to *hold an update for review*, not a silent hole in the list. | `blocklists/library.mjs` | **medium** |
| B26 | **A held update is held again on every fetch.** `fetchOne()` compares the new digest with the *active* version only, so a list whose update failed a gate (size jump, newly blocked protected name) is fetched every six hours, differs from the active version every time, and inserts another quarantined version — each with a packed copy of the whole list. Reproduced: three fetches of one unchanged held update, three quarantined rows, three "Update held" cards for the same list. Until the owner decides, the database grows by a copy of the list four times a day. | `blocklists/library.mjs` | medium |
| B28 | **A scheduled Pi-hole read, sweep, vendor update or NetAlertX pull that keeps failing is recorded and never shown.** `index.mjs`'s `quietly()` writes `fleet_last_<name>_error` to settings; nothing reads those keys (Protec's error is the only one surfaced). A Pi-hole password that stopped working fails every five minutes for weeks with the Fleet screen reading "Pi-hole read: 3 days ago" and nothing else. | `index.mjs`, `fleet/routes.mjs`, `src/screens/Fleet.tsx` | low |

### Code

| # | Finding | Where |
| --- | --- | --- |
| C31 | `matchNames()` walks every domain of every enabled list on every call, and the Fleet activity card and the device page's DNS tab call it with a dozen names each time they open. Measured: **193 ms for 3 names over 1,000,000 enabled names**; a household with HaGeZi's threat feed and Pro++ has three times that. It should remember answers between calls, until the lists change. |
| C32 | This device says "Public IP and Starlink egress: coming in a later version." The check has existed since M8, on the Ad exposure screen. |

### Not findings, recorded so a later sweep does not re-litigate them

- The CVE `first` run and the hourly KEV sync can overlap once, ninety seconds after start; both
  apply the catalogue inside a transaction, so the second is a wasted fetch, not a wrong result.
- `useStopped()` sets its flag false again on effect start, so React's StrictMode double-invoke
  does not leave it stuck at true.
- The weekly briefing's hourly check sends once per ISO week because the alert key is the week.

### What shipped (sweep 6) — 1.14.0, M18

| # | Fix |
| --- | --- |
| B27 | `compile()` excepts the built-in never-block names and the owner's pins only. `fetchOne()` holds an update that newly blocks a name this network looks up most — for a first version too — and says which; the sample lists them with the protected names. The Blocklists copy says what "never block" now means. |
| B26 | A fetch whose digest matches an already-held version is "held, unchanged" and inserts nothing; a newer held version supersedes the older. One held version per list. |
| B28 | `server/quietly.mjs`: one run at a time, the failure recorded, cleared on the next success; `GET /api/fleet` carries `errors` and the Fleet screen shows each as a banner. |
| C31 | `matchNames()` remembers up to 2,000 answers until the lists change. |
| C32 | This device points at the Ad exposure check. A source test refuses "coming in a later version" and milestone words on any screen. |

## Sweep 7 — 7 Nov 2026, at 1.14.0

The first sweep of the second pass: every module had been read once, so this one read what the
fixes since sweep 1 had changed — `pihole/sentinel.mjs`, `app.mjs`, `agents.mjs`'s enrol and
report paths, `overview.mjs`, the M16–M17 attribution code and the rewritten screens — and
**measured** instead of reading where the two sweeps that measured had found the largest things.

**Measured** on a seeded in-memory database of realistic size (60 devices each with two addresses
over time and five recognised services, 40,000 CVEs with products, 3,000 indicator hits across 20
devices, 900,000 enabled list names): `overview.compose()` 37 ms; `exposure.overview()` 28 ms;
`GET /api/fleet`'s list and merge suggestions 2 ms; `read.indicatorLookups(30)` 3 ms; the
time-bounded attribution of every hit 5 ms; the library's cold `counts()` 985 ms (precomputed
five seconds after start, by design) and a cold `matchNames()` 165 ms (then remembered, M18). The
first fetch of 900,000 names took 916 ms. Nothing of C21's order remains on the screens' paths.

**Baseline:** `npm run check` green at 298 tests. `agents.verify()` is unchanged and sound (HMAC
over the exact bytes, a ten-minute window, a constant-time compare, replays refused for reports).
The error handler, the CSRF rule and the cookie are as sweep 1 found them.

### Bugs

Nothing. The attribution code behaves as M16 and M17 say, on every path that was re-read.
Bugs' streak is 1.

### Code

| # | Finding | Where |
| --- | --- | --- |
| C33 | The live watch's timer fires `poll()` every 30 s with nothing to stop a new poll starting while the last one is still reading Pi-hole. A Pi-hole that takes a minute to answer (a hunt on a Raspberry Pi, a full long-term database) gets a second poll at 30 s, a third at 60 s, each re-reading the same overlap and each delivering the same queries to the shadow-mode observers (which deduplicate, at a cost). By construction: `setInterval(() => { void poll(); })` and no flag. |

### Not findings, recorded so a later sweep does not re-litigate them

- `app.set("trust proxy", "loopback")` means sign-in failures behind a reverse proxy on *another*
  host are counted against the proxy's address, so five wrong passwords from anyone lock everyone
  out for fifteen minutes. BoxPilot's proxy is on the same host (loopback), which is the deployment
  this is built for; a remote proxy is not supported and the setting says so.
- `backup.snapshot()` runs `VACUUM INTO` synchronously; on the 17 MB seeded database that is
  tens of milliseconds, on a year-old install perhaps a second, once per download.
- `overview.compose()` attributes the hits twice (all time for the checklist, seven days for the
  questions); at 5 ms each that is not worth a shared pass.

### What shipped (sweep 7) — 1.15.0, M19

| # | Fix |
| --- | --- |
| C33 | `poll()` runs one at a time; a tick that finds the last poll still reading does nothing. A test holds Pi-hole's answer and fires two polls. |

## Sweep 8 — 7 Nov 2026, at 1.14.0

Read in full: `egress.mjs`, `pacing.mjs`, `ratelimit.mjs`, `secrets.mjs`, `cves/feeds.mjs`,
`cves/routes.mjs`, `iocs/routes.mjs`, `blocklists/routes.mjs` (after M18), `db.mjs`'s migrations as
a set, `scripts/e2e-restore.sh`, and `agent/theyspy-agent.py`. Measured the endpoints M16 and M17
added, on the seeded database from sweep 7: `exposure.forDevice()` 7 ms, `/devices/:id/hits` 6 ms,
`/api/pihole/hits` 2 ms, `/devices/:id/findings` under a millisecond, a warm `matchNames()` 0 ms.

**Baseline:** the allowlist, the pacing, the rate limiter and the secret box are as sweeps 1 and 2
left them. The restore check does what BoxPilot does (stop, archive, wipe, unpack, start) and
checks the write-ahead log was closed. The agent script pins the scanner's hash, refuses plain
HTTP, keeps everything inside its `try`, and signs the exact bytes it sends.

### Bugs

| # | Finding | Where | Severity |
| --- | --- | --- | --- |
| B29 | `GET /api/iocs/export/constructor` answers 500. The route reads `exportFormats[format]` with the format from the URL, so `constructor` finds `Object`'s constructor, passes the "known format" test, and `renderExport` throws. Reproduced. The last of B1's class that a URL can reach; owner-only, and a 500 where a 404 belongs. | `iocs/routes.mjs` | low |

### Code

| # | Finding | Where |
| --- | --- | --- |
| C34 | `PUT /api/blocklists/baselines/exceptions` stores `site` after lower-casing it and nothing else: no length bound, no check that it is a name. `canonical()` from `blocklists/parse.mjs` is the one rule for that. |
| C36 | `ioc_hit_events` is indexed by `(indicator, client_ip)` only; the week's lookups (`hitsSince`), the attribution's window (`hitEvents`) and the briefing read it by `at`. On the seeded 3,000 rows that is 5 ms; a year of a chatty indicator is a scan and a sort per Overview poll. |

### Not findings, recorded so a later sweep does not re-litigate them

- `pacing.mjs` keeps up to `perHour` timestamps per host (5,500 for NVD). Bounded by design.
- `parseEpss` gunzips the day's file in memory (about 10 MB). Once a day.
- The agent reads `THEYSPY_CA_FILE` for a private CA. Fine: it only adds a trust root.

### What shipped (sweeps 7 and 8) — 1.15.0, M19

| # | Fix |
| --- | --- |
| C33 | `poll()` runs one at a time; a tick that finds the last poll still reading does nothing. A test holds Pi-hole's answer and fires two polls. |
| B29 | The export route reads its formats with `Object.hasOwn`; `constructor` and `__proto__` are 404. |
| C34 | A baseline exception must be a canonical domain name (`canonical()`), or the route answers 400. |
| C36 | `ioc_hit_events_at`, an index on `at`. |

## Sweep 9 — 7 Nov 2026, at 1.15.0

Read in full: `iocs/exports.mjs`, `blocklists/taxonomy.mjs`, `fleet/addresses.mjs`, `shared.mjs`,
`params.mjs`, and what M14 changed in `alerts.mjs` and `digest.mjs`. Measured the two import paths
on large inputs, on the seeded database.

**Measured:** 500,000 Zeek DNS records (a 37 MB `dns.log`, 60 clients, 100 indicator lookups)
import in **593 ms** with 60 MB of heap — the M13 streaming rewrite holds. 100,000 MVT items in 20
files took **261 seconds**: every item asks the database whether the contact exists, the only index
on `findings` is `(device_id, at)`, so each ask scans the device's rows and the import is
quadratic; and nothing is inside a transaction, so a malformed third file leaves the first two
files' findings behind.

**Baseline:** the exports write the same bytes as zero-breach's emitters (the existing test
compares every format); `parseCidr` and `hostsOf` refuse what they should; `readCappedBytes`
checks the declared length and then counts; the alert and digest fixes from M14 read as intended.

### Bugs

| # | Finding | Where | Severity |
| --- | --- | --- | --- |
| B30 | **The MVT import is quadratic and not atomic.** Reproduced: 100,000 items, 261 s; a realistic 5,000 would be a second or two, which is why nobody saw it. The per-item existence check has no index to use, duplicates within the import are asked of the database again, and there is no transaction, so a malformed file after a good one leaves a half-import. | `agents.mjs`, `db.mjs` | low |

### Code

| # | Finding | Where |
| --- | --- | --- |
| C37 | The last of B1's class in places a third party names the key: `sources[sourceKey]` (the indicator file's source column; `citation("constructor")` printed "undefined, undefined, undefined") in three places in `exports.mjs`, and `adguardKeys[filterKey]` / `filterListsTags[id]` in `taxonomy.mjs` (a directory's own keys). None reachable from a real feed; one `Object.hasOwn` each. |

### Not findings, recorded so a later sweep does not re-litigate them

- The network-log import holds 60 MB of heap for a 37 MB file: the file is a string in the request
  body already (C9's second half, still open), and the import itself streams.
- `fromName()` guesses categories from a list's name with ordered substrings, like `guessKind()`
  did; its outputs are candidates the owner reviews, not findings, so a wrong guess costs a click.

### What shipped (sweep 9) — 1.16.0, M20

| # | Fix |
| --- | --- |
| B30 | The MVT import parses every file first, writes in one transaction, deduplicates within the import in memory, and `findings_contact (device_id, source, indicator)` indexes the existence check. A test: a malformed second file records nothing; the same file twice records each pair once. |
| C37 | `Object.hasOwn` in `exports.mjs` and `taxonomy.mjs`. |

## Sweep 10 — 7 Nov 2026, at 1.16.0

The last of the second pass: `scripts/` (the three build checks and the seven e2e drivers), the
router, sidebar and sign-in, the Appearance and Sites screens, the looks test, and `third_party/`
as vendored. Measured what sweeps 7–9 had not.

**Measured:** six lists of 200,000 names update in 987 ms the first time and **0 ms** the second
(six `If-None-Match` requests, six 304s, nothing parsed); a shrunken list then a 304 leaves exactly
one held version. `discover()` upserts 400 directory entries in 4 ms. `backup.snapshot()` of the
168 MB seeded database takes **436 ms**, during which the server answers nothing (`VACUUM INTO`
is synchronous, like every node:sqlite call): a backup is an owner's click, once, so that stands,
and the number is here for when it does not.

**Baseline:** the scanner is verified against zero-breach's signed `SHA256SUMS` before it is handed
out and in the release check; the bundled indicator file against its published hash and signature
at seed time; the `dist/` and `build/` files are read by the exports and the tests only. The
release check reads every tracked file for token, key and password shapes; the manifest check ties
the manifest, compose file and looks together.

### Bugs

None.

### Code

| # | Finding | Where |
| --- | --- | --- |
| C38 | The looks check strips `//` to the end of the line before looking for colour literals, so a colour after a URL on the same line (`{ url: "https://…", color: "#ff0000" }`) is never seen. Reproduced. The check exists to catch exactly that. |

### Not findings, recorded so a later sweep does not re-litigate them

- `router.tsx` compares the path only, so a link to the current path with a different query is
  ignored; nothing in the app links with a query.
- The Appearance screen resets an emptied name to the default rather than allowing an empty brand.
- The Sites screen's "this week" is the remote's `indicator-lookups?days=7`.

### What shipped (sweep 10) — 1.17.0, M21

| # | Fix |
| --- | --- |
| C38 | The stripper leaves a `//` that follows `:` alone; a test with a colour after a URL on one line. |

## Sweep 11 — 7 Nov 2026, at 1.17.0

The third pass begins with what the second pass changed: `agents.mjs` after M20, `quietly.mjs` and
its two callers after M18, `fleet/attribution.mjs` and `netlogs.mjs` after M16, `overview.mjs` and
`exposure.mjs` after M17, and the Overview, Device and Fleet screens after M15.

**Baseline:** the MVT import reads as M20 intended (parse all, one transaction, one ask per new
pair); attribution is unchanged since M16 and its test still describes it; the two quiet runners
record and clear their errors; the Overview's day of events is the last 300 audit rows, and the
scheduled work that would fill them (fleet reads, CVE feeds) runs outside the log, so a day holds
about a dozen job rows. The five Python-only agent tests are `skipIf(!python)`, not skipped.

### Bugs

| # | Finding | Where | Severity |
| --- | --- | --- | --- |
| B31 | **The Console layout's inspector contradicts its own table.** The Overview sends the five worst not-blocked lookups for the Verdict; the Console inspector looked only there, so a sixth device whose row says "1 open" got "none not blocked" in the inspector. | `Overview.tsx` | low |

### Code

| # | Finding | Where |
| --- | --- | --- |
| C39 | Lookup groups are per indicator × domain × via × address, but the React keys on the Verdict, the Console inspector and the Device page's hits list left the domain out: two subdomains of one indicator from one address share a key (React warns and may reuse the wrong row on refresh). |

### Not findings, recorded so a later sweep does not re-litigate them

- `exposure.forDevice()` reads every hit and every exploited CVE to score one device: under 10 ms
  on the seeded database (sweep 8), and the page asks once.
- `overview.compose()` attributes the hits twice (all time for the checklist, the week for the
  questions): 37 ms in all (sweep 8).

### What shipped (sweep 11) — 1.18.0, M22

| # | Fix |
| --- | --- |
| B31 | The inspector falls back to the row's own count ("1 not blocked (see device page)"); a test renders the Console with a sixth device. |
| C39 | Keys carry the domain and the route; a test renders two subdomains of one indicator and asserts React does not complain. |

## Sweep 12 — 7 Nov 2026, at 1.18.0

The third pass continued: `blocklists/library.mjs`, `pihole/sentinel.mjs` and `pihole/routes.mjs`
after M19, `sites.mjs` and `web/scan.mjs` after M18, `readmodel.mjs` and `cves/store.mjs` after
M19, and the Pi-hole, This device and Evidence screens.

**Measured:** the Overview endpoint on the seeded database is 36 ms after M20's index (31 ms warm),
as in sweep 8; `library.counts()` cold is 979 ms and runs once after each list change, off the
request path.

### Bugs

| # | Finding | Where | Severity |
| --- | --- | --- | --- |
| B32 | **The API's `indicator-lookups?days=N` reports a group's whole history as this window's, credited to the current holder.** `readmodel.indicatorLookups()` filtered `sentinel.hits()` (all-time groups per address) by `lastSeen` and named each after the holder at `lastSeen`. Reproduced: a tablet's 500 unblocked lookups in July and the laptop's one blocked lookup this week, from the same address, come back as **the laptop, 501 lookups, 1 blocked, this week**. B18 fixed this for the briefing; the API, the MCP's `list_indicator_lookups`, `summarize()` and other sites (which read `days=7` and raise "got past blocking" alerts from it) still had it. | `readmodel.mjs` | medium |
| B33 | **The Evidence screen's import result is never shown.** `act()` sets its own "Imported." after the action, so the message the MVT and network-log imports set first ("2 new finding(s) from MVT.", or the red one for new findings and fingerprints) was overwritten at once. | `Evidence.tsx` | low |

### Code

| # | Finding | Where |
| --- | --- | --- |
| C40 | `verdictBadge[a.verdict.status]` and `verdictWord[…]` on the Evidence screen are keyed by the status string the agent reports, which `agents.mjs` stores as it came. `Object.hasOwn`. (The Pi-hole screen's `tierBadge[h.tier]` is fine: tiers are validated when an indicator file is parsed.) |

### Not findings, recorded so a later sweep does not re-litigate them

- `hitGroups`' `lastStatus` subquery does not correlate on `via`, but `via` is a function of
  (indicator, domain), so the group and the subquery see the same rows.
- `sites.mjs` keeps at most 200 lookup rows per reading, so "of N indicator lookups this week"
  stops at 200; a site with more distinct (device, name) pairs in a week has larger problems.
- `cves.list()` does not escape `%` and `_` in the free-text search; it is a search box.
- The web check pins its connections to the addresses it verified, follows same-origin redirects
  only, and records a check that could not run as failed (B23).

### What shipped (sweep 12) — 1.19.0, M23

| # | Fix |
| --- | --- |
| B32 | `indicatorLookups(days)` is built from the window's own events, attributed by `attributeHits()` like the Overview. A test: the tablet's July and the laptop's November lookups, apart, in the week and in the year. |
| B33 | `act()` keeps a message the action returns; both imports return theirs. A test imports an MVT file and reads "2 new finding(s) from MVT.". |
| C40 | `Object.hasOwn` for the verdict tables; the same test renders an agent whose status is "constructor". |

## Sweep 13 — 7 Nov 2026, at 1.19.0

The third pass continued: `integrations.mjs`, `summary.mjs`, `alerts.mjs` and `digest.mjs` after
M14 and M23, `fleet/registry.mjs` and `fleet/discovery.mjs` after M16, `thisdevice.mjs`,
`netalertx.mjs` and `protec.mjs`, and the Intel, Blocklists and Briefing screens.

**Measured:** `summarize(7)` on the seeded database is 30 ms (27 ms again); the MCP's tools call
the same read model as the API (lookups 3 ms, exploited 1 ms after C21; `check_domain` is a
Pi-hole read, budgeted per token).

### Bugs

| # | Finding | Where | Severity |
| --- | --- | --- | --- |
| B34 | **A NetAlertX pull marks every NetAlertX device as seen now.** `pull()` stamps each device with the pull's own time, whether NetAlertX saw it in its last scan or last September, so every device NetAlertX knows is "online" for the fifteen minutes after each half-hourly pull, its last-seen time is meaningless, and a device Pi-hole sees at a new address is moved back to NetAlertX's `devLastIP` on every pull (an `ip_changed` event each way, B15's class). NetAlertX says which devices were in its last scan (`devPresentLastScan`) and when it last saw each (`devLastConnection`). | `fleet/netalertx.mjs` | medium |

### Code

None.

### Not findings, recorded so a later sweep does not re-litigate them

- `fleet.observe()` credits a MAC-less sighting at an address nobody holds now to the address's last
  holder (`byAddress`). Without a MAC there is nothing better; a new record per sighting would
  multiply devices on every lease change for sources that cannot see MACs (a sweep from a bridged
  container).
- The briefing's "by N devices" counts addresses (`hitsSince` groups by client), not attributed
  devices; the sentence is about the week's lookups, and a device with two addresses is rare in a
  week.
- `alerts.fromAudit()` keys a lookup alert by clients, indicators and date: one a day per set,
  which is the stated design.
- `integrations.mjs` charges a batch per message and caps it at 20; wrong tokens are counted per
  address and blocked for the wait the limiter gives.

### What shipped (sweep 13) — 1.20.0, M24

| # | Fix |
| --- | --- |
| B34 | A present device is seen now; an absent one at NetAlertX's last-connection time (bounded by now); one that was never connected is not an observation; a record that says nothing about when (an older API) is taken at its word. `devFirstConnection` backdates the holding. A test: the printer NetAlertX last saw in September stays offline with September's time; the laptop in the last scan is online; a device that never connected is not added. |

## Sweep 14 — 7 Nov 2026, at 1.20.0

The third pass finished: `agent-routes.mjs`, `auth.mjs`, `app.mjs` and `index.mjs`, the CVE
matching (`cves/devices.mjs`, `lookup.mjs`, `advisories.mjs`, `match.mjs`), `fleet/targeted.mjs`,
`fleet/explain.mjs` and `fleet/oui.mjs`, and the Check, Exposure, Activity and Indicators screens.

**Measured:** `deviceCves.inventory()` for 30 devices with 150 services, 0.3 ms;
`checker.recent(15)` over 500 checks, 0.1 ms; `read.exploitedOnDevices()` with 150 services,
0.7 ms (C21 holds).

### Bugs

| # | Finding | Where | Severity |
| --- | --- | --- | --- |
| B35 | **The targeted check credits an address's whole indicator history to whoever holds it now.** `dnsView()` took `sentinel.hits()` for the address, and the domain result named each client after the device whose address it is today. Reproduced: a check of `192.168.1.30` names the laptop and lists the tablet's 500 July lookups under it. The Overview, the device page and the API attribute by time since M16 and M23; the check was the last place that did not. | `fleet/targeted.mjs` | medium |
| B36 | **The Check screen's "last" time is never right.** The device result reads `h.lastAt`, a field the server never sends (`lastSeen`), so every indicator lookup is shown as "last Invalid Date". | `Check.tsx` | low |

### Code

None.

### Not findings, recorded so a later sweep does not re-litigate them

- `auth`'s failure map holds one entry per address that failed to sign in within 15 minutes and
  drops an address on its next attempt; sign-in is reachable on the owner's network only.
- `software.lookup()` runs one NVD request at a time, paced as NVD asks, cached a week per
  product and version; the device page waits for the queue.
- `/api/backup` removes its temporary directory when the download ends, however it ends.

### What shipped (sweep 14) — 1.21.0, M25

| # | Fix |
| --- | --- |
| B35 | `dnsView()` attributes the address's hit events with `attributeHits()` and shows a device its own; an address with no device known shows every holder's. The domain result names a client after the holder at its last lookup. Tests: the laptop sees its one blocked lookup and the tablet its three from July; a client that asked in the tablet's lease is "tablet". |
| B36 | The screen reads `lastSeen` and says how many were not blocked. A test renders a check and finds the date, not "Invalid Date". |

## Sweep 15 — 7 Nov 2026, at 1.21.0

The fourth pass began with what the third changed (`readmodel.mjs`, `fleet/netalertx.mjs`,
`fleet/targeted.mjs`, the Overview, Evidence and Check screens and their new tests), then the
modules no sweep had read since the first pass: `jobs.mjs`, `audit.mjs`, `db.mjs`, `secrets.mjs`,
`config.mjs`, `ratelimit.mjs`, `egress.mjs`, `pacing.mjs`, `appearance.mjs`, the indicator store,
updater, parser and OpenPGP verifier, the Pi-hole client, sources and connectors, the matcher, the
port checks, the baselines, the blocklist parser and routes, and the CVE feeds and routes.

**Probed and not a finding:** a signature whose subpacket area holds a zero-length subpacket does
not loop (`parseSubpackets` consumes the length byte before the length), and the verifier refuses
it as unsigned by the pinned key.

### Bugs

| # | Finding | Where | Severity |
| --- | --- | --- | --- |
| B37 | **`/api/cves?limit=abc` answers 500.** `params.mjs` was written for exactly this ("abc became NaN, went into a statement, and the owner saw Something went wrong"), and the CVE list's `limit` and `offset` were the two query numbers it missed: `Number("abc")` reaches `cves.list()`, whose `Math.min(Math.max(NaN…))` is `NaN`, and SQLite answers "datatype mismatch". Reproduced. Only a hand-made request can send it; the screen sends numbers. | `cves/routes.mjs` | low |

### Code

None (the third clean sweep: code leaves the loop).

### Not findings, recorded so a later sweep does not re-litigate them

- `jobs.mjs` runs one job at a time and a job that never settles holds the queue; every job kind
  carries its own timeouts, and the runner is meant to be simple.
- `pacing.mjs` filters a host's sent-times list on every request (at most the hourly budget long)
  and reserves a slot before sleeping, so concurrent callers queue.
- `ratelimit.mjs` sweeps its windows once a window; `egress.mjs` reports a refused host once an
  hour.
- The OpenPGP verifier accepts only v4 EdDSA document signatures from the pinned key and refuses
  everything else by shape; the updater fetches only from the two GitHub hosts over HTTPS with no
  redirects.
- The database-file source opens Pi-hole's database read-only with `query_only` on, per call.

### What shipped (sweep 15) — 1.22.0, M26

| # | Fix |
| --- | --- |
| B37 | `intQuery` for `limit` (1–200, default 50) and `offset`; a test: `?limit=abc` and `?offset=1e3` are 400s. |
