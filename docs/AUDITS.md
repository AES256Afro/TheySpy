# TheySpy — audit ledger

A rolling review of the code, run in sweeps. Each sweep covers one category and records what it
found. **A category that goes three sweeps in a row without a finding leaves the loop** and is not
swept again unless something changes that area.

| Category | Sweeps | Clean sweeps in a row | State |
| --- | --- | --- | --- |
| Code (structure, hygiene, dead weight) | 2 | 0 | in the loop |
| Bugs (correctness) | 2 | 0 | in the loop |
| Security | 2 | 0 | in the loop |

Sweep 1's findings are fixed in 1.8.0 (M12); sweep 2's are planned as M13. Neither sweep has come
back clean, so all three categories stay in the loop. Sweep 3 reads what neither has: `fleet/registry.mjs`
and `fleet/targeted.mjs`, `fleet/discovery.mjs`, `cves/match.mjs` and `cves/devices.mjs`,
`exposure.mjs`, `alerts.mjs`, `digest.mjs`, `thisdevice.mjs`, `blocklists/parse.mjs` and
`iocs/parse.mjs`, and the thirteen screens one at a time.

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
