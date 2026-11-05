# TheySpy — audit ledger

A rolling review of the code, run in sweeps. Each sweep covers one category and records what it
found. **A category that goes three sweeps in a row without a finding leaves the loop** and is not
swept again unless something changes that area.

| Category | Sweeps | Clean sweeps in a row | State |
| --- | --- | --- | --- |
| Code (structure, hygiene, dead weight) | 1 | 0 | in the loop |
| Bugs (correctness) | 1 | 0 | in the loop |
| Security | 1 | 0 | in the loop |

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
| S3 | `secretBox` seals without associated data, so a sealed value is interchangeable between fields: the Pi-hole password opens as the ntfy token. Needs write access to the database, so it only widens an existing compromise — but binding the purpose as AAD is a few lines. | `server/secrets.mjs` | low |
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
