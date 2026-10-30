# Security

TheySpy watches a home or small-office network for ad-delivered spyware. It holds a map of every device, what they looked up, and a password that can change Pi-hole, so it is itself worth attacking. This page says what it protects, how, and what it does not do.

## Reporting a problem

Open a private security advisory on GitHub (Security → Report a vulnerability) at `AES256Afro/TheySpy`. Please do not open a public issue for something exploitable.

## What is worth protecting

| Asset | Where it lives |
| --- | --- |
| The owner session and password | `sessions` and a scrypt hash in `settings` |
| Pi-hole's app password, the ntfy token, agent secrets | `settings` / `agents`, sealed with AES-256-GCM under a key derived from `TS_SESSION_SECRET` |
| Who looked up what (DNS history), the device map, findings | SQLite in `/data` |
| The ability to change Pi-hole (lists, groups, clients) | Owner-only jobs, off unless allowed |
| The lists Pi-hole subscribes to | `/lists/<token>/…`, behind a long random token |

## Who might attack it, and what stops them

**Someone else on the network** (a guest, a compromised IoT device).
- Every screen and API call needs the owner session: an HttpOnly, `SameSite=Strict` cookie.
- Sign-in locks an address out after five wrong passwords.
- State-changing calls need an `X-TheySpy` header (a cross-site form cannot send one), and CORS is never enabled. Together these close CSRF.
- The only routes that answer without a session:
  - health;
  - the appearance (for the sign-in page);
  - the agent's routes;
  - the compiled lists (behind a token, checked in constant time before any work is done);
  - `/api/v1` and `/mcp` (bearer token).

  Each has a body limit, and those that check a secret have a per-address rate limit.

**A web page the owner visits.**
- No CORS, `SameSite=Strict`, and the `X-TheySpy` header rule (above).
- A strict Content-Security-Policy: `script-src 'self'`, no inline script, `frame-ancestors 'none'`.
- The UI is React with no raw-HTML sinks, so banners, page titles and headers from scanned sites render as text.

**A hostile website the owner checks, or a name pointed somewhere it should not be.**

The website check:
- only contacts sites on the owner's scan ranges, or public sites whose owner published a token (file or DNS TXT);
- refuses names that resolve to loopback, link-local (cloud metadata), private, CGNAT, documentation or reserved addresses outside the scan ranges, whatever proof is offered;
- connects only to the addresses it checked, pinned for every request, so DNS rebinding cannot move it;
- follows redirects only to the same origin;
- sends GET requests only, reads at most 256 KB per answer, and waits at most 10 s.

**A hostile indicator feed, blocklist, or MVT file.**
- Indicators and list entries are parsed into canonical domain names before they reach Pi-hole or a served list, so a newline, `@@` or regex cannot be smuggled through.
- Pi-hole pushes take only domains in the active, signature-checked indicator set.
- STIX exports escape pattern literals.
- The bundled zero-breach scanner is checked against its PGP-signed `SHA256SUMS` before agents may download it, and agents check its hash again before running it.

**A stolen read-only API token.**
- It can read the device list, indicator lookups and CVE matches, and nothing else: no jobs, no Pi-hole writes, no owner routes.
- Tokens are stored hashed and can be revoked on the Briefing screen.
- Each token gets 120 requests a minute, and wrong tokens lock an address out after 30 tries.

**A forged or replayed agent report.**
- Reports are HMAC-SHA256 signed with the agent's own secret over the timestamp and the exact body.
- A report is accepted only within ten minutes of its timestamp, and each must be newer than the last.
- Enrollment tokens work once, expire after a day, and are rate-limited.

**Mistakes that change Pi-hole.**
- Writes are off until the owner allows them, and `TS_PIHOLE_WRITE=false` forbids them outright.
- Every write is a logged job.
- Each write records exactly what it changed, so removing it puts Pi-hole back as it was.
- A baseline that fails part-way undoes its own changes.

**Someone with the backup file.**
- Credentials inside it are sealed under `TS_SESSION_SECRET`, which is not in the database when set through the environment (BoxPilot generates it).
- The DNS history and the device map are not encrypted: keep backups where you keep other private data.

## What it does not do

- **The outbound allowlist covers HTTP only.** It does not cover DNS lookups or the port checks, which are plain sockets limited to `TS_SCAN_RANGES`. A firewall rule is still the stronger control.
- **The scans are not stealthy, and are not meant for networks you do not run.** Sweeps and port checks stay inside `TS_SCAN_RANGES`.
- **It is not proof that a device is clean.** A gap (a check that could not run) is always shown as a gap. Advanced spyware can leave no trace that any tool finds.

## Outbound destinations

Since 1.1.0, TheySpy enforces this list itself (`server/egress.mjs`). Every request it makes goes through one connection pool, and that pool refuses any host not on the list:
- the hosts below;
- the owner's Pi-hole and ntfy;
- the hosts of the blocklists in the library.

A refused host is written to the Activity log (`egress.blocked`), at most once an hour. `TS_EGRESS=log` only records unlisted hosts; `TS_EGRESS=off` turns the list off. The website check is not on this list: it has its own pool, pinned to addresses that are on your network or that their owner proved are theirs.

| Destination | Why |
| --- | --- |
| `api.github.com`, `github.com`, `raw.githubusercontent.com` | zero-breach indicator releases and signatures |
| `www.cisa.gov`, `services.nvd.nist.gov`, `epss.cyentia.com` | CVE feeds (KEV, NVD, EPSS) |
| `chromereleases.googleblog.com`, `support.apple.com`, `api.msrc.microsoft.com` | Vendor zero-day advisories |
| Research blogs (Citizen Lab, Amnesty Security Lab, Google TAG, ESET, Recorded Future, Confiant, Gen) | Zero-day reports (RSS) |
| `api.filterlists.com`, `firebog.net`, the lists' own hosts | Blocklist discovery and updates |
| `standards-oui.ieee.org` | MAC vendor names, monthly |
| `github.com` download hosts (`*.githubusercontent.com`, `codeload.github.com`), `*.empiricalsecurity.com`, `www.blogger.com`, `feeds.feedburner.com` | Where some of the feeds above redirect |
| `geoip.starlinkisp.net`, `1.1.1.1/cdn-cgi/trace` | Only when the owner presses "Check my connection" |
| Your Pi-hole, your ntfy server | As configured |

## Review record

**29 October 2026: review of the scanning, Pi-hole write, agent and token paths.**

Nothing found allowed an unauthenticated or token-only caller to change Pi-hole, and the CSRF rule held. Six issues were found, all fixed in 1.0.0:

| Severity | Issue | Fix |
| --- | --- | --- |
| Medium | `/lists/…` compiled a list before checking its token: an unauthenticated CPU drain | The token is checked first, in constant time |
| Medium | A baseline that failed part-way left a group, client change or adlist in Pi-hole that nothing could remove | The apply undoes its own changes on failure, and reuses an existing adlist |
| Low–medium | The website check could be pointed at internal addresses through a name with a TXT record, through DNS rebinding, or through a redirect to another port | Non-public addresses are refused outside the scan ranges; checked addresses are pinned; redirects must stay on the same origin |
| Low | The 8 MB MVT parser ran before sign-in | It runs after sign-in, on that route only |
| Low | An MVT file could inject into a STIX pattern | Pattern literals are escaped |
| Low | `/api/v1/domains/:domain` took any string, and a valid token was unlimited | Domain validation, and a per-token rate limit |

Also tightened: baseline clients must be real IP addresses, and wrong API tokens are rate-limited per address.

**30 October 2026, 1.0.1:** 1.0.0 shipped undici 8.9.0, which has known advisories, among them GHSA-2m5v-pch6-74hx (TLS options dropped in `Agent`, the pattern the website check's pinned connections use). It now ships 8.12.3, and CI fails on any `npm audit` advisory in production dependencies.
