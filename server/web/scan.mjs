import { createHmac } from "node:crypto";
import { promises as dnsPromises } from "node:dns";
import net from "node:net";
import { Agent, fetch as undiciFetch } from "undici";
import { productVersion } from "../shared.mjs";
import { inCidr } from "../fleet/addresses.mjs";

// The website check: what PHP (and a PHP CMS) a site runs, whether that version is still supported,
// which CVEs NVD lists for it, and whether files that should never be public are reachable. It only
// sends GET requests to a fixed list of paths: no payloads, no logins, no crawling.
//
// It runs on a site on this network (inside TS_SCAN_RANGES), or on a public site whose owner has
// proved control of it with a token file or DNS record, so it cannot be pointed at other people's
// sites.

const userAgent = `TheySpy/${productVersion} website check (+https://github.com/AES256Afro/TheySpy)`;
const maxBody = 256 * 1024;

/** When each PHP branch stops getting security fixes (php.net/supported-versions). */
export const phpSupportEnds = Object.freeze({
  "5.6": "2018-12-31", "7.0": "2019-01-10", "7.1": "2019-12-01", "7.2": "2020-11-30", "7.3": "2021-12-06", "7.4": "2022-11-28",
  "8.0": "2023-11-26", "8.1": "2025-12-31", "8.2": "2026-12-31", "8.3": "2027-12-31", "8.4": "2028-12-31", "8.5": "2029-12-31",
});

/**
 * Paths checked, each with how to recognise a real hit (not a "soft 404" page) and what it means.
 * Evidence never keeps a secret: a .env hit records the variable names, not their values.
 */
export const probes = Object.freeze([
  { path: "/.env", severity: "critical", title: "Environment file (.env) is public",
    detect: (b) => /^[A-Z][A-Z0-9_]{2,}=/m.test(b) && !/<html/i.test(b), evidence: (b) => `variables: ${[...b.matchAll(/^([A-Z][A-Z0-9_]{2,})=/gm)].map((m) => m[1]).slice(0, 12).join(", ")}`,
    fix: "Move .env outside the web root, or deny dotfiles in the web server. Then change every password and key it held." },
  { path: "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", severity: "critical", title: "PHPUnit eval-stdin.php is reachable (CVE-2017-9841, known exploited)",
    detect: (b, r) => r.status === 200 && b.length < 200 && !/<html/i.test(b), evidence: () => "the file answers 200; it runs any PHP code sent to it",
    fix: "Delete the vendor/ folder from the web root (install without dev dependencies: composer install --no-dev) or deny /vendor/." },
  { path: "/wp-config.php.bak", severity: "critical", title: "WordPress config backup is public",
    detect: (b) => /DB_PASSWORD/.test(b), evidence: () => "contains DB_PASSWORD", fix: "Delete the backup and change the database password." },
  { path: "/wp-config.php~", severity: "critical", title: "WordPress config editor backup is public",
    detect: (b) => /DB_PASSWORD/.test(b), evidence: () => "contains DB_PASSWORD", fix: "Delete the backup and change the database password." },
  { path: "/.git/HEAD", severity: "high", title: "Git repository is public",
    detect: (b) => /^ref: refs\//.test(b.trim()), evidence: (b) => b.trim().slice(0, 60), fix: "Deny /.git/ in the web server, or deploy without the .git folder; its history may hold secrets." },
  { path: "/phpinfo.php", severity: "high", title: "phpinfo() page is public",
    detect: (b) => /phpinfo\(\)|<title>PHP \d/i.test(b), evidence: (b) => phpinfoVersion(b) ?? "phpinfo output", fix: "Delete it: it shows paths, modules and settings to anyone." },
  { path: "/info.php", severity: "high", title: "phpinfo() page is public",
    detect: (b) => /phpinfo\(\)|<title>PHP \d/i.test(b), evidence: (b) => phpinfoVersion(b) ?? "phpinfo output", fix: "Delete it: it shows paths, modules and settings to anyone." },
  { path: "/adminer.php", severity: "high", title: "Adminer database login is public",
    detect: (b) => /adminer/i.test(b) && /<form/i.test(b), evidence: () => "a database login form", fix: "Remove Adminer, or put it behind the web server's own authentication." },
  { path: "/phpmyadmin/", severity: "medium", title: "phpMyAdmin is public",
    detect: (b) => /phpMyAdmin/.test(b) && /<form/i.test(b), evidence: () => "a phpMyAdmin login form", fix: "Limit phpMyAdmin to your own network or a VPN." },
  { path: "/composer.lock", severity: "medium", title: "composer.lock is public",
    detect: (b) => /"packages"\s*:/.test(b), evidence: (b) => `${(b.match(/"name"\s*:/g) ?? []).length} packages with exact versions`, fix: "Deny it in the web server: it lists every library and version for an attacker." },
  { path: "/server-status", severity: "medium", title: "Apache server-status is public",
    detect: (b) => /Apache Server Status/i.test(b), evidence: () => "live requests and client addresses", fix: "Limit mod_status to localhost." },
  { path: "/xmlrpc.php", severity: "low", title: "WordPress XML-RPC is enabled",
    detect: (b) => /XML-RPC server accepts POST requests only/i.test(b), evidence: () => "xmlrpc.php answers", fix: "Disable XML-RPC unless an app needs it; it is used for password guessing." },
]);

const phpinfoVersion = (b) => /PHP Version <\/td><td[^>]*>\s*([\d.]+)|<h1 class="p">PHP Version ([\d.]+)/i.exec(b)?.slice(1).find(Boolean) ?? null;

/** PHP and CMS versions a page and its headers give away. */
export function fingerprint(headers, body) {
  const found = [];
  const powered = `${headers.get("x-powered-by") ?? ""} ${headers.get("server") ?? ""}`;
  const php = /PHP\/(\d+\.\d+(?:\.\d+)?)/i.exec(powered);
  if (php) found.push({ product: "PHP", version: php[1], cpe: ["php", "php"], source: "X-Powered-By / Server header" });
  else if (/PHPSESSID/i.test(headers.get("set-cookie") ?? "")) found.push({ product: "PHP", version: null, cpe: ["php", "php"], source: "PHPSESSID cookie" });
  const generator = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(body)?.[1] ?? "";
  const wp = /WordPress\s+([\d.]+)/i.exec(generator);
  if (wp) found.push({ product: "WordPress", version: wp[1], cpe: ["wordpress", "wordpress"], source: "generator tag" });
  else if (/wp-content\//.test(body)) found.push({ product: "WordPress", version: null, cpe: ["wordpress", "wordpress"], source: "wp-content paths" });
  const drupal = /Drupal\s+(\d+(?:\.\d+)*)/i.exec(generator || headers.get("x-generator") || "");
  if (drupal) found.push({ product: "Drupal", version: drupal[1], cpe: ["drupal", "drupal"], source: "generator" });
  const joomla = /Joomla!?\s*(\d+(?:\.\d+)*)?/i.exec(generator);
  if (joomla) found.push({ product: "Joomla!", version: joomla[1] ?? null, cpe: ["joomla", "joomla\\!"], source: "generator tag" });
  return found;
}

// Addresses no website check may reach unless they are inside the owner's scan ranges: private,
// loopback, link-local (cloud metadata), carrier-grade NAT, documentation, multicast and reserved.
const nonPublic = new net.BlockList();
for (const [a, p] of /** @type {[string, number][]} */ ([["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]])) nonPublic.addSubnet(a, p, "ipv4");
for (const [a, p] of /** @type {[string, number][]} */ ([["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8], ["64:ff9b::", 96], ["2001:db8::", 32]])) nonPublic.addSubnet(a, p, "ipv6");

/** @param {string} ip */
export function isPublicAddress(ip) {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) return isPublicAddress(mapped[1]);
  const family = net.isIP(ip);
  return family !== 0 && !nonPublic.check(ip, family === 6 ? "ipv6" : "ipv4");
}

/**
 * A connection pool that only ever connects to the addresses that were checked, so the name cannot
 * be pointed somewhere else (DNS rebinding) between the check and the requests.
 * @param {string[]} addresses
 */
function pinnedTo(addresses) {
  const list = addresses.map((address) => ({ address, family: net.isIP(address) }));
  return new Agent({ connect: { lookup: (_host, options, callback) => (options?.all ? callback(null, list) : callback(null, list[0].address, list[0].family)) } });
}

/**
 * @param {{
 *   db: import("node:sqlite").DatabaseSync,
 *   software: ReturnType<typeof import("../cves/lookup.mjs").createSoftwareLookup>,
 *   audit: ReturnType<typeof import("../audit.mjs").createAuditLog>,
 *   verificationKey: Buffer,
 *   scanRanges: string[],
 *   fetchImpl?: typeof fetch,
 *   resolve?: (host: string) => Promise<string[]>,
 *   resolveTxt?: (host: string) => Promise<string[][]>,
 *   now?: () => Date,
 * }} deps
 */
export function createWebScanner({ db, software: lookup, audit, verificationKey, scanRanges, fetchImpl = /** @type {typeof fetch} */ (/** @type {unknown} */ (undiciFetch)), resolve, resolveTxt, now = () => new Date() }) {
  const lookupAll = resolve ?? (async (host) => (await dnsPromises.lookup(host, { all: true })).map((a) => a.address));
  const txt = resolveTxt ?? ((host) => dnsPromises.resolveTxt(host));
  const q = {
    start: db.prepare("INSERT INTO checks (query, kind, profile, started_at, actor) VALUES (?, 'website', 'web', ?, ?)"),
    finish: db.prepare("UPDATE checks SET finished_at = ?, result = ? WHERE id = ?"),
  };

  /** The token a site's owner publishes to prove control: stable per host, secret to everyone else. */
  const tokenFor = (host) => createHmac("sha256", verificationKey).update(host.toLowerCase()).digest("hex").slice(0, 32);

  /**
   * Fetches one path on the site: GET only, same-origin redirects only, a size cap and a timeout,
   * connecting only to the checked addresses.
   * @param {string} origin @param {string} path @param {Agent} dispatcher
   */
  async function get(origin, path, dispatcher) {
    let url = new URL(path, origin);
    for (let hop = 0; hop < 4; hop += 1) {
      let response;
      try {
        response = await fetchImpl(url, /** @type {RequestInit} */ (/** @type {unknown} */ ({ dispatcher, method: "GET", redirect: "manual", headers: { "user-agent": userAgent, accept: "*/*" }, signal: AbortSignal.timeout(10_000) })));
      } catch (error) {
        return { status: 0, headers: new Headers(), body: "", error: error.cause?.code ?? error.message, url: String(url) };
      }
      if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
        const next = new URL(response.headers.get("location"), url);
        if (next.origin !== url.origin) return { status: response.status, headers: response.headers, body: "", url: String(url), offsite: String(next) };
        url = next;
        continue;
      }
      const reader = response.body?.getReader();
      const chunks = [];
      let size = 0;
      while (reader) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        size += value.length;
        if (size >= maxBody) { await reader.cancel(); break; }
      }
      return { status: response.status, headers: response.headers, body: Buffer.concat(chunks).toString("utf8"), url: String(url) };
    }
    return { status: 0, headers: new Headers(), body: "", error: "too many redirects", url: String(url) };
  }

  /**
   * Whether this site may be checked: it is on this network, or its owner published the token at
   * /.well-known/theyspy-verification.txt or in a DNS TXT record "theyspy-verification=<token>".
   */
  async function authorize(origin) {
    const host = new URL(origin).hostname;
    const addresses = net.isIP(host) ? [host] : await lookupAll(host).catch(() => []);
    if (!addresses.length) throw Object.assign(new Error(`${host} does not resolve`), { status: 400 });
    const dispatcher = pinnedTo(addresses);
    try {
      return await verify(origin, host, addresses, dispatcher);
    } catch (error) {
      void dispatcher.close();
      throw error;
    }
  }

  /** @param {string} origin @param {string} host @param {string[]} addresses @param {Agent} dispatcher */
  async function verify(origin, host, addresses, dispatcher) {
    if (addresses.every((a) => scanRanges.some((r) => inCidr(a, r)))) return { how: "on this network", addresses, dispatcher };
    // Outside the scan ranges only public addresses: a TXT record proves control of a name, not of
    // whatever address the name is pointed at (this host, a container, a cloud metadata service).
    const internal = addresses.filter((a) => !isPublicAddress(a));
    if (internal.length) throw Object.assign(new Error(`${host} points at ${internal.join(", ")}, which is not a public address and not inside the networks TheySpy may scan (TS_SCAN_RANGES).`), { status: 403 });
    const token = tokenFor(host);
    const file = await get(origin, "/.well-known/theyspy-verification.txt", dispatcher);
    if (file.status === 200 && file.body.includes(token)) return { how: "verification file", addresses, dispatcher };
    const records = await txt(host).catch(() => []);
    if (records.some((r) => r.join("").trim() === `theyspy-verification=${token}`)) return { how: "DNS TXT record", addresses, dispatcher };
    throw Object.assign(new Error(`${host} is not on your network, so TheySpy needs proof the site is yours before checking it. Publish ${token} at ${new URL("/.well-known/theyspy-verification.txt", origin)} or as a DNS TXT record "theyspy-verification=${token}", then check again.`), { status: 403, verification: { host, token } });
  }

  const scanner = {
    tokenFor,

    /**
     * Checks one website and keeps the result with the other targeted checks.
     * @param {{ url: string, log?: (line: string) => void }} options @param {string} actor
     */
    async scan({ url, log = () => {} }, actor) {
      let origin;
      try { origin = new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`).origin; } catch { throw Object.assign(new Error(`"${url}" is not a website address`), { status: 400 }); }
      const access = await authorize(origin);
      try {
        const started = now();
        const id = Number(q.start.run(origin, started.toISOString(), actor).lastInsertRowid);
        log(`Checking ${origin} (${access.how}).`);

        const home = await get(origin, "/", access.dispatcher);
        if (!home.status) throw Object.assign(new Error(`Could not reach ${origin}: ${home.error}`), { status: 502 });
        const software = fingerprint(home.headers, home.body);
        // A soft-404 page answers 200 for everything; remember it so a probe is not taken for a hit.
        const missing = await get(origin, `/theyspy-${tokenFor(origin).slice(0, 8)}-does-not-exist.php`, access.dispatcher);

        const findings = [];
        for (const probe of probes) {
          const r = await get(origin, probe.path, access.dispatcher);
          if (r.status !== 200 || (missing.status === 200 && r.body === missing.body)) continue;
          if (!probe.detect(r.body, r)) continue;
          findings.push({ path: probe.path, severity: probe.severity, title: probe.title, evidence: probe.evidence(r.body), fix: probe.fix });
          const version = probe.path.includes("info.php") ? phpinfoVersion(r.body) : null;
          if (version && !software.some((s) => s.product === "PHP" && s.version)) software.unshift({ product: "PHP", version, cpe: ["php", "php"], source: `${probe.path}` });
        }
        if (software.some((s) => s.product === "WordPress" && !s.version)) {
          const readme = await get(origin, "/readme.html", access.dispatcher);
          const v = readme.status === 200 ? /Version\s+([\d.]+)/i.exec(readme.body)?.[1] : null;
          if (v) Object.assign(software.find((s) => s.product === "WordPress"), { version: v, source: "readme.html" });
        }
        if (!home.headers.get("strict-transport-security") && origin.startsWith("https:")) findings.push({ path: "/", severity: "low", title: "No HSTS header", evidence: "Strict-Transport-Security is missing", fix: "Send Strict-Transport-Security so browsers always use HTTPS." });
        if (/PHP\//i.test(home.headers.get("x-powered-by") ?? "")) findings.push({ path: "/", severity: "low", title: "PHP announces its version", evidence: `X-Powered-By: ${home.headers.get("x-powered-by")}`, fix: "Set expose_php = Off in php.ini." });

        for (const s of software) {
          if (s.product === "PHP" && s.version) {
            const branch = s.version.split(".").slice(0, 2).join(".");
            const ends = phpSupportEnds[branch] ?? null;
            s.supportEnds = ends;
            s.supported = ends ? ends >= started.toISOString().slice(0, 10) : null;
            if (s.supported === false) findings.push({ path: "/", severity: "high", title: `PHP ${branch} no longer gets security fixes`, evidence: `support ended ${ends}`, fix: `Upgrade to a supported PHP branch (${Object.entries(phpSupportEnds).filter(([, d]) => d >= started.toISOString().slice(0, 10)).map(([b]) => b).join(", ")}).` });
          }
          if (s.version) {
            try {
              s.cves = await lookup.lookup({ vendor: s.cpe[0], product: s.cpe[1], version: s.version });
              log(`${s.product} ${s.version}: ${s.cves.length} CVEs in NVD${s.cves.some((c) => c.kev) ? `, ${s.cves.filter((c) => c.kev).length} known exploited` : ""}.`);
            } catch (error) {
              s.cvesError = error.message;
            }
          }
          delete s.cpe;
        }
        const order = { critical: 0, high: 1, medium: 2, low: 3 };
        findings.sort((a, b) => order[a.severity] - order[b.severity]);
        const result = { kind: "website", url: origin, access: access.how, status: home.status, software, findings, durationMs: now().getTime() - started.getTime() };
        q.finish.run(now().toISOString(), JSON.stringify(result), id);
        audit.record(actor, "web.checked", origin, { id, findings: findings.length, access: access.how });
        log(`${findings.length} finding${findings.length === 1 ? "" : "s"}${findings.some((f) => f.severity === "critical") ? ", critical ones first" : ""}.`);
        return { id, query: origin, profile: "web", ...result };
      } finally {
        void access.dispatcher.close();
      }
    },
  };
  return scanner;
}
