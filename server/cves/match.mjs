// Matching software against CVEs (docs/PLAN.md M6): NVD's CPE criteria with their version ranges.
// A match says how sure it is: "exact" (the CPE names this version), "range" (the version falls in a
// stated range), or "product" (the product is affected and its version could not be read or the
// CVE names no versions).

/** Splits "9.6p1" into [9, 6, "p", 1] so versions compare part by part. */
function tokens(version) {
  return String(version).toLowerCase().split(/[.\-_+:~]/).flatMap((part) => part.match(/\d+|[a-z]+/g) ?? []).map((t) => (/^\d+$/.test(t) ? Number(t) : t));
}

const preRelease = new Set(["alpha", "a", "beta", "b", "rc", "pre", "preview", "dev", "snapshot"]);

/**
 * Compares two version strings: negative, zero or positive. Numbers compare as numbers; a trailing
 * pre-release marker sorts before the release (1.0rc1 < 1.0), any other suffix after it (9.6p1 > 9.6).
 */
export function compareVersions(a, b) {
  const x = tokens(a);
  const y = tokens(b);
  const tail = (t) => (typeof t === "string" && preRelease.has(t) ? -1 : 1);
  for (let i = 0; i < Math.max(x.length, y.length); i += 1) {
    if (x[i] === undefined) return -tail(y[i]);
    if (y[i] === undefined) return tail(x[i]);
    if (x[i] === y[i]) continue;
    if (typeof x[i] === "number" && typeof y[i] === "number") return x[i] - y[i];
    if (typeof x[i] === "number") return 1; // 1.0.1 > 1.0.rc
    if (typeof y[i] === "number") return -1;
    return x[i] < y[i] ? -1 : 1;
  }
  return 0;
}

/** "cpe:2.3:a:google:chrome:141.0.7390.54:*:…" → its parts. */
export function parseCpe(criteria) {
  const p = String(criteria).split(":");
  if (p[0] !== "cpe" || p[1] !== "2.3" || p.length < 6) return null;
  return { part: p[2], vendor: p[3], product: p[4], version: p[5] ?? "*", update: p[6] ?? "*" };
}

/**
 * Whether software is affected by one CVE's CPE criteria, and how sure that is.
 * @param {{ vendor: string, product: string, version?: string | null }} software
 * @param {{ criteria: string, vsi?: string, vse?: string, vei?: string, vee?: string }[]} matches
 * @returns {{ confidence: "exact" | "range" | "product", criteria: string, fixed?: string | null } | null}
 */
export function matchSoftware(software, matches) {
  let best = null;
  const rank = { exact: 3, range: 2, product: 1 };
  for (const m of matches) {
    const cpe = parseCpe(m.criteria);
    if (!cpe || cpe.vendor !== software.vendor || cpe.product !== software.product) continue;
    const ranged = m.vsi || m.vse || m.vei || m.vee;
    let result = null;
    if (!software.version) {
      result = { confidence: "product", criteria: m.criteria };
    } else if (cpe.version !== "*" && cpe.version !== "-") {
      if (compareVersions(software.version, cpe.version) === 0) result = { confidence: "exact", criteria: m.criteria };
    } else if (ranged) {
      const v = software.version;
      const inside = (!m.vsi || compareVersions(v, m.vsi) >= 0) && (!m.vse || compareVersions(v, m.vse) > 0)
        && (!m.vei || compareVersions(v, m.vei) <= 0) && (!m.vee || compareVersions(v, m.vee) < 0);
      if (inside) result = { confidence: "range", criteria: m.criteria, fixed: m.vee ?? null };
    } else {
      result = { confidence: "product", criteria: m.criteria }; // every version
    }
    if (result && (!best || rank[result.confidence] > rank[best.confidence])) best = result;
  }
  return best;
}

/** The CPE vendor and product NVD uses for what a port check recognises (services.mjs identify()). */
export const serviceProducts = Object.freeze({
  "OpenSSH": [["openbsd", "openssh"]],
  "Dropbear SSH": [["dropbear_ssh_project", "dropbear_ssh"]],
  "nginx": [["f5", "nginx"], ["nginx", "nginx"]],
  "Apache httpd": [["apache", "http_server"]],
  "lighttpd": [["lighttpd", "lighttpd"]],
  "Caddy": [["caddyserver", "caddy"]],
  "Microsoft IIS": [["microsoft", "internet_information_services"]],
  "vsftpd": [["beasts", "vsftpd"]],
  "ProFTPD": [["proftpd", "proftpd"]],
  "Pure-FTPd": [["pureftpd", "pure-ftpd"]],
  "Postfix": [["postfix", "postfix"]],
  "Exim": [["exim", "exim"]],
  "Jetty": [["eclipse", "jetty"]],
  "mini_httpd": [["acme", "mini_httpd"]],
  "GoAhead": [["embedthis", "goahead"]],
  "OpenResty": [["openresty", "openresty"]],
  "CUPS": [["apple", "cups"], ["openprinting", "cups"]],
  "Plex Media Server": [["plex", "media_server"]],
});
