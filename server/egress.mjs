import { Agent, buildConnector, setGlobalDispatcher } from "undici";

// The outbound allowlist (SECURITY.md). Every fetch TheySpy makes goes through one connection pool
// that refuses hosts it has no reason to contact. Allowed: the feeds below, the owner's own Pi-hole
// and ntfy, and the hosts of the blocklists in the library. The website check is not covered here:
// it has its own pool, pinned to addresses the owner proved are theirs (web/scan.mjs). Port checks
// are plain sockets limited to TS_SCAN_RANGES.

/** Feeds TheySpy reads. A leading dot allows the domain and every name under it. */
export const feedHosts = [
  // zero-breach indicator releases (assets redirect to GitHub's download hosts)
  "api.github.com", "github.com", "raw.githubusercontent.com", "codeload.github.com", ".githubusercontent.com",
  // CVEs: CISA KEV, NVD, EPSS (which moved to Empirical Security)
  "www.cisa.gov", "services.nvd.nist.gov", "epss.cyentia.com", ".empiricalsecurity.com",
  // Vendor zero-day advisories and research reports
  "chromereleases.googleblog.com", "www.blogger.com", "support.apple.com", "api.msrc.microsoft.com", "msrc.microsoft.com",
  "citizenlab.ca", "securitylab.amnesty.org", "blog.google", "www.welivesecurity.com", "www.recordedfuture.com", "blog.confiant.com", "www.gendigital.com", "feeds.feedburner.com",
  // Blocklist directories
  "api.filterlists.com", "adguardteam.github.io", "firebog.net", "v.firebog.net",
  // MAC vendor names; "Check my connection" (Cloudflare's trace, SpaceX's geofeed)
  "standards-oui.ieee.org", "1.1.1.1", "geoip.starlinkisp.net",
];

/** @param {string} url @returns {string | null} */
export function hostOf(url) {
  try { return new URL(String(url)).hostname.toLowerCase().replace(/^\[|\]$/g, ""); } catch { return null; }
}

/**
 * @param {{
 *   mode?: "enforce" | "log" | "off",
 *   extraHosts?: () => Iterable<string | null | undefined>,
 *   audit?: ReturnType<typeof import("./audit.mjs").createAuditLog>,
 *   now?: () => Date,
 * }} options
 */
export function createEgress({ mode = "enforce", extraHosts = () => [], audit, now = () => new Date() }) {
  const reported = new Map(); // host → last time it was written to the audit log (once an hour)
  const matches = (host, entry) => (entry.startsWith(".") ? host === entry.slice(1) || host.endsWith(entry) : host === entry);

  const egress = {
    mode,
    /** @param {string} hostname */
    allows(hostname) {
      const host = String(hostname).toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
      if (feedHosts.some((entry) => matches(host, entry))) return true;
      for (const extra of extraHosts()) if (extra && host === String(extra).toLowerCase()) return true;
      return false;
    },
    /** Records a refused (or, in log mode, a would-be refused) host, at most once an hour each. @param {string} host */
    report(host) {
      const t = now().getTime();
      if (t - (reported.get(host) ?? 0) < 3_600_000) return;
      reported.set(host, t);
      audit?.record("system", mode === "enforce" ? "egress.blocked" : "egress.unlisted", host, { mode });
    },
    /** A connection pool that applies the list; `install` makes it the one fetch uses. */
    dispatcher() {
      const connect = buildConnector({});
      return new Agent({
        connect: (options, callback) => {
          if (mode !== "off" && !egress.allows(options.hostname)) {
            egress.report(options.hostname);
            if (mode === "enforce") return callback(Object.assign(new Error(`TheySpy's outbound allowlist does not include ${options.hostname} (see SECURITY.md; TS_EGRESS=log to only record it)`), { code: "TS_EGRESS_BLOCKED" }), null);
          }
          return connect(options, callback);
        },
      });
    },
    install() {
      if (mode !== "off") setGlobalDispatcher(egress.dispatcher());
      return egress;
    },
  };
  return egress;
}
