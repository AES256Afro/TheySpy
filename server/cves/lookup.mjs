import { productVersion } from "../shared.mjs";
import { matchSoftware } from "./match.mjs";
import { parseNvdCve } from "./feeds.mjs";

// CVEs for one exact version of one product, asked of NVD (its virtualMatchString finds every CVE
// whose CPE criteria cover that version) and kept for a week. Used by the website check, device
// matching and This-Device. KEV and EPSS come from the local CVE store.

const week = 7 * 86_400_000;

/**
 * @param {{
 *   db: import("node:sqlite").DatabaseSync,
 *   cves: ReturnType<typeof import("./store.mjs").createCveStore>,
 *   nvdApiKey?: string | null,
 *   fetchImpl?: typeof fetch,
 *   now?: () => Date,
 *   sleep?: (ms: number) => Promise<void>,
 * }} deps
 */
export function createSoftwareLookup({ db, cves, nvdApiKey = null, fetchImpl = fetch, now = () => new Date(), sleep = (ms) => new Promise((r) => setTimeout(r, ms)) }) {
  const q = {
    get: db.prepare("SELECT fetched_at, cves FROM software_cves WHERE key = ?"),
    put: db.prepare("INSERT INTO software_cves (key, fetched_at, cves) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET fetched_at = excluded.fetched_at, cves = excluded.cves"),
  };
  // One NVD request at a time, spaced as NVD asks (6.5 s without a key).
  let queue = Promise.resolve();
  let lastRequest = 0;
  const pause = nvdApiKey ? 700 : 6500;

  async function fetchNvd(software) {
    const match = `cpe:2.3:a:${software.vendor}:${software.product}:${software.version}`;
    const wait = lastRequest + pause - Date.now();
    if (lastRequest && wait > 0) await sleep(wait);
    lastRequest = Date.now();
    const response = await fetchImpl(`https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=${encodeURIComponent(match)}&resultsPerPage=2000`, {
      headers: { "user-agent": `TheySpy/${productVersion}`, ...(nvdApiKey ? { apiKey: nvdApiKey } : {}) }, signal: AbortSignal.timeout(60_000),
    });
    if (!response.ok) throw new Error(`NVD answered ${response.status}`);
    const data = /** @type {any} */ (await response.json());
    // NVD's virtualMatchString also returns CVEs that only name the product as the platform another
    // product runs on (vulnerable: false). Keep the ones whose vulnerable criteria cover this version.
    return (data.vulnerabilities ?? []).flatMap(({ cve }) => {
      const row = parseNvdCve(cve);
      const hit = matchSoftware(software, row.cpeMatches);
      if (!hit) return [];
      return [{ cveId: row.cveId, cvss: row.cvssScore, severity: row.cvssSeverity, published: row.published, description: row.description?.slice(0, 300) ?? null, fixed: hit.fixed ?? null, confidence: hit.confidence }];
    });
  }

  return {
    /**
     * CVEs for a product at a version, exploited first, then by score.
     * @param {{ vendor: string, product: string, version: string }} software
     */
    async lookup(software) {
      const key = `${software.vendor}:${software.product}:${software.version}`;
      const cached = /** @type {any} */ (q.get.get(key));
      let list;
      if (cached && now().getTime() - Date.parse(cached.fetched_at) < week) {
        list = JSON.parse(cached.cves);
      } else {
        const run = queue.then(() => fetchNvd(software));
        queue = run.catch(() => {});
        list = await run;
        q.put.run(key, now().toISOString(), JSON.stringify(list));
      }
      return list.map((c) => {
        const known = cves.get(c.cveId);
        return { ...c, kev: Boolean(known?.kev), kevDue: known?.kev?.due ?? null, epss: known?.epss ?? null };
      }).sort((a, b) => Number(b.kev) - Number(a.kev) || (b.epss ?? 0) - (a.epss ?? 0) || (b.cvss ?? 0) - (a.cvss ?? 0));
    },
  };
}
