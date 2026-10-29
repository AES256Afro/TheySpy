import { gunzipSync } from "node:zlib";

// Parsers for the CVE feeds (docs/PLAN.md §5, M5). Each turns a feed's own shape into rows the store
// merges by CVE id. Endpoints, limits and licences follow BaselineWatch's docs/SOURCES.md.

export const feedUrls = Object.freeze({
  kev: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  epss: "https://epss.cyentia.com/epss_scores-current.csv.gz",
  nvd: "https://services.nvd.nist.gov/rest/json/cves/2.0",
});

export const attributions = Object.freeze([
  "This product uses the NVD API but is not endorsed or certified by the NVD.",
  "Known exploited vulnerabilities: CISA KEV catalog (public domain).",
  "EPSS scores provided by FIRST.",
]);

const cveId = /^CVE-\d{4}-\d{4,}$/;

/** CISA's KEV JSON → its version and one row per CVE. */
export function parseKev(json) {
  const data = typeof json === "string" ? JSON.parse(json) : json;
  if (!Array.isArray(data?.vulnerabilities)) throw new Error("The KEV catalog has no vulnerabilities list");
  const entries = data.vulnerabilities.filter((v) => cveId.test(v.cveID ?? "")).map((v) => ({
    cveId: v.cveID,
    added: v.dateAdded || null,
    due: v.dueDate || null,
    ransomware: String(v.knownRansomwareCampaignUse ?? "").toLowerCase() === "known",
    name: v.vulnerabilityName || null,
    description: v.shortDescription || null,
    action: v.requiredAction || null,
    product: v.vendorProject && v.product ? `${slug(v.vendorProject)}:${slug(v.product)}` : null,
    cwes: Array.isArray(v.cwes) ? v.cwes.filter((c) => /^CWE-\d+$/.test(c)) : [],
  }));
  return { version: data.catalogVersion ?? null, released: data.dateReleased ?? null, entries };
}

const slug = (s) => String(s).trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");

/** FIRST's daily EPSS CSV (gzip or plain) → its score date and cve → { epss, percentile }. */
export function parseEpss(buffer) {
  const text = Buffer.isBuffer(buffer) && buffer[0] === 0x1f && buffer[1] === 0x8b ? gunzipSync(buffer).toString("utf8") : String(buffer);
  const scoreDate = /score_date:([0-9T:+-]+)/.exec(text)?.[1]?.slice(0, 10) ?? null;
  const scores = new Map();
  for (const line of text.split("\n")) {
    if (!line.startsWith("CVE-")) continue;
    const [id, epss, percentile] = line.trim().split(",");
    const e = Number(epss);
    const p = Number(percentile);
    if (cveId.test(id) && Number.isFinite(e) && Number.isFinite(p)) scores.set(id, { epss: e, percentile: p });
  }
  return { scoreDate, scores };
}

/** The best CVSS an NVD record carries: 4.0, then 3.1, 3.0, 2.0; NVD's own (Primary) before a CNA's. */
function bestCvss(metrics = {}) {
  for (const key of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const list = metrics[key];
    if (!Array.isArray(list) || !list.length) continue;
    const m = list.find((x) => x.type === "Primary") ?? list[0];
    const d = m.cvssData ?? {};
    return { score: Number(d.baseScore ?? NaN), severity: String(d.baseSeverity ?? m.baseSeverity ?? "").toLowerCase() || null, vector: d.vectorString ?? null };
  }
  return null;
}

/** One NVD 2.0 `cve` object → a row: description, CVSS, CWEs, CPE criteria and the products they name. */
export function parseNvdCve(cve) {
  const description = (cve.descriptions ?? []).find((d) => d.lang === "en")?.value ?? null;
  const cvss = bestCvss(cve.metrics);
  const cwes = [...new Set((cve.weaknesses ?? []).flatMap((w) => (w.description ?? []).map((d) => d.value)).filter((v) => /^CWE-\d+$/.test(v)))];
  const matches = [];
  for (const config of cve.configurations ?? []) {
    for (const node of config.nodes ?? []) {
      for (const m of node.cpeMatch ?? []) {
        if (!m.vulnerable || !m.criteria) continue;
        matches.push({
          criteria: m.criteria,
          ...(m.versionStartIncluding ? { vsi: m.versionStartIncluding } : {}), ...(m.versionStartExcluding ? { vse: m.versionStartExcluding } : {}),
          ...(m.versionEndIncluding ? { vei: m.versionEndIncluding } : {}), ...(m.versionEndExcluding ? { vee: m.versionEndExcluding } : {}),
        });
      }
    }
  }
  const products = [...new Set(matches.map((m) => m.criteria.split(":")).filter((p) => p.length > 5).map((p) => `${p[3]}:${p[4]}`))];
  return {
    cveId: cve.id, published: cve.published ?? null, modified: cve.lastModified ?? null, status: cve.vulnStatus ?? null, description,
    cvssScore: cvss && Number.isFinite(cvss.score) ? cvss.score : null, cvssSeverity: cvss?.severity ?? null, cvssVector: cvss?.vector ?? null,
    cwes, products, cpeMatches: matches.slice(0, 400),
  };
}

/** NVD's timestamps want "2026-10-29T12:00:00.000Z" style, at most 120 days apart. */
export const nvdDate = (d) => new Date(d).toISOString().replace("Z", "+00:00").replace(/\.\d{3}/, ".000");
