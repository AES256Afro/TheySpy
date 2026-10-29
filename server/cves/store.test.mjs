import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { testClock, testServices } from "../test-helpers.mjs";
import { feedUrls, parseEpss, parseKev, parseNvdCve } from "./feeds.mjs";

const kevEntry = (id, extra = {}) => ({ cveID: id, vendorProject: "Google", product: "Chromium V8", vulnerabilityName: `Google Chromium V8 issue ${id}`, dateAdded: "2026-10-27", shortDescription: "Type confusion in V8.", requiredAction: "Apply updates.", dueDate: "2026-11-17", knownRansomwareCampaignUse: "Unknown", cwes: ["CWE-843"], ...extra });
const kev = (entries, version = "2026.10.29") => JSON.stringify({ title: "KEV", catalogVersion: version, dateReleased: "2026-10-29T19:09:34Z", count: entries.length, vulnerabilities: entries });
const nvdCve = (id, extra = {}) => ({
  id, published: "2026-10-20T10:00:00.000", lastModified: "2026-10-28T10:00:00.000", vulnStatus: "Analyzed",
  descriptions: [{ lang: "en", value: `Description of ${id}` }],
  metrics: { cvssMetricV31: [{ type: "Primary", cvssData: { baseScore: 8.8, baseSeverity: "HIGH", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" } }] },
  weaknesses: [{ description: [{ lang: "en", value: "CWE-843" }] }],
  configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", versionEndExcluding: "141.0.7390.65" }, { vulnerable: false, criteria: "cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*" }] }] }],
  ...extra,
});
const epssCsv = (rows) => `#model_version:v2025.03.14,score_date:2026-10-29T00:00:00+0000\ncve,epss,percentile\n${rows.map(([id, e, p]) => `${id},${e},${p}`).join("\n")}\n`;
// EPSS covers every published CVE; a file with fewer than 100,000 scores is refused.
const filler = Array.from({ length: 100_000 }, (_, i) => [`CVE-2020-${String(100000 + i)}`, 0.001, 0.1]);

function feeds({ kevBody, nvdPages, epssBody }) {
  const requests = [];
  const fetchImpl = async (input) => {
    const url = String(input);
    requests.push(url);
    if (url === feedUrls.kev) return new Response(kevBody(), { status: 200, headers: { etag: `"${kevBody().length}"` } });
    if (url === feedUrls.epss) return new Response(epssBody(), { status: 200 });
    if (url.startsWith(feedUrls.nvd)) {
      const start = Number(new URL(url).searchParams.get("startIndex"));
      const all = nvdPages();
      return Response.json({ totalResults: all.length, startIndex: start, resultsPerPage: 2000, vulnerabilities: all.slice(start, start + 2000).map((cve) => ({ cve })) });
    }
    return new Response("not found", { status: 404 });
  };
  return { fetchImpl, requests };
}

describe("CVE feeds", () => {
  it("parses KEV, NVD and EPSS", () => {
    const k = parseKev(kev([kevEntry("CVE-2026-4127", { knownRansomwareCampaignUse: "Known" }), { cveID: "not-a-cve" }]));
    expect(k).toMatchObject({ version: "2026.10.29", entries: [{ cveId: "CVE-2026-4127", ransomware: true, product: "google:chromium_v8", due: "2026-11-17" }] });
    const n = parseNvdCve(nvdCve("CVE-2026-4127"));
    expect(n).toMatchObject({ cvssScore: 8.8, cvssSeverity: "high", cwes: ["CWE-843"], products: ["google:chrome"], cpeMatches: [{ criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", vee: "141.0.7390.65" }] });
    const e = parseEpss(gzipSync(epssCsv([["CVE-2026-4127", 0.71, 0.99]])));
    expect(e.scoreDate).toBe("2026-10-29");
    expect(e.scores.get("CVE-2026-4127")).toEqual({ epss: 0.71, percentile: 0.99 });
  });

  it("builds the list from all three, flags KEV entries as zero-days, and records later KEV additions", async () => {
    let kevList = [kevEntry("CVE-2026-4127"), kevEntry("CVE-2021-30551", { vendorProject: "Apple", product: "WebKit" })];
    let nvd = [nvdCve("CVE-2026-4127"), nvdCve("CVE-2026-5000", { metrics: {} })];
    const web = feeds({ kevBody: () => kev(kevList), nvdPages: () => nvd, epssBody: () => gzipSync(epssCsv([["CVE-2026-4127", 0.71, 0.99], ["CVE-2026-5000", 0.02, 0.4], ...filler])) });
    const now = testClock("2026-10-29T20:00:00.000Z");
    const { cves, audit } = testServices({ webFetch: web.fetchImpl, now });

    await cves.syncKev();
    await cves.syncNvd();
    await cves.syncEpss();
    expect(cves.stats()).toMatchObject({ total: 3, kev: 2, zeroDays: 2, epssHigh: 1 });
    const chrome = cves.get("cve-2026-4127");
    expect(chrome).toMatchObject({ cvss: 8.8, epss: 0.71, kev: { due: "2026-11-17" }, zeroDay: true, products: ["google:chrome"], zeroDaySources: [{ source: "CISA KEV", at: "2026-10-27" }] });
    // A KEV entry older than NVD's window keeps KEV's own words and product.
    expect(cves.get("CVE-2021-30551")).toMatchObject({ description: "Type confusion in V8.", products: ["apple:webkit"], kev: { name: expect.stringContaining("CVE-2021-30551") } });
    // The first load announces nothing.
    expect(cves.recentEvents()).toEqual([]);

    // The next hour: one new KEV entry, one new CVE from NVD since the last run.
    kevList = [...kevList, kevEntry("CVE-2026-5000", { dateAdded: "2026-10-29" })];
    nvd = [nvdCve("CVE-2026-6001")];
    now.advance(60 * 60_000);
    expect((await cves.syncKev()).added).toEqual(["CVE-2026-5000"]);
    await cves.syncNvd();
    expect(cves.recentEvents().map((e) => [e.cveId, e.kind]).sort()).toEqual([["CVE-2026-5000", "kev_added"], ["CVE-2026-6001", "new"]]);
    expect(audit.list(20).find((e) => e.action === "cves.kev_added").detail).toEqual({ cves: ["CVE-2026-5000"], count: 1 });

    const exploited = cves.list({ kev: true });
    expect(exploited.total).toBe(3);
    expect(exploited.rows[0].cveId).toBe("CVE-2026-5000"); // the newest KEV addition first
    expect(cves.list({ q: "CVE-2026-4127" }).rows.map((r) => r.cveId)).toEqual(["CVE-2026-4127"]);
    expect(cves.list({ product: "webkit" }).rows.map((r) => r.cveId)).toEqual(["CVE-2021-30551"]);
    expect(cves.list({ minEpss: 0.5 }).total).toBe(1);
  });

  it("pages through NVD in windows of at most 120 days, pausing between requests", async () => {
    const many = Array.from({ length: 4500 }, (_, i) => nvdCve(`CVE-2026-${10000 + i}`));
    const web = feeds({ kevBody: () => kev([]), nvdPages: () => many, epssBody: () => "" });
    const { cves } = testServices({ webFetch: web.fetchImpl, now: testClock("2026-10-29T20:00:00.000Z") });
    expect(await cves.syncNvd({ days: 200 })).toEqual({ fetched: 9000, added: 4500 });
    const nvdRequests = web.requests.filter((u) => u.startsWith(feedUrls.nvd));
    expect(nvdRequests).toHaveLength(6); // two windows (120 + 80 days) × three pages
    expect(new Set(nvdRequests.map((u) => new URL(u).searchParams.get("lastModStartDate"))).size).toBe(2);
    expect(cves.stats().feeds.nvd).toMatchObject({ through: "2026-10-29T20:00:00.000Z", fetched: 9000 });
  });

  it("refuses an EPSS file that looks wrong", async () => {
    const web = feeds({ kevBody: () => kev([]), nvdPages: () => [], epssBody: () => gzipSync(epssCsv([["CVE-2026-4127", 0.71, 0.99]])) });
    const { cves } = testServices({ webFetch: web.fetchImpl });
    await expect(cves.syncEpss()).rejects.toThrow(/looked wrong/);
  });
});
