import { productVersion } from "../shared.mjs";

// Zero-day reports from vendors and researchers (docs/PLAN.md §5, M5 part 2): sources that say a
// CVE "may have been exploited" before CISA adds it to KEV, or that tie it to a spyware campaign.
//  - Chrome Releases (Atom): "Google is aware that an exploit for CVE-… exists in the wild."
//  - Apple security releases: "Apple is aware of a report that this issue may have been exploited."
//  - Microsoft (MSRC CVRF): a threat marked "Exploited:Yes".
//  - Citizen Lab and Amnesty Tech: the latest research reports, with any CVEs they name.
// Project Zero's "0day In the Wild" sheet stopped being updated in 2023, and Android's bulletin
// index is drawn by script, so neither is read.

export const advisoryUrls = Object.freeze({
  chrome: "https://chromereleases.googleblog.com/feeds/posts/default?max-results=50",
  apple: "https://support.apple.com/en-us/100100",
  msrc: (month) => `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/${month}`,
  research: [["Citizen Lab", "https://citizenlab.ca/feed/"], ["Amnesty Security Lab", "https://securitylab.amnesty.org/feed/"]],
});

const cvePattern = /CVE-\d{4}-\d{4,}/g;
const unescape = (s) => String(s).replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;|&#x27;/g, "'").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&");
const text = (html) => unescape(unescape(String(html).replace(/<!\[CDATA\[|\]\]>/g, " "))).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");

/** Chrome Releases' Atom feed → CVEs Google says are exploited in the wild. */
export function parseChromeFeed(xml) {
  const out = [];
  for (const entry of String(xml).split("<entry>").slice(1)) {
    const at = /<published>([^<]+)<\/published>/.exec(entry)?.[1]?.slice(0, 10) ?? null;
    const url = /<link rel=["']alternate["'][^>]*href=["']([^"']+)["']/.exec(entry)?.[1] ?? null;
    for (const m of text(entry).matchAll(/exploit for (CVE-\d{4}-\d{4,}) exists in the wild/gi)) {
      out.push({ cveId: m[1], source: "Chrome Releases", at, url, note: "Google: an exploit exists in the wild" });
    }
  }
  return out;
}

/** Apple's security releases page → its releases, newest first: name, date, address. */
export function parseAppleIndex(html) {
  const rows = [];
  for (const m of String(html).matchAll(/<a href="(https:\/\/support\.apple\.com\/en-us\/\d+)"[^>]*>([^<]+)<\/a>[\s\S]*?<\/td>[\s\S]*?<p[^>]*>(\d{1,2} \w{3} \d{4})<\/p>/g)) {
    const at = new Date(`${m[3]} UTC`);
    rows.push({ url: m[1], name: unescape(m[2]).trim(), at: Number.isNaN(at.getTime()) ? null : at.toISOString().slice(0, 10) });
  }
  return rows;
}

/** One Apple release page → the CVEs Apple says may have been exploited. */
export function parseAppleRelease(html, release) {
  const out = [];
  // Each fix is a block that starts "Impact:"; the exploitation note sits in the block it applies to.
  for (const block of text(html).split(/Impact:/).slice(1)) {
    if (!/may have been exploited|aware of a report/i.test(block)) continue;
    for (const cveId of new Set(block.match(cvePattern) ?? [])) {
      out.push({ cveId, source: "Apple", at: release.at, url: release.url, note: `Apple (${release.name}): may have been exploited` });
    }
  }
  return out;
}

/** A month of Microsoft's CVRF → CVEs marked Exploited:Yes. */
export function parseMsrc(doc, month) {
  const out = [];
  for (const v of doc?.Vulnerability ?? []) {
    if (!(v.Threats ?? []).some((t) => /Exploited:Yes/.test(t?.Description?.Value ?? ""))) continue;
    if (!/^CVE-\d{4}-\d{4,}$/.test(v.CVE ?? "")) continue;
    out.push({ cveId: v.CVE, source: "Microsoft", at: doc?.DocumentTracking?.CurrentReleaseDate?.slice(0, 10) ?? null, url: `https://msrc.microsoft.com/update-guide/vulnerability/${v.CVE}`, note: `Microsoft (${month}): exploited${v.Title?.Value ? ` · ${v.Title.Value}` : ""}` });
  }
  return out;
}

/** An RSS feed → its latest items: title, link, date, and any CVEs they name. */
export function parseRss(xml, source) {
  return String(xml).split("<item>").slice(1).slice(0, 10).map((item) => {
    const tag = (name) => unescape((new RegExp(`<${name}>(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?</${name}>`).exec(item)?.[1] ?? "").trim());
    const date = new Date(tag("pubDate"));
    return { source, title: text(tag("title")).trim(), url: tag("link"), at: Number.isNaN(date.getTime()) ? null : date.toISOString().slice(0, 10), cves: [...new Set(text(item).match(cvePattern) ?? [])] };
  });
}

/**
 * @param {{
 *   cves: ReturnType<typeof import("./store.mjs").createCveStore>,
 *   settings: ReturnType<typeof import("../db.mjs").createSettingsStore>,
 *   fetchImpl?: typeof fetch,
 *   now?: () => Date,
 * }} deps
 */
export function createAdvisories({ cves, settings, fetchImpl = fetch, now = () => new Date() }) {
  const get = async (url, accept = "*/*") => {
    const response = await fetchImpl(url, { headers: { "user-agent": `TheySpy/${productVersion}`, accept }, signal: AbortSignal.timeout(120_000), redirect: "follow" });
    if (!response.ok) throw new Error(`${new URL(url).host} answered ${response.status}`);
    return response;
  };
  const month = (d) => `${d.getUTCFullYear()}-${["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][d.getUTCMonth()]}`;

  return {
    /**
     * Reads every source; returns what each found, and records the exploited CVEs.
     * @param {{ log?: (line: string) => void }} [options]
     */
    async sync({ log = () => {} } = {}) {
      const last = settings.get("advisories_last") ?? null;
      const results = { exploited: [], errors: [], research: [] };
      const run = async (name, work) => { try { const found = await work(); results.exploited.push(...found); log(`${name}: ${found.length} exploited.`); } catch (error) { results.errors.push(`${name}: ${error.message}`); } };

      await run("Chrome Releases", async () => parseChromeFeed(await (await get(advisoryUrls.chrome)).text()));
      await run("Apple", async () => {
        const since = last?.at ? last.at.slice(0, 10) : new Date(now().getTime() - 45 * 86_400_000).toISOString().slice(0, 10);
        const releases = parseAppleIndex(await (await get(advisoryUrls.apple)).text()).filter((r) => r.at && r.at >= since).slice(0, 15);
        const found = [];
        for (const r of releases) found.push(...parseAppleRelease(await (await get(r.url)).text(), r));
        return found;
      });
      await run("Microsoft", async () => {
        const months = last ? [month(now())] : [month(now()), month(new Date(Date.UTC(now().getUTCFullYear(), now().getUTCMonth() - 1, 1)))];
        const found = [];
        for (const m of months) {
          const response = await fetchImpl(advisoryUrls.msrc(m), { headers: { "user-agent": `TheySpy/${productVersion}`, accept: "application/json" }, signal: AbortSignal.timeout(180_000) });
          if (response.status === 404) continue; // the month's release is not out yet
          if (!response.ok) throw new Error(`MSRC answered ${response.status}`);
          found.push(...parseMsrc(await response.json(), m));
        }
        return found;
      });
      for (const [source, url] of advisoryUrls.research) {
        try { results.research.push(...parseRss(await (await get(url)).text(), source)); } catch (error) { results.errors.push(`${source}: ${error.message}`); }
      }
      const added = cves.markExploited(results.exploited);
      settings.set("advisories_last", { at: now().toISOString(), exploited: results.exploited.length, added: added.length, errors: results.errors });
      if (results.research.length) settings.set("research_reports", results.research);
      return { ...results, added };
    },
    research: () => settings.get("research_reports") ?? [],
    status: () => settings.get("advisories_last") ?? null,
  };
}
