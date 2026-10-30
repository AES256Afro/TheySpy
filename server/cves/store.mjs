import { productVersion } from "../shared.mjs";
import { createNvdKey, feedUrls, nvdDate, parseEpss, parseKev, parseNvdCve } from "./feeds.mjs";

// The CVE aggregator (docs/PLAN.md M5): NVD for descriptions, scores and CPE criteria; CISA KEV for
// what is known to be exploited (which flags a zero-day); FIRST EPSS for how likely exploitation is.
// One row per CVE; events record what changed after the first load (a KEV addition above all).

const day = 86_400_000;
const nvdWindowDays = 120; // NVD's largest lastMod window
// NVD allows 2,000 a page; a thousand halves each download, and slow pages were what stopped the first load.
const nvdPageSize = 1000;

/**
 * @param {{
 *   db: import("node:sqlite").DatabaseSync,
 *   settings: ReturnType<typeof import("../db.mjs").createSettingsStore>,
 *   audit: ReturnType<typeof import("../audit.mjs").createAuditLog>,
 *   fetchImpl?: typeof fetch,
 *   now?: () => Date,
 *   nvdApiKey?: string | null,
 *   nvdKey?: ReturnType<typeof import("./feeds.mjs").createNvdKey>,
 *   sleep?: (ms: number) => Promise<void>,
 * }} deps
 */
export function createCveStore({ db, settings, audit, fetchImpl = fetch, now = () => new Date(), nvdApiKey = null, nvdKey = createNvdKey({ apiKey: nvdApiKey, settings, audit, now }), sleep = (ms) => new Promise((r) => setTimeout(r, ms)) }) {
  const q = {
    get: db.prepare("SELECT * FROM cves WHERE cve_id = ?"),
    exists: db.prepare("SELECT kev, epss FROM cves WHERE cve_id = ?"),
    insertNvd: db.prepare(`INSERT INTO cves (cve_id, published, modified, status, description, cvss_score, cvss_severity, cvss_vector, cwes, products, cpe_matches, sources, first_seen, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
    updateNvd: db.prepare(`UPDATE cves SET published = ?, modified = ?, status = ?, description = ?, cvss_score = ?, cvss_severity = ?, cvss_vector = ?, cwes = ?,
      products = CASE WHEN ? = '[]' THEN products ELSE ? END, cpe_matches = ?, sources = json_set(sources, '$.nvd', ?), updated_at = ? WHERE cve_id = ?`),
    insertKev: db.prepare(`INSERT INTO cves (cve_id, description, cwes, products, kev, kev_added, kev_due, kev_ransomware, kev_name, kev_action, zero_day, zero_day_sources, sources, first_seen, updated_at)
      VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`),
    updateKev: db.prepare(`UPDATE cves SET kev = 1, kev_added = ?, kev_due = ?, kev_ransomware = ?, kev_name = ?, kev_action = ?, zero_day = 1, zero_day_sources = ?,
      description = COALESCE(description, ?), products = CASE WHEN products = '[]' AND ? IS NOT NULL THEN json_array(?) ELSE products END,
      sources = json_set(sources, '$.kev', ?), updated_at = ? WHERE cve_id = ?`),
    epss: db.prepare("UPDATE cves SET epss = ?, epss_percentile = ? WHERE cve_id = ? AND (epss IS NULL OR abs(epss - ?) >= 0.0005)"),
    zeroDayOf: db.prepare("SELECT zero_day, zero_day_sources FROM cves WHERE cve_id = ?"),
    markZeroDay: db.prepare("UPDATE cves SET zero_day = 1, zero_day_sources = ?, updated_at = ? WHERE cve_id = ?"),
    insertReported: db.prepare(`INSERT INTO cves (cve_id, description, zero_day, zero_day_sources, sources, first_seen, updated_at) VALUES (?, ?, 1, ?, ?, ?, ?)`),
    ids: db.prepare("SELECT cve_id FROM cves"),
    event: db.prepare("INSERT INTO cve_events (cve_id, at, kind, detail) VALUES (?, ?, ?, ?)"),
    events: db.prepare("SELECT at, kind, detail FROM cve_events WHERE cve_id = ? ORDER BY at DESC LIMIT 50"),
    recentEvents: db.prepare("SELECT e.cve_id, e.at, e.kind, e.detail, c.kev_name, c.description FROM cve_events e JOIN cves c ON c.cve_id = e.cve_id ORDER BY e.at DESC, e.id DESC LIMIT ?"),
    counts: db.prepare(`SELECT COUNT(*) AS total, SUM(kev) AS kev, SUM(zero_day) AS zero_day, SUM(CASE WHEN epss >= 0.5 THEN 1 ELSE 0 END) AS epss_high,
      SUM(CASE WHEN kev_added >= ? THEN 1 ELSE 0 END) AS kev_recent FROM cves`),
  };
  const transaction = (work) => {
    db.exec("BEGIN");
    try { const r = work(); db.exec("COMMIT"); return r; } catch (error) { db.exec("ROLLBACK"); throw error; }
  };
  const status = (feed) => settings.get(`cve_feed_${feed}`) ?? null;
  const setStatus = (feed, value) => settings.set(`cve_feed_${feed}`, { ...status(feed), ...value });
  // A feed that worked is not shown as failing, whichever job ran it (the first-start load, a
  // schedule, or Update now): an old error stayed on the CVEs screen after a good run.
  const succeeded = (feed) => settings.delete(`cve_feed_${feed}_error`);
  const headers = (extra = {}) => ({ "user-agent": `TheySpy/${productVersion} (+https://github.com/AES256Afro/TheySpy)`, ...extra });

  async function get(url, init = {}, { attempts = 4 } = {}) {
    for (let attempt = 1; ; attempt += 1) {
      let response;
      try {
        response = await fetchImpl(url, { ...init, redirect: "follow", signal: AbortSignal.timeout(120_000) });
      } catch (error) {
        if (attempt >= attempts) throw new Error(`Could not reach ${new URL(url).host}: ${error.cause?.code ?? error.message}`, { cause: error });
        await sleep(10_000 * attempt);
        continue;
      }
      // NVD answers 403 or 503 when rate-limited or busy; wait and try again.
      if ((response.status === 403 || response.status === 429 || response.status >= 500) && attempt < attempts) { await sleep(30_000 * attempt); continue; }
      return response;
    }
  }

  /**
   * One page of NVD, read whole. A page of a thousand CVEs is a few megabytes and NVD is sometimes
   * slow to send it; a body cut off by the timeout is fetched again (four tries) rather than ending
   * the run. A refused API key is set aside and the page fetched without it.
   */
  async function nvdPage(url, log) {
    for (let attempt = 1; ; attempt += 1) {
      try {
        const withKey = nvdKey.current();
        let response = await get(url, { headers: headers(withKey ? { apiKey: withKey } : {}) });
        if (withKey && nvdKey.refused(response)) {
          log("NVD refused the API key; carrying on without it (slower). Check the key in TheySpy's settings.");
          await sleep(nvdKey.pause());
          response = await get(url, { headers: headers() });
        }
        if (!response.ok) throw Object.assign(new Error(`NVD answered ${response.status}${response.status === 403 ? " (rate limited; an API key raises the limit)" : ""}`), { final: true });
        return /** @type {any} */ (await response.json());
      } catch (error) {
        if (error.final || attempt >= 4) throw error;
        log(`An NVD page was slow or cut off (${error.message}); fetching it again.`);
        await sleep(15_000 * attempt);
      }
    }
  }

  const store = {
    /** @param {ReturnType<typeof parseNvdCve>[]} rows @param {{ announce?: boolean }} [options] */
    upsertNvd(rows, { announce = true } = {}) {
      const at = now().toISOString();
      let added = 0;
      transaction(() => {
        for (const r of rows) {
          const cwes = JSON.stringify(r.cwes);
          const products = JSON.stringify(r.products);
          const matches = JSON.stringify(r.cpeMatches);
          if (q.exists.get(r.cveId)) {
            q.updateNvd.run(r.published, r.modified, r.status, r.description, r.cvssScore, r.cvssSeverity, r.cvssVector, cwes, products, products, matches, r.modified ?? at, at, r.cveId);
          } else {
            q.insertNvd.run(r.cveId, r.published, r.modified, r.status, r.description, r.cvssScore, r.cvssSeverity, r.cvssVector, cwes, products, matches, JSON.stringify({ nvd: r.modified ?? at }), at, at);
            added += 1;
            if (announce) q.event.run(r.cveId, at, "new", JSON.stringify({ cvss: r.cvssScore, severity: r.cvssSeverity }));
          }
        }
      });
      return { added, updated: rows.length - added };
    },

    /** Applies the KEV catalog; returns the CVEs it newly marks as known exploited. */
    applyKev(parsed) {
      const at = now().toISOString();
      const firstLoad = !status("kev");
      const added = [];
      transaction(() => {
        for (const e of parsed.entries) {
          const existing = /** @type {any} */ (q.exists.get(e.cveId));
          const zeroDay = JSON.stringify([{ source: "CISA KEV", at: e.added, note: e.ransomware ? "used in ransomware campaigns" : null }]);
          if (existing) q.updateKev.run(e.added, e.due, e.ransomware ? 1 : 0, e.name, e.action, zeroDay, e.description, e.product, e.product, parsed.version ?? at, at, e.cveId);
          else q.insertKev.run(e.cveId, e.description, JSON.stringify(e.cwes), JSON.stringify(e.product ? [e.product] : []), e.added, e.due, e.ransomware ? 1 : 0, e.name, e.action, zeroDay, JSON.stringify({ kev: parsed.version ?? at }), at, at);
          if (!existing?.kev && !firstLoad) {
            added.push(e.cveId);
            q.event.run(e.cveId, at, "kev_added", JSON.stringify({ name: e.name, due: e.due, ransomware: e.ransomware }));
          }
        }
      });
      if (added.length) audit.record("system", "cves.kev_added", null, { cves: added.slice(0, 50), count: added.length });
      return added;
    },

    /** Applies EPSS scores to the CVEs in the store. */
    applyEpss(scores) {
      let updated = 0;
      transaction(() => {
        for (const raw of q.ids.all()) {
          const id = /** @type {any} */ (raw).cve_id;
          const s = scores.get(id);
          if (s && Number(q.epss.run(s.epss, s.percentile, id, s.epss).changes)) updated += 1;
        }
      });
      return updated;
    },

    /**
     * Records vendor and research reports that a CVE was exploited: a zero-day source beside KEV.
     * Returns the CVEs newly flagged (announced unless this is the first time the reports are read).
     * @param {{ cveId: string, source: string, at: string | null, url: string | null, note: string }[]} reports
     */
    markExploited(reports) {
      const at = now().toISOString();
      const firstLoad = !settings.get("advisories_last");
      const added = [];
      transaction(() => {
        for (const r of reports) {
          const existing = /** @type {any} */ (q.zeroDayOf.get(r.cveId));
          const entry = { source: r.source, at: r.at, note: r.note, url: r.url };
          if (!existing) {
            q.insertReported.run(r.cveId, r.note, JSON.stringify([entry]), JSON.stringify({ [r.source]: r.at ?? at }), at, at);
          } else {
            const list = JSON.parse(existing.zero_day_sources);
            if (list.some((s) => s.source === r.source)) continue;
            q.markZeroDay.run(JSON.stringify([...list, entry]), at, r.cveId);
            if (existing.zero_day) continue; // already flagged (KEV or another vendor): no news
          }
          added.push(r.cveId);
          if (!firstLoad) q.event.run(r.cveId, at, "exploited_reported", JSON.stringify({ source: r.source, note: r.note }));
        }
      });
      if (added.length && !firstLoad) audit.record("system", "cves.zero_day_reported", null, { cves: added.slice(0, 50), count: added.length, sources: [...new Set(reports.filter((r) => added.includes(r.cveId)).map((r) => r.source))] });
      return added;
    },

    /**
     * Fetches the KEV catalog (unless unchanged) and applies it.
     * @param {{ log?: (line: string) => void }} [options] */
    async syncKev({ log = () => {} } = {}) {
      const previous = status("kev");
      const response = await get(feedUrls.kev, { headers: headers(previous?.etag ? { "if-none-match": previous.etag } : {}) });
      if (response.status === 304) { setStatus("kev", { at: now().toISOString(), changed: false }); succeeded("kev"); log("CISA KEV: unchanged."); return { changed: false, added: [] }; }
      if (!response.ok) throw new Error(`CISA KEV answered ${response.status}`);
      const parsed = parseKev(await response.text());
      const added = store.applyKev(parsed);
      setStatus("kev", { at: now().toISOString(), etag: response.headers.get("etag"), version: parsed.version, count: parsed.entries.length, added: added.length, changed: true });
      succeeded("kev");
      log(`CISA KEV ${parsed.version}: ${parsed.entries.length} known exploited${added.length ? `, ${added.length} new: ${added.slice(0, 5).join(", ")}` : ""}.`);
      return { changed: true, added };
    },

    /** @param {{ log?: (line: string) => void }} [options] */
    async syncEpss({ log = () => {} } = {}) {
      const response = await get(feedUrls.epss, { headers: headers() });
      if (!response.ok) throw new Error(`EPSS answered ${response.status}`);
      const { scoreDate, scores } = parseEpss(Buffer.from(await response.arrayBuffer()));
      if (scores.size < 100_000) throw new Error(`The EPSS file looked wrong (${scores.size} scores)`);
      const updated = store.applyEpss(scores);
      setStatus("epss", { at: now().toISOString(), scoreDate, scores: scores.size, updated });
      succeeded("epss");
      log(`EPSS ${scoreDate}: ${scores.size.toLocaleString()} scores; ${updated} changed here.`);
      return { scoreDate, updated };
    },

    /**
     * Fetches what NVD changed since the last run (or the last `days` on the first), in windows of
     * at most 120 days and pages of 2,000, pausing between requests as NVD asks.
     * @param {{ days?: number, log?: (line: string) => void }} [options]
     */
    async syncNvd({ days = nvdWindowDays, log = () => {} } = {}) {
      const previous = status("nvd");
      const end = now();
      // A run that stopped part-way (a slow page, a restart) resumes where it was: the same window
      // from the same page. The first load on BigBox started over from nothing each time and, with
      // one slow page in every hundred, never finished.
      const resume = previous?.progress?.window?.length === 2 ? previous.progress : null;
      let start = resume ? new Date(resume.window[0]) : previous?.through ? new Date(Date.parse(previous.through) - 5 * 60_000) : new Date(end.getTime() - days * day);
      let windowEnd = resume ? new Date(resume.window[1]) : null;
      let index = resume ? Math.max(0, Number(resume.done) || 0) : 0;
      if (resume) log(`Resuming NVD at ${index.toLocaleString()} of ${Number(resume.total ?? 0).toLocaleString()} (${resume.window[0].slice(0, 10)} → ${resume.window[1].slice(0, 10)}).`);
      const announce = Boolean(previous?.through);
      let fetched = 0;
      let added = 0;
      let requests = 0;
      while (start < end) {
        windowEnd ??= new Date(Math.min(end.getTime(), start.getTime() + nvdWindowDays * day));
        for (let total = index + 1; index < total; index += nvdPageSize) {
          if (requests++) await sleep(nvdKey.pause());
          const url = `${feedUrls.nvd}?lastModStartDate=${encodeURIComponent(nvdDate(start))}&lastModEndDate=${encodeURIComponent(nvdDate(windowEnd))}&startIndex=${index}&resultsPerPage=${nvdPageSize}`;
          const page = await nvdPage(url, log);
          total = Number(page.totalResults ?? 0);
          const rows = (page.vulnerabilities ?? []).map((v) => parseNvdCve(v.cve)).filter((r) => r.cveId);
          added += store.upsertNvd(rows, { announce }).added;
          fetched += rows.length;
          const done = Math.min(index + nvdPageSize, total);
          log(`NVD ${start.toISOString().slice(0, 10)} → ${windowEnd.toISOString().slice(0, 10)}: ${done.toLocaleString()} of ${total.toLocaleString()}.`);
          setStatus("nvd", { at: now().toISOString(), progress: { window: [start.toISOString(), windowEnd.toISOString()], done, total } });
        }
        start = windowEnd;
        windowEnd = null;
        index = 0;
      }
      setStatus("nvd", { at: now().toISOString(), through: end.toISOString(), fetched, added, progress: null });
      succeeded("nvd");
      return { fetched, added };
    },

    /**
     * A page of CVEs, exploited first.
     * @param {{ kev?: boolean, zeroDay?: boolean, minEpss?: number, q?: string, product?: string, severity?: string, limit?: number, offset?: number }} [filters]
     */
    list(filters = {}) {
      const where = [];
      const params = [];
      if (filters.kev) where.push("kev = 1");
      if (filters.zeroDay) where.push("zero_day = 1");
      if (filters.minEpss) { where.push("epss >= ?"); params.push(filters.minEpss); }
      if (filters.severity) { where.push("cvss_severity = ?"); params.push(filters.severity); }
      if (filters.product) { where.push("products LIKE ?"); params.push(`%${filters.product.toLowerCase().replace(/[%_]/g, "")}%`); }
      if (filters.q) {
        const term = filters.q.trim();
        if (/^CVE-\d{4}-\d+$/i.test(term)) { where.push("cve_id = ?"); params.push(term.toUpperCase()); }
        else { where.push("(description LIKE ? OR kev_name LIKE ? OR products LIKE ?)"); params.push(`%${term}%`, `%${term}%`, `%${term.toLowerCase()}%`); }
      }
      const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
      const total = Number(/** @type {any} */ (db.prepare(`SELECT COUNT(*) AS n FROM cves ${clause}`).get(...params)).n);
      const limit = Math.min(Math.max(Number(filters.limit ?? 50), 1), 200);
      const rows = db.prepare(`SELECT * FROM cves ${clause} ORDER BY kev DESC, kev_added DESC, COALESCE(epss, 0) DESC, published DESC LIMIT ? OFFSET ?`)
        .all(...params, limit, Math.max(Number(filters.offset ?? 0), 0)).map(present);
      return { total, rows };
    },
    get(id) {
      const row = q.get.get(String(id).toUpperCase());
      if (!row) return null;
      return { ...present(row), cpeMatches: JSON.parse(/** @type {any} */ (row).cpe_matches), events: q.events.all(String(id).toUpperCase()).map((e) => ({ ...(/** @type {any} */ (e)), detail: JSON.parse(/** @type {any} */ (e).detail) })) };
    },
    recentEvents: (limit = 20) => q.recentEvents.all(limit).map((raw) => {
      const e = /** @type {any} */ (raw);
      return { cveId: e.cve_id, at: e.at, kind: e.kind, detail: JSON.parse(e.detail), title: e.kev_name ?? e.description?.slice(0, 120) ?? null };
    }),
    stats() {
      const c = /** @type {any} */ (q.counts.get(new Date(now().getTime() - 7 * day).toISOString().slice(0, 10)));
      return { total: Number(c.total ?? 0), kev: Number(c.kev ?? 0), zeroDays: Number(c.zero_day ?? 0), epssHigh: Number(c.epss_high ?? 0), kevThisWeek: Number(c.kev_recent ?? 0), feeds: { kev: status("kev"), nvd: status("nvd"), epss: status("epss") }, errors: Object.fromEntries(["kev", "nvd", "epss", "advisories", "first"].map((feed) => [feed, settings.get(`cve_feed_${feed}_error`) ?? null]).filter(([, value]) => value)), apiKey: nvdKey.configured, nvdKey: nvdKey.status() };
    },
  };

  function present(row) {
    const r = /** @type {any} */ (row);
    return {
      cveId: r.cve_id, published: r.published, modified: r.modified, status: r.status, description: r.description,
      cvss: r.cvss_score, severity: r.cvss_severity, vector: r.cvss_vector, cwes: JSON.parse(r.cwes), products: JSON.parse(r.products),
      kev: r.kev ? { added: r.kev_added, due: r.kev_due, ransomware: Boolean(r.kev_ransomware), name: r.kev_name, action: r.kev_action } : null,
      epss: r.epss, epssPercentile: r.epss_percentile, zeroDay: Boolean(r.zero_day), zeroDaySources: JSON.parse(r.zero_day_sources), sources: JSON.parse(r.sources),
    };
  }
  return store;
}

/**
 * @param {ReturnType<typeof createCveStore>} store
 * @param {ReturnType<typeof import("./advisories.mjs").createAdvisories>} [advisories]
 */
export function cveJobKinds(store, advisories) {
  return {
    "cves.update": {
      title: "Update CVEs (CISA KEV, NVD, EPSS)",
      direct: true,
      async run({ log }) {
        const kev = await store.syncKev({ log });
        const nvd = await store.syncNvd({ log });
        const epss = await store.syncEpss({ log });
        const reported = advisories ? await advisories.sync({ log }) : null;
        return { kevAdded: kev.added.length, nvdFetched: nvd.fetched, epssUpdated: epss.updated, vendorReported: reported?.added.length ?? 0 };
      },
    },
  };
}
