import { createHash, randomBytes } from "node:crypto";
import { gunzipSync, gzipSync } from "node:zlib";
import { blocklistDomains } from "../iocs/exports.mjs";
import { productVersion } from "../shared.mjs";
import { listName, readAdguard, readFilterLists, readFirebog, resolveFilterListsUrl } from "./directories.mjs";
import { neverBlock, parseBlocklist, canonical } from "./parse.mjs";
import { categories, categoryIds, securityCategories } from "./taxonomy.mjs";

const maxBytes = 50 * 1024 * 1024;
const staleDays = 180;
const deadAfterFailures = 3;
const sizeJump = 0.5;

// The lists a new install starts with: TheySpy's own zero-breach set plus AdGuard-rehosted security
// lists and one balanced ad/tracker list, all low on false positives. Stricter lists are seeded as
// candidates so baselines can use them. The URLs are AdGuard HostlistsRegistry's own rehosts.
const registry = (id) => `https://adguardteam.github.io/HostlistsRegistry/assets/filter_${id}.txt`;
const starter = [
  { key: "builtin:zero-breach", directory: "builtin", name: "zero-breach AdFection / Candiru", description: "The active indicator set's reviewed domains (Indicators screen), as zero-breach exports them.", url: null, homepage: "https://github.com/interplains/zero-breach", license: "CC0-1.0", categories: ["spyware"], status: "enabled" },
  { key: "adguard:staklerware_indicators_list", name: "Stalkerware Indicators List", url: registry(31), homepage: "https://github.com/AssoEchap/stalkerware-indicators", categories: ["spyware"], status: "enabled" },
  { key: "adguard:hagezi_threat_intelligence_feeds", name: "HaGeZi's Threat Intelligence Feeds", url: registry(44), homepage: "https://github.com/hagezi/dns-blocklists", categories: ["malware", "phishing"], status: "enabled" },
  { key: "adguard:urlhaus_filter_online", name: "Malicious URL Blocklist (URLHaus)", url: registry(11), homepage: "https://urlhaus.abuse.ch/", categories: ["malware"], status: "enabled" },
  { key: "adguard:phishing_army", name: "Phishing Army", url: registry(18), homepage: "https://phishing.army/", categories: ["phishing"], status: "enabled" },
  { key: "adguard:nocoin_filter_list", name: "NoCoin Filter List", url: registry(8), homepage: "https://github.com/hoshsadiq/adblock-nocoin-list/", categories: ["cryptomining"], status: "enabled" },
  { key: "adguard:hagezi_multinormal", name: "HaGeZi's Normal Blocklist", url: registry(34), homepage: "https://github.com/hagezi/dns-blocklists", categories: ["ads", "trackers"], status: "enabled" },
  { key: "adguard:hagezi_pro", name: "HaGeZi's Pro Blocklist", url: registry(48), homepage: "https://github.com/hagezi/dns-blocklists", categories: ["ads", "trackers", "telemetry"], status: "candidate" },
  { key: "adguard:hagezi_pro++", name: "HaGeZi's Pro++ Blocklist", url: registry(51), homepage: "https://github.com/hagezi/dns-blocklists", categories: ["ads", "trackers", "telemetry"], status: "candidate" },
  { key: "adguard:hagezi_encrypted_dns_vpn_tor_proxy_bypass", name: "HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass", url: registry(52), homepage: "https://github.com/hagezi/dns-blocklists#bypass", categories: ["bypass"], status: "candidate" },
  { key: "adguard:hagezi_dyndns_blocklist", name: "HaGeZi's DynDNS Blocklist", url: registry(54), homepage: "https://github.com/hagezi/dns-blocklists", categories: ["nrd"], status: "candidate" },
  { key: "adguard:perflyst_dandelion_sprout_smart_tv_blocklist_for_adguard_home", name: "Perflyst and Dandelion Sprout's Smart-TV Blocklist", url: registry(7), homepage: "https://github.com/Perflyst/PiHoleBlocklist", categories: ["telemetry"], status: "candidate" },
  { key: "adguard:oisd_full", name: "OISD Blocklist Big", url: registry(27), homepage: "https://oisd.nl/", categories: ["ads", "trackers", "malware"], status: "candidate" },
  { key: "adguard:hagezi_gambling_blocklist", name: "HaGeZi's Gambling Blocklist", url: registry(47), homepage: "https://github.com/hagezi/dns-blocklists", categories: ["gambling"], status: "candidate" },
];

const pack = (domains) => gzipSync(Buffer.from([...domains].sort().join("\n"), "utf8"));
const unpack = (blob) => {
  const text = gunzipSync(blob).toString("utf8");
  return text ? text.split("\n") : [];
};
const digest = (domains) => createHash("sha256").update([...domains].sort().join("\n")).digest("hex");

async function readCapped(response) {
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (declared > maxBytes) throw new Error(`list is ${declared} bytes; the limit is ${maxBytes}`);
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) { await reader.cancel(); throw new Error(`list is larger than ${maxBytes} bytes`); }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * The blocklist library (docs/PLAN.md §6.1): discovers lists, fetches and versions the enabled ones
 * behind poisoning and breakage gates, and compiles categories into the lists Pi-hole subscribes to.
 * @param {{
 *   db: import("node:sqlite").DatabaseSync,
 *   settings: ReturnType<typeof import("../db.mjs").createSettingsStore>,
 *   audit: ReturnType<typeof import("../audit.mjs").createAuditLog>,
 *   iocStore: ReturnType<typeof import("../iocs/store.mjs").createIocStore>,
 *   fetchImpl?: typeof fetch,
 *   popular?: () => Promise<string[]>,
 *   now?: () => Date,
 * }} deps popular: the names the network looks up most (Pi-hole's top domains), kept off every list
 */
export function createBlocklistLibrary({ db, settings, audit, iocStore, fetchImpl = fetch, popular, now = () => new Date() }) {
  const q = {
    count: db.prepare("SELECT COUNT(*) AS n FROM blocklist_sources"),
    byKey: db.prepare("SELECT * FROM blocklist_sources WHERE key = ?"),
    byId: db.prepare("SELECT * FROM blocklist_sources WHERE id = ?"),
    insert: db.prepare("INSERT INTO blocklist_sources (key, directory, name, description, url, homepage, license, syntax, categories, curated, status, deprecated, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
    refresh: db.prepare("UPDATE blocklist_sources SET name = ?, description = ?, url = COALESCE(?, url), homepage = COALESCE(?, homepage), license = COALESCE(?, license), syntax = COALESCE(?, syntax), curated = ?, deprecated = ? WHERE id = ?"),
    enabled: db.prepare("SELECT * FROM blocklist_sources WHERE status = 'enabled' ORDER BY id"),
    list: db.prepare("SELECT s.*, v.count AS entries FROM blocklist_sources s LEFT JOIN blocklist_versions v ON v.id = s.active_version_id WHERE s.status != 'candidate' OR ? ORDER BY s.status = 'enabled' DESC, s.name COLLATE NOCASE"),
    candidates: db.prepare("SELECT * FROM blocklist_sources WHERE status = 'candidate' ORDER BY curated DESC, name COLLATE NOCASE"),
    setStatus: db.prepare("UPDATE blocklist_sources SET status = ? WHERE id = ?"),
    setCategories: db.prepare("UPDATE blocklist_sources SET categories = ? WHERE id = ?"),
    setUrl: db.prepare("UPDATE blocklist_sources SET url = ?, homepage = COALESCE(?, homepage) WHERE id = ?"),
    checked: db.prepare("UPDATE blocklist_sources SET last_checked_at = ?, etag = ?, last_modified = ?, failures = 0, last_error = NULL WHERE id = ?"),
    changed: db.prepare("UPDATE blocklist_sources SET last_changed_at = ?, active_version_id = ? WHERE id = ?"),
    failed: db.prepare("UPDATE blocklist_sources SET last_checked_at = ?, failures = failures + 1, last_error = ? WHERE id = ?"),
    version: db.prepare("SELECT * FROM blocklist_versions WHERE id = ?"),
    versionMeta: db.prepare("SELECT id, source_id, status, sha256, count, added, removed, sample, reasons, fetched_at, decided_at, decided_by FROM blocklist_versions WHERE id = ?"),
    insertVersion: db.prepare("INSERT INTO blocklist_versions (source_id, status, sha256, count, added, removed, sample, reasons, domains, fetched_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
    decide: db.prepare("UPDATE blocklist_versions SET status = ?, decided_at = ?, decided_by = ? WHERE id = ?"),
    supersede: db.prepare("UPDATE blocklist_versions SET status = 'superseded' WHERE source_id = ? AND status = 'active' AND id != ?"),
    quarantined: db.prepare("SELECT v.id, v.source_id, v.count, v.added, v.removed, v.sample, v.reasons, v.fetched_at, s.name FROM blocklist_versions v JOIN blocklist_sources s ON s.id = v.source_id WHERE v.status = 'quarantined' ORDER BY v.id DESC"),
    pruneOld: db.prepare("DELETE FROM blocklist_versions WHERE source_id = ? AND status IN ('superseded', 'rejected') AND id NOT IN (SELECT id FROM blocklist_versions WHERE source_id = ? AND status IN ('superseded', 'rejected') ORDER BY id DESC LIMIT 2)"),
  };

  const row = (r) => r && {
    id: Number(r.id), key: r.key, directory: r.directory, name: r.name, description: r.description, url: r.url, homepage: r.homepage, license: r.license, syntax: r.syntax,
    categories: JSON.parse(r.categories), curated: Boolean(r.curated), status: r.status, deprecated: Boolean(r.deprecated),
    discoveredAt: r.discovered_at, lastCheckedAt: r.last_checked_at, lastChangedAt: r.last_changed_at, failures: Number(r.failures), lastError: r.last_error,
    activeVersionId: r.active_version_id === null ? null : Number(r.active_version_id), entries: r.entries === undefined || r.entries === null ? null : Number(r.entries),
  };
  const health = (s) => {
    if (s.failures >= deadAfterFailures) return "dead";
    if (s.deprecated) return "deprecated";
    if (s.lastChangedAt && now().getTime() - Date.parse(s.lastChangedAt) > staleDays * 86400_000) return "stale";
    if (s.status === "enabled" && !s.activeVersionId && s.directory !== "builtin") return "not fetched";
    return "ok";
  };

  function upsert(c, status = "candidate") {
    const existing = /** @type {any} */ (q.byKey.get(c.key));
    if (existing) {
      q.refresh.run(c.name, c.description ?? null, c.url ?? null, c.homepage ?? null, c.license ?? null, c.syntax ?? null, c.curated ? 1 : 0, c.deprecated ? 1 : 0, existing.id);
      return { id: Number(existing.id), created: false };
    }
    const { lastInsertRowid } = q.insert.run(c.key, c.directory, c.name, c.description ?? null, c.url ?? null, c.homepage ?? null, c.license ?? null, c.syntax ?? null, JSON.stringify(c.categories), c.curated ? 1 : 0, status, c.deprecated ? 1 : 0, now().toISOString());
    return { id: Number(lastInsertRowid), created: true };
  }

  // --- never-block -------------------------------------------------------------------------------
  /** Built-in names, the owner's pins, and the sites the network uses most (from Pi-hole, if known). */
  function neverBlockSet() {
    const pins = settings.get("blocklists_pins") ?? [];
    const popular = settings.get("blocklists_popular") ?? [];
    return new Set([...neverBlock, ...pins, ...popular]);
  }

  // --- compiled lists ----------------------------------------------------------------------------
  // Big lists run to millions of names (HaGeZi's threat feed alone is about two million), so only
  // the three most recently requested compilations stay in memory, and the per-category counts the
  // screen shows are kept as numbers, worked out once after each change.
  const cacheSize = 3;
  // Pi-hole fetches a subscribed list about once a week (gravity), so a very large compilation is
  // rebuilt on request (about a second) rather than held in memory between requests.
  const cacheLimit = 500_000;
  let cache = new Map();
  let counts = null;
  const invalidate = () => { cache = new Map(); counts = null; };
  function domainsOf(source) {
    if (source.directory === "builtin") {
      const set = iocStore.activeSet();
      return set ? blocklistDomains(set) : [];
    }
    if (!source.active_version_id) return [];
    const v = /** @type {any} */ (q.version.get(source.active_version_id));
    return v ? unpack(v.domains) : [];
  }

  const library = {
    /** First start: the built-in and starter lists. */
    seed() {
      if (Number(/** @type {any} */ (q.count.get()).n) > 0) return false;
      for (const s of starter) upsert({ directory: "adguard", syntax: "adblock", license: null, description: null, ...s }, s.status);
      audit.record("system", "blocklists.seeded", null, { enabled: starter.filter((s) => s.status === "enabled").length, candidates: starter.filter((s) => s.status === "candidate").length });
      return true;
    },

    get: (id) => row(q.byId.get(id)),
    sources: ({ includeCandidates = false } = {}) => q.list.all(includeCandidates ? 1 : 0).map((r) => { const s = row(r); return { ...s, health: health(s) }; }),
    candidates: () => q.candidates.all().map(row),
    quarantined: () => q.quarantined.all().map((r) => {
      const v = /** @type {any} */ (r);
      return { id: Number(v.id), sourceId: Number(v.source_id), name: v.name, count: Number(v.count), added: Number(v.added), removed: Number(v.removed), sample: JSON.parse(v.sample), reasons: JSON.parse(v.reasons), fetchedAt: v.fetched_at };
    }),
    versionMeta: (id) => {
      const v = /** @type {any} */ (q.versionMeta.get(id));
      return v && { id: Number(v.id), sourceId: Number(v.source_id), status: v.status, count: Number(v.count), added: Number(v.added), removed: Number(v.removed), sample: JSON.parse(v.sample), reasons: JSON.parse(v.reasons), fetchedAt: v.fetched_at };
    },

    /** Reads the directories and records lists not seen before as candidates. */
    async discover(actor = "system") {
      const results = { added: 0, seen: 0, errors: [] };
      /** @type {[string, (f: typeof fetch) => Promise<import("./directories.mjs").Candidate[]>][]} */
      const readers = [["AdGuard registry", readAdguard], ["FilterLists", readFilterLists], ["Firebog", readFirebog]];
      for (const [name, read] of readers) {
        try {
          for (const c of await read(fetchImpl)) {
            results.seen += 1;
            if (upsert(c).created) results.added += 1;
          }
        } catch (error) {
          results.errors.push(`${name}: ${error.message}`);
        }
      }
      settings.set("blocklists_last_discovery", { at: now().toISOString(), ...results });
      audit.record(actor, "blocklists.discovered", null, results);
      return results;
    },

    /** @param {number} id @param {"enabled" | "disabled" | "candidate"} status */
    async setStatus(id, status, actor) {
      const s = row(q.byId.get(id));
      if (!s) throw Object.assign(new Error("No such list"), { status: 404 });
      if (s.directory === "builtin" && status !== "enabled") throw Object.assign(new Error("The built-in zero-breach list stays on; it is the spyware set itself."), { status: 400 });
      if (status === "enabled" && !s.url && s.directory === "filterlists") {
        const resolved = await resolveFilterListsUrl(fetchImpl, s.key.split(":")[1]);
        if (!resolved.url) throw Object.assign(new Error("FilterLists gives no HTTPS download address for this list."), { status: 409 });
        q.setUrl.run(resolved.url, resolved.homepage, id);
      }
      q.setStatus.run(status, id);
      invalidate();
      audit.record(actor, `blocklists.${status}`, `blocklist:${id}`, { name: s.name });
      return library.get(id);
    },

    setCategories(id, list, actor) {
      const valid = [...new Set(list)].filter((c) => categoryIds.includes(c));
      if (!valid.length) throw Object.assign(new Error("Give at least one known category"), { status: 400 });
      q.setCategories.run(JSON.stringify(valid), id);
      invalidate();
      audit.record(actor, "blocklists.categories_changed", `blocklist:${id}`, { categories: valid });
      return library.get(id);
    },

    /** Adds a list by URL (enabled; fetched on the next update). */
    addCustom({ url, name, categories: cats }, actor) {
      let u;
      try { u = new URL(String(url)); } catch { u = null; }
      if (!u || u.protocol !== "https:" || u.username || u.password) throw Object.assign(new Error("The list address must be an https:// URL"), { status: 400 });
      const valid = (cats ?? []).filter((c) => categoryIds.includes(c));
      const { id, created } = upsert({ key: `custom:${u.href}`, directory: "custom", name: String(name || listName(u.href)).slice(0, 120), url: u.href, categories: valid.length ? valid : ["other"] }, "enabled");
      if (!created) q.setStatus.run("enabled", id);
      invalidate();
      audit.record(actor, "blocklists.custom_added", `blocklist:${id}`, { url: u.href });
      return library.get(id);
    },

    /** Records the names the network uses most, so no list update can take them away. */
    rememberPopular(domains) {
      const clean = [...new Set(domains.map(canonical).filter(Boolean))].slice(0, 300);
      settings.set("blocklists_popular", clean);
      return clean.length;
    },
    setPins(pins, actor) {
      const clean = [...new Set(pins.map(canonical).filter(Boolean))].slice(0, 500);
      settings.set("blocklists_pins", clean);
      invalidate();
      audit.record(actor, "blocklists.pins_changed", null, { count: clean.length });
      return clean;
    },
    pins: () => settings.get("blocklists_pins") ?? [],

    /** Fetches one enabled list; returns what happened to it. */
    async fetchOne(id, actor = "system") {
      const s = /** @type {any} */ (q.byId.get(id));
      if (!s || s.status !== "enabled" || s.directory === "builtin") return { id, outcome: "skipped" };
      try {
        const headers = { "user-agent": `TheySpy/${productVersion}` };
        if (s.etag && s.active_version_id) headers["if-none-match"] = s.etag;
        if (s.last_modified && s.active_version_id) headers["if-modified-since"] = s.last_modified;
        const response = await fetchImpl(s.url, { headers, redirect: "follow", signal: AbortSignal.timeout(60_000) });
        if (response.url && !response.url.startsWith("https://")) throw new Error("the list redirected away from HTTPS");
        if (response.status === 304) {
          q.checked.run(now().toISOString(), s.etag, s.last_modified, id);
          return { id, outcome: "unchanged" };
        }
        if (!response.ok) throw new Error(`the server answered ${response.status}`);
        const { domains } = parseBlocklist(await readCapped(response));
        if (!domains.size) throw new Error("the list has no usable domain entries");
        const sha = digest(domains);
        const previous = s.active_version_id ? /** @type {any} */ (q.version.get(s.active_version_id)) : null;
        q.checked.run(now().toISOString(), response.headers.get("etag"), response.headers.get("last-modified"), id);
        if (previous?.sha256 === sha) return { id, outcome: "unchanged" };
        const before = new Set(previous ? unpack(previous.domains) : []);
        const added = [...domains].filter((d) => !before.has(d));
        const removed = previous ? [...before].filter((d) => !domains.has(d)) : [];
        const reasons = [];
        if (previous && previous.count >= 100 && Math.abs(domains.size - previous.count) / previous.count > sizeJump) reasons.push(`size changed from ${previous.count} to ${domains.size} entries`);
        const protectedNames = neverBlockSet();
        const risky = added.filter((d) => protectedNames.has(d));
        if (previous && risky.length) reasons.push(`would newly block ${risky.length} protected name${risky.length === 1 ? "" : "s"}: ${risky.slice(0, 5).join(", ")}`);
        const status = reasons.length ? "quarantined" : "active";
        const sample = { added: added.slice(0, 50), removed: removed.slice(0, 50), risky: risky.slice(0, 50) };
        const versionId = Number(q.insertVersion.run(id, status, sha, domains.size, added.length, removed.length, JSON.stringify(sample), JSON.stringify(reasons), pack(domains), now().toISOString()).lastInsertRowid);
        if (status === "active") {
          q.supersede.run(id, versionId);
          q.changed.run(now().toISOString(), versionId, id);
          q.pruneOld.run(id, id);
          invalidate();
        } else {
          audit.record(actor, "blocklists.update_quarantined", `blocklist:${id}`, { name: s.name, reasons });
        }
        return { id, outcome: status === "active" ? (previous ? "updated" : "first") : "quarantined", count: domains.size, added: added.length, removed: removed.length, reasons };
      } catch (error) {
        q.failed.run(now().toISOString(), error.message, id);
        return { id, outcome: "failed", error: error.message };
      }
    },

    /**
     * Fetches every enabled list (or the ones given).
     * @param {{ ids?: number[], actor?: string }} [options]
     */
    async update({ ids, actor = "system" } = {}) {
      if (popular) {
        const names = await popular().catch(() => []);
        if (names.length) library.rememberPopular(names);
      }
      const targets = ids ?? q.enabled.all().map((r) => Number(/** @type {any} */ (r).id));
      const results = [];
      for (const id of targets) results.push(await library.fetchOne(id, actor));
      /** @type {Record<string, any>} */
      const summary = { at: now().toISOString(), lists: results.length, ...Object.fromEntries(["first", "updated", "unchanged", "quarantined", "failed"].map((k) => [k, results.filter((r) => r.outcome === k).length])) };
      settings.set("blocklists_last_update", summary);
      audit.record(actor, "blocklists.updated", null, summary);
      return { summary, results };
    },

    /** Accepts a quarantined version (it becomes active) or rejects it (the old one stays). */
    decide(versionId, accept, actor) {
      const v = /** @type {any} */ (q.version.get(versionId));
      if (!v || v.status !== "quarantined") throw Object.assign(new Error("Only a quarantined update can be accepted or rejected"), { status: 409 });
      if (accept) {
        q.decide.run("active", now().toISOString(), actor, versionId);
        q.supersede.run(v.source_id, versionId);
        q.changed.run(now().toISOString(), versionId, v.source_id);
        invalidate();
      } else {
        q.decide.run("rejected", now().toISOString(), actor, versionId);
      }
      audit.record(actor, accept ? "blocklists.update_accepted" : "blocklists.update_rejected", `blocklist-version:${versionId}`);
      return library.versionMeta(versionId);
    },

    /**
     * Every domain in the enabled lists of these categories, minus the never-block names.
     * @param {string[]} wanted category ids
     * @returns {{ domains: string[], sources: number, etag: string }}
     */
    compile(wanted, { remember = true } = {}) {
      const keyName = [...new Set(wanted)].sort().join(",");
      if (cache.has(keyName)) {
        const hit = cache.get(keyName);
        cache.delete(keyName);
        cache.set(keyName, hit); // most recently used last
        return hit;
      }
      const protectedNames = neverBlockSet();
      const out = new Set();
      let sources = 0;
      for (const r of q.enabled.all()) {
        const s = /** @type {any} */ (r);
        if (!JSON.parse(s.categories).some((c) => wanted.includes(c))) continue;
        sources += 1;
        for (const d of domainsOf(s)) if (!protectedNames.has(d)) out.add(d);
      }
      const domains = [...out].sort();
      const result = { domains, sources, etag: createHash("sha256").update(domains.join("\n")).digest("hex").slice(0, 32) };
      if (remember && domains.length <= cacheLimit) {
        cache.set(keyName, result);
        while (cache.size > cacheSize) cache.delete(cache.keys().next().value);
      }
      return result;
    },

    /**
     * Which enabled lists (and so categories) cover each looked-up name, either the name itself or
     * a parent of it, the way Pi-hole treats Adblock-style entries. Lists are read one at a time, so
     * a two-million-name list never sits in memory next to the others.
     * @param {string[]} names
     * @returns {Map<string, { categories: Set<string>, lists: Set<string> }>}
     */
    matchNames(names) {
      const bySuffix = new Map();
      for (const name of names) {
        const labels = name.split(".");
        for (let i = 0; i < labels.length - 1; i += 1) {
          const suffix = labels.slice(i).join(".");
          if (!bySuffix.has(suffix)) bySuffix.set(suffix, []);
          bySuffix.get(suffix).push(name);
        }
      }
      const protectedNames = neverBlockSet();
      const out = new Map();
      for (const r of q.enabled.all()) {
        const s = /** @type {any} */ (r);
        const cats = JSON.parse(s.categories);
        for (const d of domainsOf(s)) {
          const hit = bySuffix.get(d);
          if (!hit || protectedNames.has(d)) continue;
          for (const name of hit) {
            if (protectedNames.has(name)) continue;
            const e = out.get(name) ?? { categories: new Set(), lists: new Set() };
            for (const c of cats) e.categories.add(c);
            e.lists.add(s.name);
            out.set(name, e);
          }
        }
      }
      return out;
    },

    /** Turns on the lists a baseline needs; returns the ids that were newly enabled. */
    async ensureEnabled(keys, actor) {
      const ids = [];
      for (const key of keys) {
        const s = row(q.byKey.get(key));
        if (s && s.status !== "enabled") { await library.setStatus(s.id, "enabled", actor); ids.push(s.id); }
      }
      return ids;
    },

    /** How many domains and lists each category and each named list has, as numbers only. */
    counts() {
      if (counts) return counts;
      const of = (cats) => { const c = library.compile(cats, { remember: false }); return { domains: c.domains.length, lists: c.sources }; };
      counts = {
        categories: Object.fromEntries(categories.map((c) => [c.id, of([c.id])])),
        lists: Object.fromEntries(Object.entries(compiledLists).map(([id, l]) => [id, of(l.categories)])),
      };
      return counts;
    },

    /** Domains per category across enabled lists (for the screen). */
    categoryCounts() {
      const n = library.counts();
      return categories.map((c) => ({ ...c, ...n.categories[c.id] }));
    },

    /** The secret path segment Pi-hole uses to subscribe; created once. */
    listToken() {
      let token = settings.get("lists_token");
      if (!token) { token = randomBytes(18).toString("base64url"); settings.set("lists_token", token); }
      return token;
    },

    invalidate,
  };
  return library;
}

/** Named compiled lists Pi-hole can subscribe to, besides one per category. */
export const compiledLists = Object.freeze({
  security: { name: "Security", description: "Spyware, malware, phishing, cryptomining and newly registered or dynamic domains.", categories: securityCategories },
  recommended: { name: "Recommended", description: "Security plus ads and trackers.", categories: [...securityCategories, "ads", "trackers"] },
});

/** @param {ReturnType<typeof createBlocklistLibrary>} library */
export function blocklistJobKinds(library) {
  return {
    "blocklists.discover": {
      title: "Look for new blocklists",
      direct: true,
      async run({ log, actor }) {
        const r = await library.discover(actor);
        log(`Read ${r.seen} lists from the directories; ${r.added} not seen before.${r.errors.length ? ` Problems: ${r.errors.join("; ")}` : ""}`);
        return r;
      },
    },
    "blocklists.update": {
      title: "Update enabled blocklists",
      direct: true,
      async run({ log, actor, params }) {
        const { summary, results } = await library.update({ ids: params?.ids, actor });
        library.counts(); // work out the screen's numbers now, not on the next page load
        for (const r of results.filter((x) => x.outcome === "failed" || x.outcome === "quarantined")) log(`List ${r.id}: ${r.outcome}${r.error ? ` (${r.error})` : ""}${r.reasons?.length ? ` (${r.reasons.join("; ")})` : ""}`);
        log(`${summary.lists} lists: ${summary.first} fetched for the first time, ${summary.updated} updated, ${summary.unchanged} unchanged, ${summary.quarantined} held for review, ${summary.failed} failed.`);
        return summary;
      },
    },
  };
}
