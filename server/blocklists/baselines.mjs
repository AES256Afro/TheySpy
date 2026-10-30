import { PiholeError } from "../pihole/client.mjs";
import { isBlocked } from "../pihole/match.mjs";
import { categories as allCategories, categoryIds, securityCategories } from "./taxonomy.mjs";

// Baselines (docs/PLAN.md §6.2): named blocking levels for the whole network or one device. Each is
// a set of categories plus the lists it needs; applying one turns those lists on. Every level
// includes the spyware and ADINT category: there is no safe way to be shown targeted ads.

const essential = ["spyware", "malware", "phishing", "cryptomining"];
export const baselines = Object.freeze([
  { id: "essential", name: "Essential", severity: 1, categories: essential, lists: [],
    summary: "Security only: spyware and ADINT, malware, phishing and cryptomining. Ads still show; nothing visible breaks." },
  { id: "balanced", name: "Balanced", severity: 2, categories: [...essential, "ads", "trackers"], lists: ["adguard:hagezi_multinormal"],
    summary: "Adds standard ad and tracker blocking (HaGeZi Normal). Recommended for most devices; rare breakage." },
  { id: "strict", name: "Strict", severity: 3, categories: [...essential, "ads", "trackers", "telemetry", "nrd"],
    lists: ["adguard:hagezi_pro++", "adguard:hagezi_dyndns_blocklist", "adguard:perflyst_dandelion_sprout_smart_tv_blocklist_for_adguard_home"],
    summary: "Very strong: aggressive ad and tracker blocking (HaGeZi Pro++), device telemetry, dynamic DNS. Some sites need an exception." },
  { id: "lockdown", name: "Lockdown", severity: 4, categories: [...securityCategories, "ads", "trackers", "telemetry", "bypass", "social"],
    lists: ["adguard:hagezi_pro++", "adguard:hagezi_dyndns_blocklist", "adguard:perflyst_dandelion_sprout_smart_tv_blocklist_for_adguard_home", "adguard:hagezi_encrypted_dns_vpn_tor_proxy_bypass"],
    summary: "Most severe: adds encrypted-DNS, VPN and proxy bypass endpoints and any social-media lists you turn on. Things will break." },
]);

// Public suffixes with two labels that people meet at home; anything else counts the last two
// labels as the site. Good enough to group "i.ytimg.com" with "ytimg.com", not a full PSL.
const twoLabelSuffixes = new Set(["co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "ne.jp", "co.za", "com.br", "com.cn", "com.mx", "co.in", "co.kr", "com.tr", "com.sg", "com.hk", "com.tw",
  "github.io", "cloudfront.net", "amazonaws.com", "herokuapp.com", "azurewebsites.net", "blogspot.com", "appspot.com", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com"]);
/** The site a name belongs to (its registrable domain, roughly). */
export function siteOf(name) {
  const labels = name.split(".");
  if (labels.length <= 2) return name;
  const lastTwo = labels.slice(-2).join(".");
  return twoLabelSuffixes.has(lastTwo) ? labels.slice(-3).join(".") : lastTwo;
}

/** A scope's key: "network", or "device-<ip>" with the address made path-safe. */
export const scopeKey = (client) => (client ? `device-${client.replace(/[^0-9a-f]/gi, "-")}` : "network");

/** How severe a set of categories is, on the built-in levels' 1–4 scale. */
function severityOf(categories) {
  if (categories.some((c) => ["bypass", "social"].includes(c))) return 4;
  if (categories.some((c) => ["telemetry", "nrd"].includes(c))) return 3;
  if (categories.some((c) => ["ads", "trackers"].includes(c))) return 2;
  return 1;
}

/**
 * @param {{
 *   db: import("node:sqlite").DatabaseSync,
 *   library: ReturnType<typeof import("./library.mjs").createBlocklistLibrary>,
 *   sentinel: ReturnType<typeof import("../pihole/sentinel.mjs").createSentinel>,
 *   settings: ReturnType<typeof import("../db.mjs").createSettingsStore>,
 *   audit: ReturnType<typeof import("../audit.mjs").createAuditLog>,
 *   now?: () => Date,
 * }} deps
 */
export function createBaselines({ db, library, sentinel, settings, audit, now = () => new Date() }) {
  const exceptionsAll = () => settings.get("baseline_exceptions") ?? {};
  const assignmentsAll = () => settings.get("baseline_assignments") ?? {};
  const saveAssignments = (all) => settings.set("baseline_assignments", all);
  const all = () => {
    const custom = settings.get("baseline_custom");
    return custom ? [...baselines, custom] : baselines;
  };
  const find = (id) => all().find((b) => b.id === id) ?? null;

  const q = {
    shadowAdd: db.prepare(`INSERT INTO baseline_shadow (scope, domain, queries, blocked, first_at, last_at) VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT (scope, domain) DO UPDATE SET queries = queries + excluded.queries, blocked = blocked + excluded.blocked, last_at = MAX(last_at, excluded.last_at)`),
    shadowRows: db.prepare("SELECT domain, queries, blocked FROM baseline_shadow WHERE scope = ?"),
    shadowClear: db.prepare("DELETE FROM baseline_shadow WHERE scope = ?"),
  };

  /**
   * Each level's effect on a scope's lookups (name → counts): grouped by site, with the lists that
   * would block it, whether Pi-hole already blocks it, and how likely it is to break something.
   */
  function evaluate(counts, scope, levels) {
    const total = [...counts.values()].reduce((n, c) => n + c.queries, 0);
    const blockedNow = [...counts.values()].reduce((n, c) => n + c.blocked, 0);
    const matches = library.matchNames([...counts.keys()]);
    const kept = new Set(api.exceptions(scope));
    const keptBy = (name) => [...kept].find((site) => name === site || name.endsWith(`.${site}`));
    const enabled = library.sources().filter((src) => src.status === "enabled");

    const results = levels.map((b) => {
      const sites = new Map();
      // Lookups blocked with the baseline on: everything it blocks, plus what Pi-hole blocks already.
      let blockedAfter = blockedNow;
      for (const [name, c] of counts) {
        const m = matches.get(name);
        const categories = m ? [...m.categories].filter((x) => b.categories.includes(x)) : [];
        if (!categories.length) continue;
        const site = siteOf(name);
        const exception = keptBy(name) ?? null;
        if (!exception) blockedAfter += c.queries - c.blocked;
        const s = sites.get(site) ?? { site, names: [], queries: 0, alreadyBlocked: 0, categories: new Set(), lists: new Set(), firstParty: 0, kept: Boolean(exception) };
        s.names.push(name);
        s.queries += c.queries;
        s.alreadyBlocked += c.blocked;
        for (const x of categories) s.categories.add(x);
        for (const l of m.lists) s.lists.add(l);
        if (name === site || name === `www.${site}`) s.firstParty += c.queries;
        sites.set(site, s);
      }
      const list = [...sites.values()].map((s) => ({
        site: s.site, names: s.names.slice(0, 5), more: Math.max(0, s.names.length - 5), queries: s.queries,
        today: s.alreadyBlocked >= s.queries ? "blocked" : s.alreadyBlocked ? "partly" : "allowed",
        categories: [...s.categories], lists: [...s.lists].slice(0, 4), kept: s.kept,
        // Blocking a site the device opens directly and often is what people notice; blocking a
        // tracker called from inside other pages usually is not. A spyware, malware or phishing site
        // is never a breakage risk: blocking it is the point.
        risk: [...s.categories].some((c) => essential.includes(c)) ? "low" : s.firstParty >= 10 ? "high" : s.queries >= 50 && s.firstParty > 0 ? "medium" : "low",
      })).sort((a, b2) => ({ high: 0, medium: 1, low: 2 }[a.risk] - { high: 0, medium: 1, low: 2 }[b2.risk]) || b2.queries - a.queries);
      return {
        id: b.id, name: b.name, severity: b.severity, summary: b.summary,
        sites: list.length, newlyBlocked: list.filter((s) => s.today !== "blocked" && !s.kept).length, mightBreak: list.filter((s) => s.risk !== "low" && !s.kept).length,
        shareAfter: total ? blockedAfter / total : 0,
        details: list.slice(0, 300),
        missingLists: b.lists.filter((key) => !enabled.some((src) => src.key === key)),
        // Categories the level names but no enabled list covers (zero-breach's own list covers spyware).
        missingCategories: b.categories.filter((c) => c !== "spyware" && !enabled.some((src) => src.categories.includes(c))),
      };
    });
    return { total, blockedNow, levels: results, kept: [...kept] };
  }

  const api = {
    list: () => all(),
    find,

    /**
     * Sets the owner's own level: any categories (spyware and ADINT always included) and a name.
     * @param {{ name?: string, categories: string[] }} input
     */
    setCustom({ name, categories }, actor) {
      if (!Array.isArray(categories) || categories.some((c) => !categoryIds.includes(c))) throw Object.assign(new Error(`categories must be from: ${categoryIds.join(", ")}`), { status: 400 });
      const label = String(name ?? "").trim() || "Custom";
      if (label.length > 40) throw Object.assign(new Error("The name must be 40 characters or fewer"), { status: 400 });
      const chosen = categoryIds.filter((c) => c === "spyware" || categories.includes(c));
      const names = chosen.map((c) => allCategories.find((x) => x.id === c).name);
      const custom = { id: "custom", name: label, severity: severityOf(chosen), categories: chosen, lists: [], custom: true, summary: `Your own level: ${names.join(", ")}.` };
      settings.set("baseline_custom", custom);
      audit.record(actor, "baselines.custom_saved", null, { name: label, categories: chosen });
      return custom;
    },
    deleteCustom(actor) {
      if (Object.values(assignmentsAll()).some((a) => a.baseline === "custom")) throw Object.assign(new Error("Your level is in use; remove it from every device first"), { status: 409 });
      settings.delete("baseline_custom");
      audit.record(actor, "baselines.custom_deleted", null, {});
    },

    /** Sites the owner chose to keep allowing, per scope ("network" or "device-…"). */
    exceptions: (scope) => exceptionsAll()[scope] ?? [],
    setException(scope, site, keep, actor) {
      const all = exceptionsAll();
      const current = new Set(all[scope] ?? []);
      if (keep) current.add(site); else current.delete(site);
      all[scope] = [...current].sort();
      settings.set("baseline_exceptions", all);
      audit.record(actor, keep ? "baselines.exception_added" : "baselines.exception_removed", scope, { site });
      return all[scope];
    },

    /**
     * The compiled list for a baseline in one scope: its categories, minus the scope's exceptions
     * (a site and everything under it).
     */
    compileFor(baselineId, scope) {
      const b = find(baselineId);
      if (!b) return null;
      const compiled = library.compile(b.categories);
      const kept = api.exceptions(scope);
      if (!kept.length) return compiled;
      const domains = compiled.domains.filter((d) => !kept.some((site) => d === site || d.endsWith(`.${site}`)));
      return { ...compiled, domains, etag: `${compiled.etag}-${kept.length}` };
    },

    /** The devices that ask Pi-hole most, and the suggested baseline for each and for the network. */
    async scopes() {
      const hits = new Set(sentinel.hits().map((h) => h.clientIp));
      const devices = await sentinel.source().clients().catch(() => []);
      return {
        network: { key: "network", suggested: "balanced", why: "Balanced is the safe default for a mixed household; raise individual devices rather than everyone." },
        devices: devices.map((d) => ({
          ...d, key: scopeKey(d.ip),
          suggested: hits.has(d.ip) ? "strict" : "balanced",
          why: hits.has(d.ip) ? "This device looked up a spyware or ad-intelligence indicator. Strict removes nearly all ad delivery." : "No indicator lookups from this device. Balanced blocks ads and trackers with little breakage.",
        })),
      };
    },

    /**
     * What each baseline would block for a scope, from its real lookups over a window; and, while
     * one is tried in shadow there, what it would have blocked since.
     * @param {{ client?: string, windowDays?: number }} options
     */
    async preview({ client, windowDays = 7 } = {}) {
      const until = now().getTime() / 1000;
      const { rows, basis } = await sentinel.source().domainCounts({ client, from: until - windowDays * 86400, until });
      const counts = new Map();
      for (const r of rows) {
        const e = counts.get(r.domain) ?? { queries: 0, blocked: 0 };
        e.queries += r.queries;
        e.blocked += r.blocked;
        counts.set(r.domain, e);
      }
      const scope = scopeKey(client);
      const { total, blockedNow, levels, kept } = evaluate(counts, scope, all());
      return { scope, client: client ?? null, windowDays, basis, totalQueries: total, shareNow: total ? blockedNow / total : 0, levels, exceptions: kept, shadow: api.shadowReport(client) };
    },

    // --- shadow mode -----------------------------------------------------------------------------

    /**
     * Tries a baseline without blocking anything: from now on the live watch counts the scope's
     * lookups, and the report shows what the baseline would have blocked.
     * @param {{ baselineId: string, client?: string }} options
     */
    startShadow({ baselineId, client }, actor) {
      const b = find(baselineId);
      if (!b) throw Object.assign(new Error("No such baseline"), { status: 404 });
      if (!sentinel.watch.status().enabled) throw Object.assign(new Error("Shadow mode counts new lookups with the live watch; turn the watch on (Pi-hole Sentinel) first."), { status: 409 });
      const scope = scopeKey(client);
      const current = assignmentsAll()[scope];
      if (current && current.mode !== "shadow") throw Object.assign(new Error("A baseline is applied here; remove it before trying another in shadow."), { status: 409 });
      q.shadowClear.run(scope);
      const assignments = assignmentsAll();
      assignments[scope] = { baseline: b.id, client: client ?? null, mode: "shadow", startedAt: now().toISOString(), by: actor };
      saveAssignments(assignments);
      audit.record(actor, "baselines.shadow_started", scope, { baseline: b.id });
      return assignments[scope];
    },

    /** What the baseline tried in shadow for a scope would have blocked so far, or null. */
    shadowReport(client) {
      const scope = scopeKey(client);
      const a = assignmentsAll()[scope];
      const b = a?.mode === "shadow" ? find(a.baseline) : null;
      if (!b) return null;
      const counts = new Map(q.shadowRows.all(scope).map((r) => [String(/** @type {any} */ (r).domain), { queries: Number(/** @type {any} */ (r).queries), blocked: Number(/** @type {any} */ (r).blocked) }]));
      const { total, blockedNow, levels } = evaluate(counts, scope, [b]);
      return { baseline: b.id, startedAt: a.startedAt, totalQueries: total, shareNow: total ? blockedNow / total : 0, level: levels[0] };
    },

    /**
     * The live watch's queries, counted for every scope in shadow mode. Polls overlap, so a query
     * at or before the last one counted (by id and time) is skipped.
     * @param {{ queryId: number, at: string, domain: string, status: string, clientIp: string }[]} queries
     */
    observe(queries) {
      const shadows = Object.entries(assignmentsAll()).filter(([, a]) => a.mode === "shadow");
      if (!shadows.length || !queries.length) return;
      const mark = settings.get("baseline_shadow_mark") ?? { id: 0, at: "" };
      const next = { ...mark };
      const counts = new Map();
      for (const query of queries) {
        if (query.queryId <= mark.id && query.at <= mark.at) continue;
        if (query.queryId > next.id) next.id = query.queryId;
        if (query.at > next.at) next.at = query.at;
        for (const [scope, a] of shadows) {
          if ((a.client && a.client !== query.clientIp) || query.at < a.startedAt || !query.domain) continue;
          const key = `${scope}\u0000${query.domain}`;
          const e = counts.get(key) ?? { scope, domain: query.domain, queries: 0, blocked: 0, first: query.at, last: query.at };
          e.queries += 1;
          if (isBlocked(query.status)) e.blocked += 1;
          if (query.at < e.first) e.first = query.at;
          if (query.at > e.last) e.last = query.at;
          counts.set(key, e);
        }
      }
      db.exec("BEGIN");
      try {
        for (const e of counts.values()) q.shadowAdd.run(e.scope, e.domain, e.queries, e.blocked, e.first, e.last);
        db.exec("COMMIT");
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
      settings.set("baseline_shadow_mark", next);
    },

    assignments: () => assignmentsAll(),

    /**
     * Applies a baseline: turns on the lists it needs and fetches them, then has Pi-hole subscribe to
     * the scope's compiled list. The whole network uses Pi-hole's Default group; a device gets its
     * own group (and keeps Default, so its other lists still apply). What was changed is recorded so
     * removing the baseline puts Pi-hole back exactly as it was.
     * @param {{ baselineId: string, client?: string, listsOrigin: string, log?: (line: string) => void }} options
     */
    async apply({ baselineId, client, listsOrigin, log = () => {} }, actor) {
      const b = find(baselineId);
      if (!b) throw Object.assign(new Error("No such baseline"), { status: 404 });
      if (!sentinel.effective().write) throw Object.assign(new Error("Changing Pi-hole is turned off. Allow it on the Pi-hole Sentinel screen first."), { status: 403 });
      const scope = scopeKey(client);
      if (assignmentsAll()[scope]) await api.remove({ client, log }, actor);

      const enabled = await library.ensureEnabled(b.lists, actor);
      if (enabled.length) {
        log(`Turning on ${enabled.length} list${enabled.length === 1 ? "" : "s"} ${b.name} needs, and fetching them.`);
        await library.update({ ids: enabled, actor });
      }
      const address = `${listsOrigin}/lists/${library.listToken()}/baseline-${b.id}--${scope}.adblock`;
      const label = `${b.name} (${client ?? "whole network"})`;
      const source = sentinel.source();
      if (!source.canWrite) throw new PiholeError("Applying a baseline needs the Pi-hole API.");
      const record = await /** @type {any} */ (source).client().session(async (c) => {
        let group = null;
        let clientBefore = null;
        // What this attempt changed, so a failure part-way leaves Pi-hole as it found it.
        const undo = [];
        try {
          if (client) {
            const groupName = `TheySpy ${client}`;
            group = (await c.listGroups()).find((g) => g.name === groupName) ?? null;
            if (!group) {
              group = await c.addGroup(groupName, `TheySpy: ${b.name} baseline`);
              if (!group) throw new PiholeError("Pi-hole did not create the group");
              undo.push(() => c.deleteGroup(groupName));
            }
            const existing = (await c.listClients()).find((x) => x.client === client);
            const groupId = group.id;
            clientBefore = existing ? { groups: existing.groups.filter((g) => g !== groupId), comment: existing.comment ?? "" } : null;
            const groups = [...new Set([...(clientBefore?.groups ?? [0]), groupId])];
            if (existing) {
              await c.updateClient(client, groups, existing.comment ?? "");
              undo.push(() => c.updateClient(client, existing.groups, existing.comment ?? ""));
            } else {
              await c.addClient(client, groups, `TheySpy: ${b.name} baseline`);
              undo.push(() => c.deleteClient(client));
            }
          }
          if (!(await c.listAdlists("block")).some((l) => l.address === address)) {
            await c.addAdlist(address, `TheySpy: baseline ${label}`, group ? [group.id] : [0]);
            undo.push(() => c.deleteAdlist(address));
          }
          log(`Pi-hole subscribed to the ${label} list; rebuilding gravity.`);
          await c.updateGravity();
          let loaded = null;
          for (let i = 0; i < 15 && !loaded?.number; i += 1) {
            loaded = (await c.listAdlists("block")).find((l) => l.address === address);
            if (!loaded?.number) await new Promise((resolve) => setTimeout(resolve, 1000));
          }
          if (!loaded?.number) throw new PiholeError(`Pi-hole added the ${label} list but loaded no entries; check it can reach ${listsOrigin}.`);
          return { address, groupId: group?.id ?? null, groupName: group?.name ?? null, clientBefore, entries: Number(loaded.number) };
        } catch (error) {
          for (const step of undo.reverse()) await step().catch(() => {});
          if (undo.length) log("Undid this attempt's changes in Pi-hole.");
          throw error;
        }
      });
      const assignments = assignmentsAll();
      assignments[scope] = { baseline: b.id, client: client ?? null, appliedAt: now().toISOString(), by: actor, ...record };
      saveAssignments(assignments);
      audit.record(actor, "baselines.applied", scope, { baseline: b.id, entries: record.entries });
      return assignments[scope];
    },

    /**
     * Undoes exactly what apply changed in Pi-hole.
     * @param {{ client?: string, log?: (line: string) => void }} options
     */
    async remove({ client, log = () => {} }, actor) {
      const scope = scopeKey(client);
      const a = assignmentsAll()[scope];
      if (!a) throw Object.assign(new Error("No baseline is applied there"), { status: 404 });
      if (a.mode === "shadow") {
        q.shadowClear.run(scope);
        const assignments = assignmentsAll();
        delete assignments[scope];
        saveAssignments(assignments);
        audit.record(actor, "baselines.shadow_stopped", scope, { baseline: a.baseline });
        return { removed: true, shadow: true };
      }
      const source = sentinel.source();
      await /** @type {any} */ (source).client().session(async (c) => {
        if ((await c.listAdlists("block")).some((l) => l.address === a.address)) await c.deleteAdlist(a.address);
        if (a.client) {
          if (a.clientBefore) await c.updateClient(a.client, a.clientBefore.groups, a.clientBefore.comment);
          else if ((await c.listClients()).some((x) => x.client === a.client)) await c.deleteClient(a.client);
          if (a.groupName && (await c.listGroups()).some((g) => g.name === a.groupName)) await c.deleteGroup(a.groupName);
        }
        log("Removed the baseline from Pi-hole; rebuilding gravity.");
        await c.updateGravity();
      });
      const assignments = assignmentsAll();
      delete assignments[scope];
      saveAssignments(assignments);
      audit.record(actor, "baselines.removed", scope, { baseline: a.baseline });
      return { removed: true };
    },
  };
  sentinel.watch.observe((queries) => api.observe(queries));
  return api;
}

/** @param {ReturnType<typeof createBaselines>} baselinesApi */
export function baselineJobKinds(baselinesApi) {
  return {
    "baselines.apply": {
      title: "Apply a baseline in Pi-hole",
      async run({ log, params, actor }) {
        const a = await baselinesApi.apply({ ...params, log }, actor);
        log(`${baselinesApi.find(a.baseline)?.name ?? a.baseline} is on for ${a.client ?? "the whole network"}: Pi-hole loaded ${a.entries} entries.`);
        return { baseline: a.baseline, entries: a.entries };
      },
    },
    "baselines.remove": {
      title: "Remove a baseline from Pi-hole",
      async run({ log, params, actor }) {
        await baselinesApi.remove({ client: params.client, log }, actor);
        log(`Baseline removed for ${params.client ?? "the whole network"}; Pi-hole is as it was before.`);
        return { removed: true };
      },
    },
  };
}
