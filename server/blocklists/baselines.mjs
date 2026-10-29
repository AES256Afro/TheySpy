import { PiholeError } from "../pihole/client.mjs";
import { securityCategories } from "./taxonomy.mjs";

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
export const baselineById = (id) => baselines.find((b) => b.id === id) ?? null;

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

/**
 * @param {{
 *   library: ReturnType<typeof import("./library.mjs").createBlocklistLibrary>,
 *   sentinel: ReturnType<typeof import("../pihole/sentinel.mjs").createSentinel>,
 *   settings: ReturnType<typeof import("../db.mjs").createSettingsStore>,
 *   audit: ReturnType<typeof import("../audit.mjs").createAuditLog>,
 *   now?: () => Date,
 * }} deps
 */
export function createBaselines({ library, sentinel, settings, audit, now = () => new Date() }) {
  const exceptionsAll = () => settings.get("baseline_exceptions") ?? {};
  const assignmentsAll = () => settings.get("baseline_assignments") ?? {};

  const api = {
    list: () => baselines,

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
      const b = baselineById(baselineId);
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
     * What each baseline would block for a scope, from its real lookups: grouped by site, with the
     * lists that would block it, whether Pi-hole already blocks it, and how likely it is to break
     * something.
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
      const total = [...counts.values()].reduce((n, c) => n + c.queries, 0);
      const blockedNow = [...counts.values()].reduce((n, c) => n + c.blocked, 0);
      const matches = library.matchNames([...counts.keys()]);
      const scope = scopeKey(client);
      const kept = new Set(api.exceptions(scope));
      const keptBy = (name) => [...kept].find((site) => name === site || name.endsWith(`.${site}`));

      const levels = baselines.map((b) => {
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
          // tracker called from inside other pages usually is not.
          risk: s.firstParty >= 10 ? "high" : s.queries >= 50 && s.firstParty > 0 ? "medium" : "low",
        })).sort((a, b2) => ({ high: 0, medium: 1, low: 2 }[a.risk] - { high: 0, medium: 1, low: 2 }[b2.risk]) || b2.queries - a.queries);
        return {
          id: b.id, name: b.name, severity: b.severity, summary: b.summary,
          sites: list.length, newlyBlocked: list.filter((s) => s.today !== "blocked" && !s.kept).length, mightBreak: list.filter((s) => s.risk !== "low" && !s.kept).length,
          shareAfter: total ? blockedAfter / total : 0,
          details: list.slice(0, 300),
          missingLists: b.lists.filter((key) => !library.sources().some((s) => s.key === key && s.status === "enabled")),
        };
      });
      return { scope, client: client ?? null, windowDays, basis, totalQueries: total, shareNow: total ? blockedNow / total : 0, levels, exceptions: [...kept] };
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
      const b = baselineById(baselineId);
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
        if (client) {
          const groupName = `TheySpy ${client}`;
          group = (await c.listGroups()).find((g) => g.name === groupName) ?? (await c.addGroup(groupName, `TheySpy: ${b.name} baseline`));
          if (!group) throw new PiholeError("Pi-hole did not create the group");
          const existing = (await c.listClients()).find((x) => x.client === client);
          clientBefore = existing ? { groups: existing.groups, comment: existing.comment ?? "" } : null;
          const groups = [...new Set([...(existing?.groups ?? [0]), group.id])];
          if (existing) await c.updateClient(client, groups, existing.comment ?? ""); else await c.addClient(client, groups, `TheySpy: ${b.name} baseline`);
        }
        await c.addAdlist(address, `TheySpy: baseline ${label}`, group ? [group.id] : [0]);
        log(`Pi-hole subscribed to the ${label} list; rebuilding gravity.`);
        await c.updateGravity();
        let loaded = null;
        for (let i = 0; i < 15 && !loaded?.number; i += 1) {
          loaded = (await c.listAdlists("block")).find((l) => l.address === address);
          if (!loaded?.number) await new Promise((resolve) => setTimeout(resolve, 1000));
        }
        if (!loaded?.number) throw new PiholeError(`Pi-hole added the ${label} list but loaded no entries; check it can reach ${listsOrigin}.`);
        return { address, groupId: group?.id ?? null, groupName: group?.name ?? null, clientBefore, entries: Number(loaded.number) };
      });
      const all = assignmentsAll();
      all[scope] = { baseline: b.id, client: client ?? null, appliedAt: now().toISOString(), by: actor, ...record };
      settings.set("baseline_assignments", all);
      audit.record(actor, "baselines.applied", scope, { baseline: b.id, entries: record.entries });
      return all[scope];
    },

    /**
     * Undoes exactly what apply changed in Pi-hole.
     * @param {{ client?: string, log?: (line: string) => void }} options
     */
    async remove({ client, log = () => {} }, actor) {
      const scope = scopeKey(client);
      const a = assignmentsAll()[scope];
      if (!a) throw Object.assign(new Error("No baseline is applied there"), { status: 404 });
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
      const all = assignmentsAll();
      delete all[scope];
      settings.set("baseline_assignments", all);
      audit.record(actor, "baselines.removed", scope, { baseline: a.baseline });
      return { removed: true };
    },
  };
  return api;
}

/** @param {ReturnType<typeof createBaselines>} baselinesApi */
export function baselineJobKinds(baselinesApi) {
  return {
    "baselines.apply": {
      title: "Apply a baseline in Pi-hole",
      async run({ log, params, actor }) {
        const a = await baselinesApi.apply({ ...params, log }, actor);
        log(`${baselineById(a.baseline).name} is on for ${a.client ?? "the whole network"}: Pi-hole loaded ${a.entries} entries.`);
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
