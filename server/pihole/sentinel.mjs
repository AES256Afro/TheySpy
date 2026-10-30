import { blocklistDomains } from "../iocs/exports.mjs";
import { PiholeError, wildcardRegex } from "./client.mjs";
import { createMatcher } from "./match.mjs";
import { apiSource, databaseSource } from "./sources.mjs";

const tag = "TheySpy:";
const day = 24 * 60 * 60;

/**
 * Pi-hole Sentinel: hunts Pi-hole's DNS history for indicator lookups, watches new queries, checks
 * which indicator domains Pi-hole already blocks, and pushes (and rolls back) deny entries for the
 * rest. Pushing is off until the owner allows it, and a rollback removes only entries TheySpy added
 * that still carry its comment, so nothing the owner made by hand is ever touched.
 * @param {{
 *   db: import("node:sqlite").DatabaseSync,
 *   settings: ReturnType<typeof import("../db.mjs").createSettingsStore>,
 *   audit: ReturnType<typeof import("../audit.mjs").createAuditLog>,
 *   iocStore: ReturnType<typeof import("../iocs/store.mjs").createIocStore>,
 *   secretBox: ReturnType<typeof import("../secrets.mjs").createSecretBox>,
 *   env?: { url?: string, password?: string, dbPath?: string, write?: boolean },
 *   fetchImpl?: typeof fetch,
 *   now?: () => Date,
 * }} deps
 */
export function createSentinel({ db, settings, audit, iocStore, secretBox, env = {}, fetchImpl, now = () => new Date() }) {
  const insertEvent = db.prepare("INSERT OR IGNORE INTO ioc_hit_events (source, query_id, at, indicator, domain, via, client_ip, client_name, status, blocked, found_by, found_at) VALUES ('pihole', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
  const insertHunt = db.prepare("INSERT INTO pihole_hunts (mode, from_at, until_at, indicators, queries_seen, new_hits, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?)");
  const lastHunt = db.prepare("SELECT * FROM pihole_hunts ORDER BY id DESC LIMIT 1");
  const insertPush = db.prepare("INSERT INTO pihole_pushes (status, entries, pushed_at, pushed_by) VALUES ('active', ?, ?, ?)");
  const pushById = db.prepare("SELECT * FROM pihole_pushes WHERE id = ?");
  const pushList = db.prepare("SELECT id, status, entries, pushed_at, pushed_by, rolled_back_at, rolled_back_by FROM pihole_pushes ORDER BY id DESC LIMIT 20");
  const markRolledBack = db.prepare("UPDATE pihole_pushes SET status = 'rolled_back', rolled_back_at = ?, rolled_back_by = ? WHERE id = ?");
  const hitGroups = db.prepare(`
    SELECT e.indicator, e.domain, e.via, e.client_ip AS clientIp, MAX(e.client_name) AS clientName,
           MIN(e.at) AS firstSeen, MAX(e.at) AS lastSeen, COUNT(*) AS lookups, SUM(e.blocked) AS blocked,
           (SELECT status FROM ioc_hit_events l WHERE l.indicator = e.indicator AND l.domain = e.domain AND l.client_ip = e.client_ip ORDER BY l.at DESC LIMIT 1) AS lastStatus,
           i.tier, i.confidence, i.source
    FROM ioc_hit_events e LEFT JOIN iocs i ON i.value = e.indicator
    GROUP BY e.indicator, e.domain, e.via, e.client_ip
    ORDER BY lastSeen DESC`);

  // --- configuration ---------------------------------------------------------------------------

  const stored = () => settings.get("pihole") ?? {};
  function effective() {
    const s = stored();
    const mode = env.url ? "api" : env.dbPath ? "database" : s.mode ?? null;
    const password = env.password ?? (s.passwordSealed ? secretBox.open(s.passwordSealed) : null);
    return {
      mode,
      url: env.url ?? s.url ?? null,
      dbPath: env.dbPath ?? s.dbPath ?? null,
      password,
      passwordUnreadable: !env.password && Boolean(s.passwordSealed) && password === null,
      write: env.write ?? Boolean(s.write),
      watch: s.watch ?? true,
      windowDays: Math.min(Math.max(Number(s.windowDays ?? 90), 1), 365),
    };
  }
  function source() {
    const c = effective();
    if (c.mode === "api" && c.url) return apiSource({ url: c.url, password: c.password, fetchImpl });
    if (c.mode === "database" && c.dbPath) return databaseSource({ path: c.dbPath });
    throw new PiholeError("Pi-hole is not connected yet. Add its address on the Pi-hole Sentinel screen.");
  }
  const matcher = () => {
    const set = iocStore.activeSet();
    if (!set) throw new PiholeError("No indicator set is active.");
    return createMatcher(set);
  };

  /** Stores new lookups; one audit entry per batch, naming the indicators and clients involved. */
  function recordHits(hits, foundBy) {
    const fresh = [];
    const foundAt = now().toISOString();
    for (const h of hits) {
      const { changes } = insertEvent.run(h.queryId, h.at, h.indicator, h.domain, h.via, h.clientIp, h.clientName, h.status, h.blocked ? 1 : 0, foundBy, foundAt);
      if (Number(changes)) fresh.push(h);
    }
    if (fresh.length) {
      audit.record(foundBy === "watch" ? "system" : foundBy, "pihole.indicator_lookups", null, {
        lookups: fresh.length,
        indicators: [...new Set(fresh.map((h) => h.indicator))].slice(0, 20),
        clients: [...new Set(fresh.map((h) => h.clientIp))].slice(0, 20),
        allowed: fresh.filter((h) => !h.blocked).length,
      });
    }
    return fresh.length;
  }

  // --- live watch ------------------------------------------------------------------------------

  const watchState = { running: false, lastPollAt: null, lastError: null, newHits: 0 };
  let timer = null;
  let lastPoll = null;
  const observers = new Set();
  async function poll() {
    const c = effective();
    if (!c.mode || !c.watch) return;
    const started = now().getTime() / 1000;
    const from = (lastPoll ?? started - 300) - 90; // overlap: rows are unique, so re-reading is free
    try {
      const seen = [];
      const { hits } = await source().recent(matcher(), from, observers.size ? (q) => seen.push(q) : undefined);
      watchState.newHits += recordHits(hits, "watch");
      for (const observe of observers) observe(seen);
      watchState.lastError = null;
      lastPoll = started;
      // A poll that reached Pi-hole is as good as the Test button: say so, so the screen does not
      // keep showing "Not tested yet" (or an old failure) while everything works.
      const last = settings.get("pihole_last_test");
      const where = source().describe();
      if (!last?.ok || last.where !== where) {
        if (last?.ok === false) audit.record("system", "pihole.reachable", where, { after: last.message });
        settings.set("pihole_last_test", { ok: true, mode: c.mode, where, via: "live watch", at: now().toISOString() });
      }
    } catch (error) {
      watchState.lastError = error.message;
      if (settings.get("pihole_last_test")?.ok !== false) {
        sentinel.recordFailedTest(error.message);
        audit.record("system", "pihole.unreachable", null, { error: error.message });
      }
    }
    watchState.lastPollAt = now().toISOString();
  }

  const sentinel = {
    effective,
    /** The configured history source (Pi-hole API or database file); throws when none is set. */
    source,

    /** Settings as the UI may see them: never the password itself. */
    publicConfig() {
      const c = effective();
      return {
        configured: Boolean(c.mode && (c.url || c.dbPath)),
        mode: c.mode, url: c.url, dbPath: c.dbPath, write: c.write, watch: c.watch, windowDays: c.windowDays,
        hasPassword: Boolean(c.password), passwordUnreadable: c.passwordUnreadable,
        fromEnv: { url: Boolean(env.url), password: Boolean(env.password), dbPath: Boolean(env.dbPath), write: env.write !== undefined },
      };
    },

    /** @param {{ mode?: string, url?: string, password?: string, dbPath?: string, write?: boolean, watch?: boolean, windowDays?: number }} input */
    configure(input, actor) {
      const next = { ...stored() };
      const errors = [];
      if (input.mode !== undefined) { if (["api", "database"].includes(input.mode)) next.mode = input.mode; else errors.push("mode must be api or database"); }
      if (input.url !== undefined) {
        try {
          const u = new URL(String(input.url));
          if (!["http:", "https:"].includes(u.protocol) || u.username || u.password) throw new Error();
          next.url = u.origin;
        } catch { errors.push("address must look like http://192.168.1.5 or https://pi.hole"); }
      }
      if (input.dbPath !== undefined) { if (typeof input.dbPath === "string" && input.dbPath.startsWith("/")) next.dbPath = input.dbPath; else errors.push("database path must be absolute"); }
      if (input.password !== undefined) { if (typeof input.password === "string" && input.password.length <= 200) next.passwordSealed = input.password ? secretBox.seal(input.password) : undefined; else errors.push("password is too long"); }
      for (const flag of ["write", "watch"]) if (input[flag] !== undefined) { if (typeof input[flag] === "boolean") next[flag] = input[flag]; else errors.push(`${flag} must be true or false`); }
      if (input.windowDays !== undefined) { const n = Number(input.windowDays); if (Number.isInteger(n) && n >= 1 && n <= 365) next.windowDays = n; else errors.push("window must be 1 to 365 days"); }
      if (errors.length) throw Object.assign(new Error(errors.join("; ")), { status: 400 });
      settings.set("pihole", next);
      // A test of the old address or password says nothing about the new one.
      if (["mode", "url", "password", "dbPath"].some((k) => input[k] !== undefined)) settings.delete("pihole_last_test");
      audit.record(actor, "pihole.settings_changed", null, { ...input, password: input.password === undefined ? undefined : "(changed)" });
      lastPoll = null;
      return sentinel.publicConfig();
    },

    async test() {
      const s = source();
      const result = { mode: s.mode, where: s.describe(), ...(await s.test()), at: now().toISOString() };
      settings.set("pihole_last_test", { ok: true, ...result });
      return result;
    },
    recordFailedTest(message) { settings.set("pihole_last_test", { ok: false, message, at: now().toISOString() }); },

    /**
     * Looks back over the window for every lookup of an indicator.
     * @param {{ windowDays?: number, actor?: string }} [options]
     */
    async hunt({ windowDays, actor = "owner" } = {}) {
      const c = effective();
      const until = now().getTime() / 1000;
      const from = until - (windowDays ?? c.windowDays) * day;
      const m = matcher();
      const { queriesSeen, hits } = await source().hunt(m, { from, until });
      const fresh = recordHits(hits, actor);
      insertHunt.run(c.mode, new Date(from * 1000).toISOString(), new Date(until * 1000).toISOString(), m.size, queriesSeen, fresh, now().toISOString());
      return { queriesSeen, hits: hits.length, newHits: fresh, indicators: m.size, from: new Date(from * 1000).toISOString() };
    },

    lastHunt() {
      const row = /** @type {any} */ (lastHunt.get());
      return row ? { mode: row.mode, from: row.from_at, until: row.until_at, indicators: Number(row.indicators), queriesSeen: Number(row.queries_seen), newHits: Number(row.new_hits), finishedAt: row.finished_at } : null;
    },

    hits() {
      return hitGroups.all().map((r) => {
        const row = /** @type {any} */ (r);
        return { ...row, lookups: Number(row.lookups), blocked: Number(row.blocked) };
      });
    },

    /** For each blocklist-worthy indicator domain: does Pi-hole block it, and its subdomains? */
    async coverage() {
      const s = source();
      if (!s.canWrite) throw new PiholeError("The coverage check needs the Pi-hole API; a database file cannot show Pi-hole's lists.");
      const set = iocStore.activeSet();
      const domains = blocklistDomains(set);
      const judge = (search) => {
        const own = (search.domains ?? []).filter((d) => d.enabled !== false);
        const lists = (search.gravity ?? []).filter((g) => g.enabled !== false);
        const allow = own.some((d) => d.type === "allow") || lists.some((g) => g.type === "allow");
        const by = [...own.filter((d) => d.type === "deny").map((d) => (String(d.comment ?? "").startsWith(tag) ? `TheySpy ${d.kind}` : `your ${d.kind} deny entry`)), ...lists.filter((g) => g.type === "block").map((g) => g.address)];
        return { blocked: !allow && by.length > 0, allowlisted: allow, by: [...new Set(by)] };
      };
      const results = await /** @type {ReturnType<typeof apiSource>} */ (s).client().session(async (c) => {
        const out = [];
        for (const domain of domains) {
          const self = judge(await c.search(domain));
          const sub = judge(await c.search(`theyspy-coverage-probe.${domain}`));
          out.push({ domain, blocked: self.blocked, subdomainsBlocked: sub.blocked, allowlisted: self.allowlisted || sub.allowlisted, by: self.by });
        }
        return out;
      });
      const summary = {
        at: now().toISOString(), asof: set.asof, total: results.length,
        blocked: results.filter((r) => r.blocked).length,
        fullyBlocked: results.filter((r) => r.blocked && r.subdomainsBlocked).length,
        allowlisted: results.filter((r) => r.allowlisted).length,
        results,
      };
      settings.set("pihole_coverage", summary);
      return summary;
    },
    /** The network's most-looked-up names, or [] when Pi-hole is not reachable over its API. */
    async topDomains() {
      const c = effective();
      if (c.mode !== "api" || !c.url) return [];
      try {
        return await /** @type {ReturnType<typeof apiSource>} */ (source()).client().session((client) => client.topDomains(200));
      } catch {
        return [];
      }
    },

    lastCoverage: () => settings.get("pihole_coverage") ?? null,
    /** A push or rollback changes what Pi-hole blocks, so the last check no longer describes it. */
    markCoverageStale() {
      const coverage = settings.get("pihole_coverage");
      if (coverage) settings.set("pihole_coverage", { ...coverage, stale: true });
    },

    /** Pi-hole's adlists that TheySpy added (their comment starts with "TheySpy:"). */
    async subscriptions() {
      const s = source();
      if (!s.canWrite) return [];
      return /** @type {ReturnType<typeof apiSource>} */ (s).client().session(async (c) => (await c.listAdlists("block"))
        .filter((l) => String(l.comment ?? "").startsWith(tag))
        .map((l) => ({ address: l.address, entries: Number(l.number ?? 0), status: Number(l.status ?? 0), enabled: l.enabled !== false, updated: l.date_updated ? new Date(Number(l.date_updated) * 1000).toISOString() : null })));
    },

    /**
     * Subscribes Pi-hole to one of TheySpy's compiled lists and rebuilds gravity, then confirms
     * Pi-hole loaded it. Only with writes allowed, and only TheySpy's own /lists/ addresses.
     * @param {string} address
     * @param {string} label
     */
    async subscribe(address, label, actor) {
      if (!effective().write) throw Object.assign(new Error("Changing Pi-hole is turned off. Allow it on the Pi-hole Sentinel screen first."), { status: 403 });
      if (!/^https?:\/\/[^/]+\/lists\/[\w-]+\/[a-z]+\.(txt|hosts|adblock|dnsmasq|rpz)$/.test(address)) throw Object.assign(new Error("Only TheySpy's own list addresses can be added"), { status: 400 });
      const s = source();
      if (!s.canWrite) throw new PiholeError("Subscribing needs the Pi-hole API.");
      return /** @type {ReturnType<typeof apiSource>} */ (s).client().session(async (c) => {
        if (!(await c.listAdlists("block")).some((l) => l.address === address)) await c.addAdlist(address, `${tag} ${label}`);
        const log = await c.updateGravity();
        // Gravity logs "Target: <url>" then a line ending "Status: Retrieval successful" (or why it failed).
        const after = log.indexOf(address) >= 0 ? log.slice(log.indexOf(address)).split("\n")[1] ?? "" : "";
        const retrieval = after.includes("Status:") ? after.slice(after.lastIndexOf("Status:") + 7).trim() : null;
        let loaded = null;
        for (let i = 0; i < 15 && !loaded?.number; i += 1) {
          loaded = (await c.listAdlists("block")).find((l) => l.address === address);
          if (!loaded?.number) await new Promise((resolve) => setTimeout(resolve, 1000));
        }
        audit.record(actor, "pihole.subscribed", null, { list: label, entries: Number(loaded?.number ?? 0) });
        if (!loaded?.number) throw new PiholeError(`Pi-hole added the list but loaded no entries (${retrieval ?? "no status in its log"}). Check that Pi-hole can reach ${new URL(address).origin}.`);
        return { entries: Number(loaded.number), retrieval };
      });
    },

    async unsubscribe(address, actor) {
      if (!effective().write) throw Object.assign(new Error("Changing Pi-hole is turned off."), { status: 403 });
      const s = source();
      return /** @type {ReturnType<typeof apiSource>} */ (s).client().session(async (c) => {
        const list = (await c.listAdlists("block")).find((l) => l.address === address);
        if (!list || !String(list.comment ?? "").startsWith(tag)) throw Object.assign(new Error("That list is not one TheySpy added"), { status: 404 });
        await c.deleteAdlist(address);
        await c.updateGravity();
        audit.record(actor, "pihole.unsubscribed", null, { comment: list.comment });
        return { removed: true };
      });
    },

    /** What a push would add, from the latest coverage check: indicator domains not fully blocked and not allowlisted by the owner. */
    pushPreview() {
      const coverage = sentinel.lastCoverage();
      if (!coverage || coverage.stale) return null;
      const domains = coverage.results.filter((r) => !(r.blocked && r.subdomainsBlocked) && !r.allowlisted).map((r) => r.domain);
      return { checkedAt: coverage.at, domains, skippedAllowlisted: coverage.results.filter((r) => r.allowlisted).map((r) => r.domain) };
    },

    /** Adds a wildcard deny entry per domain. Only indicator domains, only when the owner allowed writes. */
    async push(domains, actor) {
      if (!effective().write) throw Object.assign(new Error("Changing Pi-hole is turned off. Allow it on the Pi-hole Sentinel screen first."), { status: 403 });
      const allowed = new Set(blocklistDomains(iocStore.activeSet()));
      const wanted = [...new Set(domains)].filter((d) => allowed.has(d));
      if (wanted.length !== new Set(domains).size) throw Object.assign(new Error("Only indicator domains from the active set can be pushed."), { status: 400 });
      const s = source();
      if (!s.canWrite) throw new PiholeError("Pushing needs the Pi-hole API.");
      const set = iocStore.activeSet();
      return /** @type {ReturnType<typeof apiSource>} */ (s).client().session(async (c) => {
        const existing = new Set((await c.listDomains("deny", "regex")).map((d) => d.domain));
        const patterns = wanted.map(wildcardRegex).filter((p) => !existing.has(p));
        if (!patterns.length) return { added: 0, pushId: null };
        const processed = await c.addDenyRegex(patterns, `${tag} AdFection / Candiru indicator (zero-breach ${set.asof ?? "set"})`);
        const added = (processed.success ?? []).map((s2) => s2.item);
        const present = new Set((await c.listDomains("deny", "regex")).map((d) => d.domain));
        const missing = added.filter((p) => !present.has(p));
        if (missing.length) throw new PiholeError(`Pi-hole reported ${missing.length} entries added that it does not list`);
        const pushId = Number(insertPush.run(JSON.stringify(added), now().toISOString(), actor).lastInsertRowid);
        sentinel.markCoverageStale();
        audit.record(actor, "pihole.denylist_pushed", `pihole-push:${pushId}`, { entries: added.length, errors: processed.errors?.length ?? 0 });
        return { added: added.length, errors: processed.errors ?? [], pushId };
      });
    },

    /** Removes exactly what one push added, if it still carries TheySpy's comment. */
    async rollback(pushId, actor) {
      const row = /** @type {any} */ (pushById.get(pushId));
      if (!row || row.status !== "active") throw Object.assign(new Error("Only an active push can be rolled back"), { status: 409 });
      const entries = JSON.parse(row.entries);
      const s = source();
      return /** @type {ReturnType<typeof apiSource>} */ (s).client().session(async (c) => {
        const current = await c.listDomains("deny", "regex");
        const ours = new Set(current.filter((d) => String(d.comment ?? "").startsWith(tag)).map((d) => d.domain));
        const remove = entries.filter((p) => ours.has(p));
        await c.deleteDenyRegex(remove);
        const left = new Set((await c.listDomains("deny", "regex")).map((d) => d.domain));
        const stuck = remove.filter((p) => left.has(p));
        if (stuck.length) throw new PiholeError(`${stuck.length} entries are still in Pi-hole after removal`);
        markRolledBack.run(now().toISOString(), actor, pushId);
        sentinel.markCoverageStale();
        audit.record(actor, "pihole.denylist_rolled_back", `pihole-push:${pushId}`, { removed: remove.length, alreadyGoneOrEdited: entries.length - remove.length });
        return { removed: remove.length, skipped: entries.length - remove.length };
      });
    },

    pushes() {
      return pushList.all().map((r) => {
        const row = /** @type {any} */ (r);
        return { id: Number(row.id), status: row.status, entries: JSON.parse(row.entries).length, pushedAt: row.pushed_at, pushedBy: row.pushed_by, rolledBackAt: row.rolled_back_at, rolledBackBy: row.rolled_back_by };
      });
    },

    watch: {
      status: () => ({ ...watchState, enabled: Boolean(effective().mode && effective().watch) }),
      poll,
      /**
       * Calls `observe` with every query each poll reads. Polls overlap by 90 seconds, so an
       * observer sees some queries twice and must skip what it has counted (by queryId and time).
       * @param {(queries: ReturnType<typeof import("./match.mjs").fromApi>[]) => void} observe
       */
      observe(observe) { observers.add(observe); return () => observers.delete(observe); },
      /** Starts the 30-second watch loop (index.mjs only; tests call poll directly). */
      start(intervalMs = 30_000) {
        if (timer) return;
        watchState.running = true;
        timer = setInterval(() => { void poll(); }, intervalMs);
        timer.unref();
      },
      stop() { if (timer) clearInterval(timer); timer = null; watchState.running = false; },
    },
  };
  return sentinel;
}

/**
 * Job kinds for Pi-hole. Testing, hunting and the coverage check can be started directly; pushes
 * and rollbacks only from the review screen, with their parameters.
 * @param {ReturnType<typeof createSentinel>} sentinel
 */
export function piholeJobKinds(sentinel) {
  return {
    "pihole.test": {
      title: "Test the Pi-hole connection",
      direct: true,
      async run({ log }) {
        try {
          const result = await sentinel.test();
          log(`Connected: ${result.where}.`);
          return result;
        } catch (error) {
          sentinel.recordFailedTest(error.message);
          throw error;
        }
      },
    },
    "pihole.hunt": {
      title: "Hunt Pi-hole's history for indicator lookups",
      direct: true,
      async run({ log, params, actor }) {
        const result = await sentinel.hunt({ windowDays: params?.windowDays, actor });
        log(`Looked at ${result.queriesSeen} queries for ${result.indicators} indicator domains since ${result.from}: ${result.hits} matching lookups, ${result.newHits} not seen before.`);
        return result;
      },
    },
    "pihole.coverage": {
      title: "Check which indicators Pi-hole blocks",
      direct: true,
      async run({ log }) {
        const c = await sentinel.coverage();
        log(`${c.blocked} of ${c.total} indicator domains are blocked; ${c.fullyBlocked} with their subdomains; ${c.allowlisted} are on your allowlist.`);
        return { total: c.total, blocked: c.blocked, fullyBlocked: c.fullyBlocked, allowlisted: c.allowlisted };
      },
    },
    "pihole.subscribe": {
      title: "Subscribe Pi-hole to a TheySpy list",
      async run({ log, params, actor }) {
        const result = await sentinel.subscribe(params.address, params.label, actor);
        log(`Pi-hole loaded ${result.entries} entries from TheySpy's ${params.label} list.`);
        return result;
      },
    },
    "pihole.unsubscribe": {
      title: "Remove a TheySpy list from Pi-hole",
      async run({ log, params, actor }) {
        await sentinel.unsubscribe(params.address, actor);
        log(`Removed TheySpy's ${params.label ?? "list"} from Pi-hole and rebuilt gravity.`);
        return { removed: true };
      },
    },
    "pihole.push": {
      title: "Add indicator domains to Pi-hole's denylist",
      async run({ log, params, actor }) {
        const result = await sentinel.push(params.domains, actor);
        log(result.pushId ? `Added ${result.added} wildcard deny entries (push ${result.pushId}).` : "Nothing to add: every domain already has an entry.");
        return result;
      },
    },
    "pihole.rollback": {
      title: "Remove a denylist push from Pi-hole",
      async run({ log, params, actor }) {
        const result = await sentinel.rollback(Number(params.pushId), actor);
        log(`Removed ${result.removed} entries${result.skipped ? `; ${result.skipped} were already gone or no longer TheySpy's` : ""}.`);
        return result;
      },
    },
  };
}
