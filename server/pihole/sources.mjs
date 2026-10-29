import { existsSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { createPiholeClient, PiholeError } from "./client.mjs";
import { findHits, fromApi, statusName } from "./match.mjs";

// Two ways to read Pi-hole's DNS history, with one interface:
//  - "api": Pi-hole 6 over HTTP(S). Hunts ask per indicator (`*name`), from both the in-memory log
//    and the long-term database (which trails it by up to a minute), and merge by query id.
//  - "database": a read-only copy or mount of pihole-FTL.db (Pi-hole 5 or 6; both keep a `queries`
//    table or view with text `domain` and `client`). One pass over the window covers every indicator,
//    and CNAME-blocked lookups too. It cannot read or change Pi-hole's lists.

const key = (q) => `${q.queryId}:${q.at}`;

/**
 * @param {{ url: string, password: string | null, fetchImpl?: typeof fetch }} options
 */
export function apiSource({ url, password, fetchImpl }) {
  const client = () => createPiholeClient({ url, password, fetchImpl });
  return {
    mode: "api",
    canWrite: true,
    client,
    describe: () => `Pi-hole API at ${new URL(url).origin}`,
    async test() {
      return client().session(async (c) => ({ ...(await c.version()) }));
    },
    /**
     * @param {ReturnType<typeof import("./match.mjs").createMatcher>} matcher
     * @param {{ from: number, until: number }} window Unix seconds
     */
    async hunt(matcher, { from, until }) {
      return client().session(async (c) => {
        const seen = new Map();
        for (const name of matcher.domains) {
          for (const disk of [false, true]) {
            for (const row of await c.queries({ domain: `*${name}`, from, until, disk })) {
              const q = fromApi(row);
              seen.set(key(q), q);
            }
          }
        }
        return { queriesSeen: seen.size, hits: findHits(seen.values(), matcher) };
      });
    },
    /** Devices by how much they ask, for choosing a baseline's scope. */
    async clients() {
      return client().session((c) => c.topClients(50));
    },
    /**
     * How often each name was looked up and blocked: one device over a window (from its query log),
     * or the whole network from Pi-hole's own top-domain stats (its in-memory day).
     * @param {{ client?: string, from: number, until: number }} scope
     */
    async domainCounts({ client: ip, from, until }) {
      return client().session(async (c) => {
        if (!ip) return { rows: await c.topDomainCounts(2000), basis: "Pi-hole's 2,000 most-looked-up allowed and blocked names, from its in-memory statistics" };
        const seen = new Map();
        for (const disk of [false, true]) for (const row of await c.queries({ from, until, disk, client: ip })) seen.set(`${row.id}:${row.time}`, row);
        const counts = new Map();
        for (const row of seen.values()) {
          const q = fromApi(row);
          const e = counts.get(q.domain) ?? { domain: q.domain, queries: 0, blocked: 0 };
          e.queries += 1;
          if (/BLOCK|GRAVITY|REGEX|DENYLIST|BLACKLIST|SPECIAL/.test(q.status)) e.blocked += 1;
          counts.set(q.domain, e);
        }
        return { rows: [...counts.values()], basis: `every lookup ${ip} made` };
      });
    },
    /** Everything since `from` in the in-memory log, for the live watch. */
    async recent(matcher, from) {
      return client().session(async (c) => {
        const rows = (await c.queries({ from })).map(fromApi);
        return { queriesSeen: rows.length, hits: findHits(rows, matcher) };
      });
    },
  };
}

/**
 * @param {{ path: string }} options
 */
export function databaseSource({ path }) {
  function open() {
    if (!existsSync(path)) throw new PiholeError(`No Pi-hole database at ${path}. Mount pihole-FTL.db read-only and set its path.`);
    const db = new DatabaseSync(path, { readOnly: true });
    db.exec("PRAGMA query_only = ON; PRAGMA busy_timeout = 5000;");
    return db;
  }
  /** Client names: Pi-hole 6 keeps them in client_by_id, Pi-hole 5 in network_addresses. */
  function clientNames(db) {
    const tables = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type IN ('table', 'view')").all().map((r) => /** @type {any} */ (r).name));
    const table = tables.has("client_by_id") ? "client_by_id" : tables.has("network_addresses") ? "network_addresses" : null;
    const names = new Map();
    if (table) for (const row of db.prepare(`SELECT ip, name FROM ${table} WHERE name IS NOT NULL AND name != ''`).all()) names.set(/** @type {any} */ (row).ip, /** @type {any} */ (row).name);
    return names;
  }
  function* rows(db, from, until) {
    const names = clientNames(db);
    const statement = db.prepare("SELECT id, timestamp, domain, client, status, additional_info FROM queries WHERE timestamp >= ? AND timestamp <= ? ORDER BY id");
    for (const raw of statement.iterate(Math.floor(from), Math.ceil(until))) {
      const row = /** @type {any} */ (raw);
      const status = statusName(Number(row.status));
      yield {
        queryId: Number(row.id),
        at: new Date(Number(row.timestamp) * 1000).toISOString(),
        domain: String(row.domain ?? "").toLowerCase(),
        cname: status.endsWith("_CNAME") && typeof row.additional_info === "string" ? row.additional_info.toLowerCase() : null,
        status,
        clientIp: String(row.client ?? ""),
        clientName: names.get(row.client) ?? null,
      };
    }
  }
  const scan = (matcher, from, until) => {
    const db = open();
    try {
      let queriesSeen = 0;
      const counted = (function* () { for (const q of rows(db, from, until)) { queriesSeen += 1; yield q; } })();
      const hits = findHits(counted, matcher);
      return { queriesSeen, hits };
    } finally {
      db.close();
    }
  };
  return {
    mode: "database",
    canWrite: false,
    describe: () => `Pi-hole database file ${path}`,
    async test() {
      const db = open();
      try {
        const row = /** @type {any} */ (db.prepare("SELECT COUNT(*) AS n, MIN(timestamp) AS first FROM queries").get());
        return { queries: Number(row.n), since: row.first ? new Date(Number(row.first) * 1000).toISOString() : null };
      } finally {
        db.close();
      }
    },
    async hunt(matcher, { from, until }) { return scan(matcher, from, until); },
    async clients() {
      const db = open();
      try {
        const names = clientNames(db);
        return db.prepare("SELECT client, COUNT(*) AS n FROM queries WHERE timestamp >= ? GROUP BY client ORDER BY n DESC LIMIT 50").all(Math.floor(Date.now() / 1000) - 7 * 86400)
          .map((r) => ({ ip: String(/** @type {any} */ (r).client), name: names.get(/** @type {any} */ (r).client) ?? null, queries: Number(/** @type {any} */ (r).n) }));
      } finally { db.close(); }
    },
    async domainCounts({ client: ip, from, until }) {
      const db = open();
      try {
        const blocked = [1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18].join(",");
        const where = `timestamp >= ? AND timestamp <= ?${ip ? " AND client = ?" : ""}`;
        const rows = db.prepare(`SELECT domain, COUNT(*) AS n, SUM(CASE WHEN status IN (${blocked}) THEN 1 ELSE 0 END) AS b FROM queries WHERE ${where} GROUP BY domain ORDER BY n DESC LIMIT 20000`)
          .all(...[Math.floor(from), Math.ceil(until), ...(ip ? [ip] : [])]).map((r) => ({ domain: String(/** @type {any} */ (r).domain).toLowerCase(), queries: Number(/** @type {any} */ (r).n), blocked: Number(/** @type {any} */ (r).b) }));
        return { rows, basis: ip ? `every lookup ${ip} made` : "every lookup on the network" };
      } finally { db.close(); }
    },
    async recent(matcher, from) { return scan(matcher, from, Date.now() / 1000 + 60); },
  };
}
