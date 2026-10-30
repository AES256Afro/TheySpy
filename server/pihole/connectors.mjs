import { createHash } from "node:crypto";
import { PiholeError } from "./client.mjs";
import { findHits } from "./match.mjs";

// DNS servers other than Pi-hole, read-only, behind the same interface as sources.mjs: hunting the
// query log, the live watch, one domain's lookups, one device's lookups and the busiest devices.
// Changing lists (pushes, subscriptions, baselines) and the network table stay Pi-hole's.
//  - AdGuard Home: /control/querylog, paged by `older_than`, `search` matches part of a name.
//  - Technitium DNS: /api/logs/query through its query-log app (Query Logs (Sqlite) or another),
//    with exact `qname` and `*.name` for subdomains, and a start/end window.
//  - OPNsense (Unbound with reporting on): /api/unbound/overview/searchQueries, which returns the
//    latest 1,000 queries; a hunt sees only those, the 30-second watch sees everything new.
// Each answer is mapped to TheySpy's query shape; a blocked answer gets the status BLOCKED.

const pageLimit = 500;
const maxPages = 400; // 200,000 entries a request; a hunt over a long window stops there and says so

/** A stable numeric id for a log entry that has none of its own. */
const idOf = (...parts) => Number.parseInt(createHash("sha256").update(parts.join("|")).digest("hex").slice(0, 12), 16);
const lower = (value) => String(value ?? "").toLowerCase().replace(/\.$/, "");
const within = (name, domain) => name === domain || name.endsWith(`.${domain}`);
const seconds = (iso) => Date.parse(iso) / 1000;

/**
 * Shared behaviour over a source's `queries({ from, until, name?, client? })` iterator.
 * @param {{ mode: string, describe: () => string, test: () => Promise<object>, queries: (scope: { from: number, until: number, name?: string, client?: string }) => AsyncIterable<any>, networkCounts?: () => Promise<{ rows: any[], basis: string }>, topClients?: () => Promise<any[]>, clientLabels?: () => Promise<{ clients: any[], gateway: string | null }>, limits?: string }} parts
 */
function logSource({ mode, describe, test, queries, networkCounts, topClients, clientLabels, limits }) {
  /** @param {{ from: number, until: number, name?: string, client?: string }} scope @param {(query: any) => void} [observe] */
  const collect = async (scope, observe = () => {}) => {
    const out = [];
    for await (const q of queries(scope)) { observe(q); out.push(q); }
    return out;
  };
  return {
    mode,
    canWrite: false,
    limits: limits ?? null,
    describe,
    test,
    async hunt(matcher, { from, until }) {
      const seen = new Map();
      for (const name of matcher.domains) for (const q of await collect({ from, until, name })) seen.set(`${q.queryId}:${q.at}`, q);
      return { queriesSeen: seen.size, hits: findHits(seen.values(), matcher) };
    },
    /** @param {any} matcher @param {number} from @param {(query: any) => void} [observe] */
    async recent(matcher, from, observe = () => {}) {
      const rows = await collect({ from, until: Date.now() / 1000 + 60 }, observe);
      return { queriesSeen: rows.length, hits: findHits(rows, matcher) };
    },
    async lookupsOf(domain, { from, until }) {
      return (await collect({ from, until, name: domain })).filter((q) => within(q.domain, domain));
    },
    async domainCounts({ client, from, until }) {
      if (!client && networkCounts) return networkCounts();
      const counts = new Map();
      for (const q of await collect({ from, until, client })) {
        const e = counts.get(q.domain) ?? { domain: q.domain, queries: 0, blocked: 0 };
        e.queries += 1;
        if (q.status === "BLOCKED") e.blocked += 1;
        counts.set(q.domain, e);
      }
      return { rows: [...counts.values()], basis: client ? `every lookup ${client} made` : "every lookup on the network" };
    },
    async clients() {
      if (topClients) return topClients();
      const counts = new Map();
      for (const q of await collect({ from: Date.now() / 1000 - 7 * 86400, until: Date.now() / 1000 })) counts.set(q.clientIp, { ip: q.clientIp, name: q.clientName, queries: (counts.get(q.clientIp)?.queries ?? 0) + 1 });
      return [...counts.values()].sort((a, b) => b.queries - a.queries).slice(0, 50);
    },
    clientLabels: clientLabels ?? (async () => ({ clients: [], gateway: null })),
    async networkDevices() { return []; },
  };
}

/** HTTP for the connectors: JSON, a timeout, and errors in the server's own words. */
function caller({ url, fetchImpl = fetch, headers = {}, name }) {
  const origin = new URL(url).origin;
  return async (path, init = {}) => {
    let response;
    try {
      response = await fetchImpl(`${origin}${path}`, { ...init, headers: { accept: "application/json", ...headers, ...(init.headers ?? {}) }, signal: AbortSignal.timeout(30_000) });
    } catch (error) {
      throw new PiholeError(`Could not reach ${name} at ${origin}: ${error.cause?.code ?? error.message}`);
    }
    if (response.status === 401 || response.status === 403) throw new PiholeError(`${name} refused the sign-in (${response.status}); check the user and password or token.`);
    if (!response.ok) throw new PiholeError(`${name} answered ${response.status} to ${path.split("?")[0]}`);
    return response.json();
  };
}

/**
 * AdGuard Home, with a user and password (HTTP basic, as its own API uses).
 * @param {{ url: string, username: string | null, password: string | null, fetchImpl?: typeof fetch }} options
 */
export function adguardSource({ url, username, password, fetchImpl }) {
  const get = caller({ url, fetchImpl, name: "AdGuard Home", headers: username ? { authorization: `Basic ${Buffer.from(`${username}:${password ?? ""}`).toString("base64")}` } : {} });
  const toQuery = (e) => {
    const at = new Date(e.time).toISOString();
    const clientIp = String(e.client ?? "");
    return {
      queryId: idOf(e.time, clientIp, e.question?.name, e.question?.type), at, domain: lower(e.question?.name), cname: null,
      status: String(e.reason ?? "").startsWith("Filtered") ? "BLOCKED" : e.cached ? "CACHE" : "FORWARDED",
      clientIp, clientName: e.client_info?.name || null,
    };
  };
  return logSource({
    mode: "adguard",
    describe: () => `AdGuard Home at ${new URL(url).origin}`,
    async test() {
      const s = await get("/control/status");
      return { version: s.version ?? null, running: s.running ?? null, protection: s.protection_enabled ?? null };
    },
    async *queries({ from, until, name, client }) {
      let olderThan = "";
      for (let page = 0; page < maxPages; page += 1) {
        const search = name ?? client ?? "";
        const data = await get(`/control/querylog?limit=${pageLimit}&response_status=all${search ? `&search=${encodeURIComponent(search)}` : ""}${olderThan ? `&older_than=${encodeURIComponent(olderThan)}` : ""}`);
        const entries = data.data ?? [];
        for (const e of entries) {
          const t = seconds(e.time);
          if (t > until) continue;
          if (t < from) return;
          const q = toQuery(e);
          if (client && q.clientIp !== client) continue;
          yield q;
        }
        if (!entries.length || !data.oldest || data.oldest === olderThan) return;
        olderThan = data.oldest;
      }
    },
    async networkCounts() {
      const s = await get("/control/stats");
      const blocked = new Map((s.top_blocked_domains ?? []).flatMap((o) => Object.entries(o)));
      const rows = (s.top_queried_domains ?? []).flatMap((o) => Object.entries(o)).map(([domain, n]) => ({ domain: lower(domain), queries: Number(n), blocked: Number(blocked.get(domain) ?? 0) }));
      for (const [domain, n] of blocked) if (!rows.some((r) => r.domain === lower(domain))) rows.push({ domain: lower(domain), queries: Number(n), blocked: Number(n) });
      return { rows, basis: "AdGuard Home's most-looked-up and most-blocked names, from its statistics" };
    },
    async topClients() {
      const s = await get("/control/stats");
      return (s.top_clients ?? []).flatMap((o) => Object.entries(o)).map(([ip, n]) => ({ ip, name: null, queries: Number(n) }));
    },
    async clientLabels() {
      const c = await get("/control/clients");
      const clients = (c.clients ?? []).flatMap((x) => (x.ids ?? []).map((id) => ({ client: String(id), label: x.name?.trim() || null })));
      return { clients, gateway: null };
    },
  });
}

/**
 * Technitium DNS Server, with an API token (Administration → Sessions → Create Token). Its query
 * log lives in a query-logger app; the first one installed is used.
 * @param {{ url: string, password: string | null, fetchImpl?: typeof fetch }} options
 */
export function technitiumSource({ url, password: token, fetchImpl }) {
  const get = caller({ url, fetchImpl, name: "Technitium" });
  const api = async (path, params = {}) => {
    const query = new URLSearchParams({ token: token ?? "", ...params });
    const body = await get(`${path}?${query}`);
    if (body.status === "invalid-token") throw new PiholeError("Technitium refused the API token; create one under Administration → Sessions.");
    if (body.status !== "ok") throw new PiholeError(`Technitium: ${body.errorMessage ?? body.status}`);
    return body.response ?? {};
  };
  let logger = null;
  async function findLogger() {
    if (logger) return logger;
    for (const app of (await api("/api/apps/list")).apps ?? []) {
      const dns = (app.dnsApps ?? []).find((x) => x.isQueryLogger);
      if (dns) { logger = { name: app.name, classPath: dns.classPath }; return logger; }
    }
    throw new PiholeError("Technitium has no query-log app. Install \"Query Logs (Sqlite)\" from Apps → App Store, so TheySpy can read lookups.");
  }
  const blockedTypes = new Set(["Blocked", "UpstreamBlocked", "CacheBlocked"]);
  const toQuery = (e) => ({
    queryId: idOf(e.timestamp, e.clientIpAddress, e.qname, e.qtype, e.rowNumber), at: new Date(e.timestamp).toISOString(), domain: lower(e.qname), cname: null,
    status: blockedTypes.has(e.responseType) ? "BLOCKED" : e.responseType === "Cached" ? "CACHE" : e.responseType === "Authoritative" ? "LOCAL" : "FORWARDED",
    clientIp: String(e.clientIpAddress ?? ""), clientName: null,
  });
  return logSource({
    mode: "technitium",
    describe: () => `Technitium DNS at ${new URL(url).origin}`,
    async test() {
      const session = await get(`/api/user/session/get?${new URLSearchParams({ token: token ?? "" })}`);
      if (session.status !== "ok") throw new PiholeError("Technitium refused the API token; create one under Administration → Sessions.");
      const found = await findLogger();
      return { version: session.info?.version ?? null, queryLog: found.name };
    },
    async *queries({ from, until, name, client }) {
      const { name: app, classPath } = await findLogger();
      const window = { start: new Date(from * 1000).toISOString(), end: new Date(until * 1000).toISOString() };
      // An exact name and its subdomains are two filters in Technitium.
      const names = name ? [name, `*.${name}`] : [null];
      for (const qname of names) {
        for (let page = 1; page <= maxPages; page += 1) {
          const r = await api("/api/logs/query", { name: app, classPath, pageNumber: String(page), entriesPerPage: String(pageLimit), descendingOrder: "true", ...window, ...(qname ? { qname } : {}), ...(client ? { clientIpAddress: client } : {}) });
          for (const e of r.entries ?? []) yield toQuery(e);
          if (page >= Number(r.totalPages ?? 0)) break;
        }
      }
    },
    async networkCounts() {
      const r = await api("/api/dashboard/stats/get", { type: "LastDay" });
      const blocked = new Map((r.topBlockedDomains ?? []).map((d) => [lower(d.name), Number(d.hits)]));
      const rows = (r.topDomains ?? []).map((d) => ({ domain: lower(d.name), queries: Number(d.hits), blocked: blocked.get(lower(d.name)) ?? 0 }));
      for (const [domain, n] of blocked) if (!rows.some((x) => x.domain === domain)) rows.push({ domain, queries: n, blocked: n });
      return { rows, basis: "Technitium's most-looked-up and most-blocked names over the last day" };
    },
    async topClients() {
      const r = await api("/api/dashboard/stats/get", { type: "LastDay" });
      return (r.topClients ?? []).map((c) => ({ ip: String(c.name), name: c.domain || null, queries: Number(c.hits) }));
    },
  });
}

/**
 * OPNsense's Unbound, with an API key and secret (System → Access → Users → API keys). Needs
 * Services → Unbound DNS → General → Statistics (reporting) on.
 * @param {{ url: string, username: string | null, password: string | null, fetchImpl?: typeof fetch }} options
 */
export function opnsenseSource({ url, username: key, password: secret, fetchImpl }) {
  const get = caller({ url, fetchImpl, name: "OPNsense", headers: { authorization: `Basic ${Buffer.from(`${key ?? ""}:${secret ?? ""}`).toString("base64")}` } });
  const toQuery = (r) => {
    const t = Number(r.time);
    const at = new Date((t > 1e12 ? t : t * 1000)).toISOString();
    const client = String(r.client ?? "");
    const isIp = /^[\d.]+$|:/.test(client);
    return {
      queryId: idOf(r.time, client, r.domain, r.type), at, domain: lower(r.domain), cname: null,
      status: ["Block", "Drop"].includes(r.action) ? "BLOCKED" : r.source === "Cache" ? "CACHE" : ["Local", "Local-data"].includes(r.source) ? "LOCAL" : "FORWARDED",
      clientIp: client, clientName: isIp ? null : client,
    };
  };
  const latest = async (searchPhrase = "") => {
    const body = new URLSearchParams({ current: "1", rowCount: "1000", ...(searchPhrase ? { searchPhrase } : {}) });
    const r = await get("/api/unbound/overview/searchQueries", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: String(body) });
    return (r.rows ?? []).map(toQuery);
  };
  return logSource({
    mode: "opnsense",
    limits: "OPNsense's API returns the latest 1,000 lookups, so a hunt covers only those; the 30-second watch sees every new one.",
    describe: () => `OPNsense Unbound at ${new URL(url).origin}`,
    async test() {
      const enabled = await get("/api/unbound/overview/isEnabled");
      if (!Number(enabled.enabled ?? enabled.result ?? 0)) throw new PiholeError("Unbound reporting is off in OPNsense: Services → Unbound DNS → General → Statistics.");
      const rows = await latest();
      return { reporting: true, recentLookups: rows.length };
    },
    async *queries({ from, until, name, client }) {
      for (const q of await latest(name ?? client ?? "")) {
        const t = seconds(q.at);
        if (t < from || t > until) continue;
        if (client && q.clientIp !== client) continue;
        yield q;
      }
    },
    async networkCounts() {
      const r = await get("/api/unbound/overview/totals/50");
      const blocked = new Map(Object.entries(r.top_blocked ?? {}).map(([domain, v]) => [lower(domain), Number(v?.total ?? v ?? 0)]));
      const rows = Object.entries(r.top ?? {}).map(([domain, v]) => ({ domain: lower(domain), queries: Number(v?.total ?? v ?? 0), blocked: blocked.get(lower(domain)) ?? 0 }));
      for (const [domain, n] of blocked) if (!rows.some((x) => x.domain === domain)) rows.push({ domain, queries: n, blocked: n });
      return { rows, basis: "OPNsense's most-looked-up and most-blocked names" };
    },
  });
}
