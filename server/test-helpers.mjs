import { readFileSync } from "node:fs";
import { createAuditLog } from "./audit.mjs";
import { createAuth } from "./auth.mjs";
import { createSettingsStore, openDatabase } from "./db.mjs";
import { createBackup } from "./backup.mjs";
import { createNetworkLogs } from "./netlogs.mjs";
import { createIocStore } from "./iocs/store.mjs";
import { createIocUpdater, iocJobKinds } from "./iocs/updater.mjs";
import { createJobRunner, jobKinds } from "./jobs.mjs";
import { createSentinel, piholeJobKinds } from "./pihole/sentinel.mjs";
import { createSecretBox } from "./secrets.mjs";
import { blocklistJobKinds, createBlocklistLibrary } from "./blocklists/library.mjs";
import { baselineJobKinds, createBaselines } from "./blocklists/baselines.mjs";
import { createDiscovery, fleetJobKinds } from "./fleet/discovery.mjs";
import { createFleet } from "./fleet/registry.mjs";
import { createOui, ouiJobKinds } from "./fleet/oui.mjs";
import { createCveStore, cveJobKinds } from "./cves/store.mjs";
import { createAdvisories } from "./cves/advisories.mjs";
import { createWebScanner } from "./web/scan.mjs";
import { createSoftwareLookup } from "./cves/lookup.mjs";
import { createDeviceCves } from "./cves/devices.mjs";
import { createAlerts } from "./alerts.mjs";
import { createDigest } from "./digest.mjs";
import { createApiTokens } from "./integrations.mjs";
import { createReadModel } from "./readmodel.mjs";
import { createAgents } from "./agents.mjs";
import { createExposure } from "./exposure.mjs";
import { createTargetedCheck, targetedJobKinds } from "./fleet/targeted.mjs";

/** A clock tests can move. */
export function testClock(start = "2026-10-29T12:00:00.000Z") {
  let at = Date.parse(start);
  const now = () => new Date(at);
  now.advance = (ms) => { at += ms; };
  return now;
}

/** Bytes of a vendored zero-breach file. */
export const vendored = (path) => readFileSync(new URL(`../third_party/zero-breach/${path}`, import.meta.url));

/**
 * A stand-in for GitHub: serves the vendored v0.1.8 release by default; `files` overrides or adds
 * paths (a value of null answers 404).
 * @param {Record<string, string | Buffer | null>} [files]
 */
export function fakeGitHub(files = {}) {
  const release = "release-signatures/v0.1.8/";
  const base = {
    "https://api.github.com/repos/interplains/zero-breach/releases/latest": JSON.stringify({ tag_name: "v0.1.8" }),
    [`https://raw.githubusercontent.com/interplains/zero-breach/main/${release}SHA256SUMS.txt`]: vendored(`${release}SHA256SUMS.txt`),
    [`https://raw.githubusercontent.com/interplains/zero-breach/main/${release}SHA256SUMS.txt.asc`]: vendored(`${release}SHA256SUMS.txt.asc`),
    "https://raw.githubusercontent.com/interplains/zero-breach/v0.1.8/iocs/adfection_iocs.txt": vendored("iocs/adfection_iocs.txt"),
    "https://raw.githubusercontent.com/interplains/zero-breach/main/iocs/adfection_iocs.txt": vendored("iocs/adfection_iocs.txt"),
    "https://raw.githubusercontent.com/interplains/zero-breach/main/iocs/adfection_iocs.txt.sha256": vendored("iocs/adfection_iocs.txt.sha256"),
  };
  const table = { ...base, ...files };
  const requested = [];
  /** @type {typeof fetch & { requested: string[] }} */
  const fetchImpl = Object.assign(async (url) => {
    requested.push(String(url));
    const body = table[String(url)];
    if (body === undefined || body === null) return new Response("not found", { status: 404 });
    return new Response(body, { status: 200 });
  }, { requested });
  return fetchImpl;
}

/**
 * A Pi-hole 6 API stand-in, behaving as a live FTL v6.7 did when probed: X-FTL-SID sessions,
 * newest-first paging with a fixed cursor and a `start` offset, `*name` as a plain suffix match,
 * search over exact and regex entries plus adlist (gravity) names, and regex deny entries.
 * @param {{ password?: string, queries?: any[], gravity?: Record<string, string>, network?: any[], gateway?: string | null }} [options]
 *   gravity maps an exact name to the address of the adlist that blocks it; network is the network
 *   table in the API's shape
 */
export function fakePihole({ password = "pihole-pass", queries = [], gravity = {}, network = [], gateway = null } = {}) {
  const state = { queries: [...queries], gravity: { ...gravity }, network: [...network], gateway, domains: [], sessions: new Set(), nextId: 1, logins: 0, logouts: 0, requests: [], groups: [{ id: 0, name: "Default", comment: "The default group", enabled: true }], clients: [], adlists: [], gravityEntries: 3 };
  const json = (status, body) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const listed = (type, kind) => state.domains.filter((d) => d.type === type && d.kind === kind);
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(String(input));
    const method = init.method ?? "GET";
    const path = url.pathname.replace(/^\/api\//, "");
    state.requests.push(`${method} ${path}`);
    const body = init.body ? JSON.parse(String(init.body)) : undefined;
    if (path === "auth" && method === "POST") {
      if (body?.password !== password) return json(401, { session: { valid: false } });
      const sid = `sid-${state.logins += 1}`;
      state.sessions.add(sid);
      return json(200, { session: { valid: true, totp: false, sid, csrf: "x", validity: 1800 } });
    }
    const sid = /** @type {any} */ (init.headers)?.["X-FTL-SID"];
    if (!state.sessions.has(sid)) return json(401, { error: { key: "unauthorized", message: "Unauthorized" } });
    if (path === "auth" && method === "DELETE") { state.sessions.delete(sid); state.logouts += 1; return new Response(null, { status: 204 }); }
    if (path === "info/version") return json(200, { version: { core: { local: { version: "v6.4.3" } }, ftl: { local: { version: "v6.7" } }, web: { local: { version: "v6.5" } } } });
    if (path === "queries") {
      const p = url.searchParams;
      const domain = p.get("domain");
      let rows = state.queries.filter((q) => (p.get("disk") === "true" ? q.onDisk !== false : q.inMemory !== false));
      if (p.get("from")) rows = rows.filter((q) => q.time >= Number(p.get("from")));
      if (p.get("until")) rows = rows.filter((q) => q.time <= Number(p.get("until")));
      if (domain) rows = rows.filter((q) => (domain.startsWith("*") ? q.domain.endsWith(domain.slice(1)) : q.domain === domain));
      if (p.get("client_ip")) rows = rows.filter((q) => q.client.ip === p.get("client_ip"));
      rows = rows.sort((a, b) => b.id - a.id);
      const cursor = p.get("cursor") ? Number(p.get("cursor")) : rows[0]?.id ?? null;
      const pinned = rows.filter((q) => cursor === null || q.id <= cursor);
      const start = Number(p.get("start") ?? 0);
      const length = Number(p.get("length") ?? 100);
      return json(200, { queries: pinned.slice(start, start + length).map(({ onDisk: _onDisk, inMemory: _inMemory, ...q }) => q), cursor, recordsTotal: state.queries.length, recordsFiltered: pinned.length, draw: 0 });
    }
    if (path.startsWith("search/")) {
      const name = decodeURIComponent(path.slice("search/".length));
      const domains = state.domains.filter((d) => (d.kind === "exact" ? d.domain === name : new RegExp(d.domain).test(name)));
      const lists = state.gravity[name] ? [{ domain: name, address: state.gravity[name], type: "block", enabled: true }] : [];
      return json(200, { search: { domains, gravity: lists, results: { domains: { exact: domains.filter((d) => d.kind === "exact").length, regex: domains.filter((d) => d.kind === "regex").length }, gravity: { allow: 0, block: lists.length }, total: domains.length + lists.length } } });
    }
    if (path === "network/devices") return json(200, { devices: state.network, took: 0 });
    if (path === "network/gateway") return json(200, { gateway: state.gateway ? [{ family: "inet", interface: "eth0", address: state.gateway, local: [] }] : [], took: 0 });
    if (path === "stats/top_clients") {
      const byClient = new Map();
      for (const q of state.queries) { const e = byClient.get(q.client.ip) ?? { ip: q.client.ip, name: q.client.name ?? "", count: 0 }; e.count += 1; byClient.set(q.client.ip, e); }
      return json(200, { clients: [...byClient.values()].sort((a, b) => b.count - a.count) });
    }
    if (path === "stats/top_domains") {
      const blocked = url.searchParams.get("blocked") === "true";
      const byDomain = new Map();
      for (const q of state.queries.filter((x) => /GRAVITY|REGEX|DENYLIST/.test(x.status) === blocked)) byDomain.set(q.domain, (byDomain.get(q.domain) ?? 0) + 1);
      return json(200, { domains: [...byDomain].map(([d, count]) => ({ domain: d, count })) });
    }
    if (path === "groups" && method === "GET") return json(200, { groups: state.groups });
    if (path === "groups" && method === "POST") { const g = { id: state.groups.length, name: body.name, comment: body.comment, enabled: true }; state.groups.push(g); return json(201, { groups: [g] }); }
    if (path.startsWith("groups/") && method === "DELETE") { state.groups = state.groups.filter((g) => g.name !== decodeURIComponent(path.slice(7))); return new Response(null, { status: 204 }); }
    if (path === "clients" && method === "GET") return json(200, { clients: state.clients });
    if (path === "clients" && method === "POST") { state.clients.push({ client: body.client, groups: body.groups, comment: body.comment }); return json(201, {}); }
    if (path.startsWith("clients/") && method === "PUT") { const c = state.clients.find((x) => x.client === decodeURIComponent(path.slice(8))); Object.assign(c, { groups: body.groups, comment: body.comment }); return json(200, {}); }
    if (path.startsWith("clients/") && method === "DELETE") { state.clients = state.clients.filter((x) => x.client !== decodeURIComponent(path.slice(8))); return new Response(null, { status: 204 }); }
    if (path === "lists" && method === "GET") return json(200, { lists: state.adlists });
    if (path === "lists" && method === "POST") { state.adlists.push({ address: body.address, comment: body.comment, groups: body.groups, enabled: true, number: 0 }); return json(201, {}); }
    if (path.startsWith("lists/") && method === "DELETE") { state.adlists = state.adlists.filter((l) => l.address !== decodeURIComponent(path.slice(6))); return new Response(null, { status: 204 }); }
    if (path === "action/gravity") { for (const l of state.adlists) l.number = state.gravityEntries ?? 3; return new Response("  [i] Target: x\n  [i] Status: Retrieval successful\n", { status: 200 }); }
    const listMatch = /^domains\/(allow|deny)\/(exact|regex)$/.exec(path);
    if (listMatch && method === "GET") return json(200, { domains: listed(listMatch[1], listMatch[2]) });
    if (listMatch && method === "POST") {
      const items = Array.isArray(body.domain) ? body.domain : [body.domain];
      if (items.some((item) => state.domains.some((d) => d.domain === item && d.type === listMatch[1] && d.kind === listMatch[2]))) return json(400, { error: { key: "database_error", message: "The item is already present" } });
      for (const item of items) state.domains.push({ id: state.nextId++, domain: item, type: listMatch[1], kind: listMatch[2], comment: body.comment ?? null, enabled: body.enabled ?? true, groups: body.groups ?? [0] });
      return json(201, { domains: [], processed: { success: items.map((item) => ({ item })), errors: [] } });
    }
    if (path === "domains:batchDelete" && method === "POST") {
      state.domains = state.domains.filter((d) => !body.some((b) => b.item === d.domain && b.type === d.type && b.kind === d.kind));
      return new Response(null, { status: 204 });
    }
    return json(404, { error: { key: "not_found", message: path } });
  };
  return { fetchImpl, state };
}

/**
 * A web server for blocklists and directories. `files` maps a URL to its body (a string), to
 * { status, body, etag }, or to null for 404; it can be changed between calls. Conditional GETs
 * get a 304 when the ETag still matches.
 * @param {Record<string, any>} files
 */
export function fakeWeb(files = {}) {
  const state = { files: { ...files }, requests: [] };
  const fetchImpl = async (input, init = {}) => {
    const url = String(input);
    state.requests.push(url);
    const entry = state.files[url];
    if (entry === undefined || entry === null) return new Response("not found", { status: 404 });
    const { status = 200, body = "", etag } = typeof entry === "string" ? { body: entry } : entry;
    const ifNoneMatch = /** @type {any} */ (init.headers)?.["if-none-match"];
    if (etag && ifNoneMatch === etag) return new Response(null, { status: 304 });
    return new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: etag ? { etag } : {} });
  };
  return { fetchImpl, state };
}

/**
 * Everything the app needs, in memory, with the bundled indicator set seeded.
 * @param {{ adminPassword?: string | null, sessionSecret?: string | null, now?: () => Date, db?: import("node:sqlite").DatabaseSync, fetchImpl?: typeof fetch, piholeFetch?: typeof fetch, piholeEnv?: object, webFetch?: typeof fetch, popular?: () => Promise<string[]>, network?: Partial<{ neighbours: () => Promise<{ ip: string, mac: string }[]>, probeHost: (ip: string) => Promise<{ port: number, answer: string } | null>, reverse: (ip: string) => Promise<string | null>, reverseVia: (server: string, ip: string) => Promise<string | null>, checkPortsImpl: any, lookup: (name: string) => Promise<string | null> }>, scanRanges?: string[], ntfyFetch?: typeof fetch, ntfyEnv?: { url?: string, topic?: string, token?: string } }} [options]
 */
export function testServices({ adminPassword = "correct horse", sessionSecret = "test-secret", now = testClock(), db = openDatabase(":memory:"), fetchImpl = fakeGitHub(), piholeFetch = fakePihole().fetchImpl, piholeEnv = {}, webFetch = fakeWeb().fetchImpl, popular, network = {}, scanRanges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], ntfyFetch = async () => new Response("", { status: 200 }), ntfyEnv = {} } = {}) {
  const settings = createSettingsStore(db, { now });
  const audit = createAuditLog(db, { now });
  const auth = createAuth({ db, settings, audit, adminPassword, sessionSecret, now });
  const iocStore = createIocStore({ db, audit, now });
  iocStore.seedBundled();
  const updater = createIocUpdater({ fetchImpl });
  const sentinel = createSentinel({ db, settings, audit, iocStore, secretBox: createSecretBox(auth.deriveKey("settings")), env: piholeEnv, fetchImpl: piholeFetch, now });
  const library = createBlocklistLibrary({ db, settings, audit, iocStore, fetchImpl: webFetch, popular, now });
  library.seed();
  const baselines = createBaselines({ db, library, sentinel, settings, audit, now });
  const oui = createOui({ db, settings, fetchImpl: webFetch, now });
  const fleet = createFleet({ db, audit, now, vendorOf: oui.vendorOf, gateway: () => settings.get("fleet_gateway") ?? null });
  const cves = createCveStore({ db, settings, audit, fetchImpl: webFetch, now, sleep: async () => {} });
  const advisories = createAdvisories({ cves, settings, fetchImpl: webFetch, now });
  // No real network in tests: no neighbours, nothing answers, no names, unless a test says so.
  const { checkPortsImpl = async () => [], lookup = async () => null, ...probes } = network;
  const discovery = createDiscovery({ fleet, sentinel, settings, audit, scanRanges, now, neighbours: async () => [], probeHost: async () => null, reverse: async () => null, reverseVia: async () => null, ...probes });
  // Websites in tests: the fake web, addresses from the test's lookup, no DNS TXT records.
  const software = createSoftwareLookup({ db, cves, fetchImpl: webFetch, now, sleep: async () => {} });
  const web = createWebScanner({ db, software, audit, verificationKey: auth.deriveKey("web-verification"), scanRanges, fetchImpl: webFetch, now,
    resolve: async (host) => { const ip = await lookup(host); return ip ? [ip] : []; }, resolveTxt: async () => [] });
  const checker = createTargetedCheck({ db, fleet, discovery, sentinel, audit, scanRanges, now, checkPortsImpl, lookup, web });
  const agents = createAgents({ db, fleet, iocStore, audit, secretBox: createSecretBox(auth.deriveKey("agents")), now });
  const deviceCves = createDeviceCves({ db, fleet, services: checker.servicesOf, software, audit, now, reported: agents.inventory });
  /** @type {any} */ let read;
  const alerts = createAlerts({ db, settings, audit, secretBox: createSecretBox(auth.deriveKey("alerts")), env: ntfyEnv, names: () => fleet.namesByIp(), kevMatches: (ids) => read.kevMatches(ids), fetchImpl: ntfyFetch, now });
  const digest = createDigest({ fleet, sentinel, cves, library, alerts, now });
  read = createReadModel({ fleet, sentinel, cves, deviceCves, digest: () => digest, now });
  const tokens = createApiTokens({ db, audit, now });
  const exposure = createExposure({ fleet, sentinel, agents, read, deviceCves, settings, audit, fetchImpl: webFetch, now });
  const jobs = createJobRunner({ db, audit, now, kinds: { ...jobKinds, ...iocJobKinds({ store: iocStore, updater, settings, now }), ...piholeJobKinds(sentinel), ...blocklistJobKinds(library), ...baselineJobKinds(baselines), ...fleetJobKinds(discovery), ...targetedJobKinds(checker), ...ouiJobKinds(oui), ...cveJobKinds(cves, advisories) } });
  return { db, settings, audit, auth, jobs, iocStore, updater, sentinel, library, baselines, fleet, discovery, checker, oui, cves, web, software, deviceCves, alerts, digest, read, tokens, advisories, agents, exposure, backup: createBackup({ db, audit, now }), netlogs: createNetworkLogs({ db, fleet, iocStore, audit, now }), now };
}
