import { promises as dnsPromises } from "node:dns";
import net from "node:net";
import { inCidr, normaliseMac, parseCidr } from "./addresses.mjs";
import { checkPorts, profiles } from "./services.mjs";

// The targeted check (docs/PLAN.md M4, mockup 03): one address, MAC, hostname, network or domain.
//  - An address, MAC or hostname resolves to one device: Quick sees whether it is up; Standard and
//    Deep also check its ports; DNS only sends it nothing and reads Pi-hole's history for it.
//  - A network is swept (Quick only).
//  - A domain reads Pi-hole's history: which devices looked it up, and when. No packets.
// Every active check stays inside TS_SCAN_RANGES.

const domainPattern = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/i;

/**
 * What a query names. Throws a 400 for anything else.
 * @param {string} query
 */
export function classify(query) {
  const q = String(query ?? "").trim().replace(/\[\.\]/g, ".");
  if (!q) throw Object.assign(new Error("Type an address, MAC, hostname, network or domain"), { status: 400 });
  if (net.isIPv4(q)) return { kind: "ip", value: q };
  if (q.includes("/") && parseCidr(q)) return { kind: "network", value: parseCidr(q).cidr };
  const mac = normaliseMac(q);
  if (mac && /^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$|^[0-9a-f]{4}(\.[0-9a-f]{4}){2}$|^[0-9a-f]{12}$/i.test(q)) return { kind: "mac", value: mac };
  if (domainPattern.test(q)) return { kind: "name", value: q.toLowerCase() };
  if (/^[a-z0-9-]{1,63}$/i.test(q)) return { kind: "name", value: q.toLowerCase() };
  throw Object.assign(new Error(`"${q}" is not an address, MAC, hostname, network or domain`), { status: 400 });
}

/**
 * @param {{
 *   db: import("node:sqlite").DatabaseSync,
 *   fleet: ReturnType<typeof import("./registry.mjs").createFleet>,
 *   discovery: ReturnType<typeof import("./discovery.mjs").createDiscovery>,
 *   sentinel: ReturnType<typeof import("../pihole/sentinel.mjs").createSentinel>,
 *   audit: ReturnType<typeof import("../audit.mjs").createAuditLog>,
 *   scanRanges: string[],
 *   now?: () => Date,
 *   checkPortsImpl?: typeof checkPorts,
 *   lookup?: (name: string) => Promise<string | null>,
 * }} deps
 */
export function createTargetedCheck({ db, fleet, discovery, sentinel, audit, scanRanges, now = () => new Date(), checkPortsImpl = checkPorts, lookup }) {
  const resolveName = lookup ?? (async (name) => { try { return (await dnsPromises.lookup(name, { family: 4 })).address; } catch { return null; } });
  const allowed = (ip) => scanRanges.some((range) => inCidr(ip, range));
  const q = {
    start: db.prepare("INSERT INTO checks (query, kind, profile, device_id, started_at, actor) VALUES (?, ?, ?, ?, ?, ?)"),
    finish: db.prepare("UPDATE checks SET finished_at = ?, device_id = ?, result = ? WHERE id = ?"),
    get: db.prepare("SELECT * FROM checks WHERE id = ?"),
    recent: db.prepare("SELECT id, query, kind, profile, device_id, started_at, finished_at, actor FROM checks ORDER BY id DESC LIMIT ?"),
    service: db.prepare(`INSERT INTO device_services (device_id, port, proto, service, product, version, banner, tls, risk, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (device_id, port, proto) DO UPDATE SET service = excluded.service, product = COALESCE(excluded.product, product), version = COALESCE(excluded.version, version),
      banner = COALESCE(excluded.banner, banner), tls = COALESCE(excluded.tls, tls), risk = excluded.risk, last_seen = excluded.last_seen`),
    services: db.prepare("SELECT port, proto, service, product, version, banner, tls, risk, first_seen, last_seen FROM device_services WHERE device_id = ? ORDER BY port"),
    clearClosed: db.prepare("DELETE FROM device_services WHERE device_id = ? AND last_seen < ?"),
  };

  const servicesOf = (deviceId) => q.services.all(deviceId).map((raw) => {
    const r = /** @type {any} */ (raw);
    return { port: r.port, proto: r.proto, service: r.service, product: r.product, version: r.version, banner: r.banner, tls: r.tls ? JSON.parse(r.tls) : null, risk: r.risk, firstSeen: r.first_seen, lastSeen: r.last_seen };
  });

  /** Pi-hole's view of one client: its indicator lookups and the names it looks up most. */
  async function dnsView(ip, days = 7) {
    const hits = sentinel.hits().filter((h) => h.clientIp === ip);
    if (!sentinel.effective().mode) return { connected: false, hits, topDomains: [], totalLookups: 0 };
    const until = now().getTime() / 1000;
    const { rows } = await sentinel.source().domainCounts({ client: ip, from: until - days * 86400, until });
    const total = rows.reduce((n, r) => n + r.queries, 0);
    return { connected: true, hits, totalLookups: total, topDomains: [...rows].sort((a, b) => b.queries - a.queries).slice(0, 15) };
  }

  /** Finds the device a MAC or hostname names, or the address a hostname resolves to. */
  async function resolveTarget(kind, value) {
    if (kind === "ip") return { ip: value, device: fleet.list().find((d) => d.ip === value) ?? null };
    if (kind === "mac") {
      const device = fleet.list().find((d) => d.mac === value);
      if (!device?.ip) throw Object.assign(new Error(`No device with MAC ${value} has been seen`), { status: 404 });
      return { ip: device.ip, device };
    }
    const known = fleet.list().find((d) => d.hostname === value || d.hostname?.split(".")[0] === value || d.label?.toLowerCase() === value);
    if (known?.ip) return { ip: known.ip, device: known };
    const ip = await resolveName(value);
    if (ip && allowed(ip)) return { ip, device: fleet.list().find((d) => d.ip === ip) ?? null };
    return null; // not a device on this network: a domain
  }

  const checker = {
    profiles: () => Object.entries(profiles).map(([id, p]) => ({ id, label: p.label, ports: p.ports.length })).concat([{ id: "dns", label: "DNS only", ports: 0 }]),

    /**
     * Runs a check and keeps its result.
     * @param {{ query: string, profile?: string, log?: (line: string) => void }} options @param {string} actor
     */
    async run({ query, profile = "standard", log = () => {} }, actor) {
      if (!["quick", "standard", "deep", "dns"].includes(profile)) throw Object.assign(new Error("profile must be quick, standard, deep or dns"), { status: 400 });
      const { kind, value } = classify(query);
      const started = now();
      const id = Number(q.start.run(query, kind, profile, null, started.toISOString(), actor).lastInsertRowid);
      let result;
      let deviceId = null;

      if (kind === "network") {
        if (profile !== "quick") throw Object.assign(new Error("A network can only be swept (Quick); check one address for its ports"), { status: 400 });
        const sweep = await discovery.sweep({ targets: [value], log, record: false });
        result = { kind: "network", network: value, sweep, devices: fleet.list().filter((d) => d.ip && inCidr(d.ip, value)) };
      } else {
        const target = await resolveTarget(kind, value);
        if (!target) {
          // A domain: who on the network looked it up, from Pi-hole's history. Nothing is sent to it.
          if (!sentinel.effective().mode) throw Object.assign(new Error("Checking a domain reads Pi-hole's history; connect Pi-hole first"), { status: 409 });
          const until = now().getTime() / 1000;
          const lookups = await sentinel.source().lookupsOf(value, { from: until - 30 * 86400, until });
          const byClient = new Map();
          for (const l of lookups) {
            const e = byClient.get(l.clientIp) ?? { ip: l.clientIp, name: l.clientName, lookups: 0, blocked: 0, first: l.at, last: l.at, names: new Set() };
            e.lookups += 1;
            if (/BLOCK|GRAVITY|REGEX|DENYLIST|SPECIAL/.test(l.status)) e.blocked += 1;
            if (l.at < e.first) e.first = l.at;
            if (l.at > e.last) e.last = l.at;
            e.names.add(l.domain);
            byClient.set(l.clientIp, e);
          }
          const devices = fleet.list();
          result = {
            kind: "domain", domain: value, days: 30, lookups: lookups.length,
            indicator: sentinel.hits().some((h) => h.domain === value || h.indicator === value),
            clients: [...byClient.values()].sort((a, b) => b.lookups - a.lookups).map((c) => ({ ...c, names: [...c.names].slice(0, 6), device: devices.find((d) => d.ip === c.ip)?.name ?? c.name ?? null })),
          };
          log(`${value}: ${lookups.length} lookups from ${byClient.size} devices in 30 days.`);
        } else {
          const { ip } = target;
          let device = target.device;
          if (profile !== "dns") {
            if (!allowed(ip)) throw Object.assign(new Error(`${ip} is outside the ranges TheySpy may scan (TS_SCAN_RANGES: ${scanRanges.join(", ")})`), { status: 403 });
            const sweep = await discovery.sweep({ targets: [`${ip}/32`], log, record: false });
            device = fleet.list().find((d) => d.ip === ip) ?? device;
            let open = [];
            if (profile !== "quick") {
              const ports = profiles[profile].ports;
              log(`Checking ${ports.length} ports on ${ip}.`);
              open = await checkPortsImpl(ip, ports, { onProgress: (done) => log(`${done} of ${ports.length} ports checked.`) });
              if (open.length && !device) {
                fleet.observe([{ ip, seenAt: now().toISOString() }], "scan");
                device = fleet.list().find((d) => d.ip === ip) ?? null;
              }
              if (device) {
                const at = now().toISOString();
                for (const s of open) q.service.run(device.id, s.port, s.proto, s.service, s.product, s.version, s.banner, s.tls ? JSON.stringify(s.tls) : null, s.risk, at, at);
                // A full Standard or Deep check is the truth for its ports: forget what no longer answers.
                q.clearClosed.run(device.id, started.toISOString());
              }
              log(`${open.length} open port${open.length === 1 ? "" : "s"}${open.some((s) => s.risk) ? `, ${open.filter((s) => s.risk).length} worth a look` : ""}.`);
            }
            result = { kind: "device", ip, up: sweep.alive > 0 || open.length > 0, open };
          } else {
            result = { kind: "device", ip, up: null, open: null };
          }
          deviceId = device?.id ?? null;
          result.device = device ? fleet.get(device.id) : null;
          result.services = device ? servicesOf(device.id) : [];
          result.dns = await dnsView(ip).catch((error) => ({ connected: true, error: error.message, hits: [], topDomains: [], totalLookups: 0 }));
        }
      }
      const finished = now();
      result.durationMs = finished.getTime() - started.getTime();
      q.finish.run(finished.toISOString(), deviceId, JSON.stringify(result), id);
      audit.record(actor, "fleet.checked", query, { id, kind, profile });
      return { id, query, kind, profile, ...result };
    },

    get(id) {
      const r = /** @type {any} */ (q.get.get(id));
      return r ? { id: r.id, query: r.query, kind: r.kind, profile: r.profile, startedAt: r.started_at, finishedAt: r.finished_at, ...(r.result ? JSON.parse(r.result) : {}) } : null;
    },
    recent: (limit = 15) => q.recent.all(limit).map((raw) => {
      const r = /** @type {any} */ (raw);
      return { id: r.id, query: r.query, kind: r.kind, profile: r.profile, deviceId: r.device_id, startedAt: r.started_at, finishedAt: r.finished_at };
    }),
    servicesOf,
  };
  return checker;
}

/** @param {ReturnType<typeof createTargetedCheck>} checker */
export function targetedJobKinds(checker) {
  return {
    "fleet.check": {
      title: "Targeted check",
      async run({ log, params, actor }) {
        const r = await checker.run({ query: params.query, profile: params.profile, log }, actor);
        return { checkId: r.id };
      },
    },
  };
}
