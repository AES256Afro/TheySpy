import { randomBytes } from "node:crypto";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { pathToFileURL } from "node:url";
import { createAgents } from "./agents.mjs";
import { createAlerts } from "./alerts.mjs";
import { createAuditLog } from "./audit.mjs";
import { createBlocklistLibrary } from "./blocklists/library.mjs";
import { readConfig } from "./config.mjs";
import { createDeviceCves } from "./cves/devices.mjs";
import { createSoftwareLookup } from "./cves/lookup.mjs";
import { createCveStore } from "./cves/store.mjs";
import { createSettingsStore } from "./db.mjs";
import { createDigest } from "./digest.mjs";
import { createFleet } from "./fleet/registry.mjs";
import { createOui } from "./fleet/oui.mjs";
import { defang } from "./iocs/parse.mjs";
import { createIocStore } from "./iocs/store.mjs";
import { createSentinel } from "./pihole/sentinel.mjs";
import { createReadModel } from "./readmodel.mjs";
import { createSecretBox } from "./secrets.mjs";
import { productVersion } from "./shared.mjs";

// What TheySpy found, for a tool on the same machine that cannot sign in: BoxPilot's "Spyware
// watch" agent runs `node server/summary.mjs` inside the container (docker exec) and reads the
// JSON it prints. The database is opened read-only, so nothing here can change it, and nothing
// is fetched. Every list is capped and every string bounded; indicators are defanged.

const clip = (value, max = 120) => { const text = String(value ?? ""); return text.length > max ? `${text.slice(0, max - 1)}…` : text; };

/**
 * @param {DatabaseSync} db A read-only connection.
 * @param {{ days?: number, now?: () => Date, env?: Record<string, string | undefined> }} [options]
 */
export function summarize(db, { days = 7, now = () => new Date(), env = {} } = {}) {
  const config = readConfig(env);
  // Sealed credentials stay sealed: nothing here needs Pi-hole's password or ntfy's token.
  const box = createSecretBox(randomBytes(32));
  const settings = createSettingsStore(db, { now });
  const audit = createAuditLog(db, { now });
  const iocStore = createIocStore({ db, audit, now });
  const fetchImpl = async () => { throw new Error("The summary fetches nothing"); };
  const sentinel = createSentinel({ db, settings, audit, iocStore, secretBox: box, env: config.pihole, fetchImpl, now });
  const library = createBlocklistLibrary({ db, settings, audit, iocStore, fetchImpl, popular: async () => [], now });
  const oui = createOui({ db, settings, fetchImpl, now });
  const fleet = createFleet({ db, audit, now, vendorOf: oui.vendorOf, gateway: () => settings.get("fleet_gateway") ?? null });
  const cves = createCveStore({ db, settings, audit, fetchImpl, now });
  const software = createSoftwareLookup({ db, cves, fetchImpl, now });
  const agents = createAgents({ db, fleet, iocStore, audit, secretBox: box, now });
  // The same rows the targeted check's servicesOf returns (fleet/targeted.mjs).
  const servicesQuery = db.prepare("SELECT * FROM device_services WHERE device_id = ? ORDER BY port");
  const services = (deviceId) => servicesQuery.all(deviceId).map((raw) => {
    const r = /** @type {any} */ (raw);
    return { port: r.port, proto: r.proto, service: r.service, product: r.product, version: r.version, banner: r.banner, tls: r.tls ? JSON.parse(r.tls) : null, risk: r.risk, firstSeen: r.first_seen, lastSeen: r.last_seen };
  });
  const deviceCves = createDeviceCves({ db, fleet, services, software, audit, now, reported: agents.inventory });
  const alerts = createAlerts({ db, settings, audit, secretBox: box, env: {}, fetchImpl, now });
  const digest = createDigest({ fleet, sentinel, cves, library, alerts, now });
  const read = createReadModel({ fleet, sentinel, cves, deviceCves, digest: () => digest, now });

  const since = new Date(now().getTime() - days * 86_400_000).toISOString();
  const lookups = /** @type {any[]} */ (read.indicatorLookups(days)).sort((a, b) => (b.lookups - b.blocked) - (a.lookups - a.blocked) || b.lookups - a.lookups);
  const exploited = /** @type {any[]} */ (read.exploitedOnDevices());
  const findings = /** @type {any[]} */ (db.prepare(`SELECT f.kind, f.indicator, f.source, f.at, COALESCE(d.label, d.hostname, d.ip) AS device FROM findings f LEFT JOIN devices d ON d.id = f.device_id WHERE f.status = 'open' ORDER BY f.at DESC`).all());
  const contacted = findings.filter((f) => f.kind === "contacted");
  const lastReport = /** @type {any} */ (db.prepare("SELECT MAX(last_report_at) AS at, COUNT(*) AS n FROM agents WHERE revoked_at IS NULL").get());
  const test = settings.get("pihole_last_test");
  const status = digest.compose(days);

  return {
    theyspy: productVersion,
    at: now().toISOString(),
    days,
    pihole: { connected: Boolean(sentinel.effective().mode), lastTest: test ? { ok: Boolean(test.ok), at: test.at ?? null } : null },
    sections: status.sections.map((s) => ({ title: s.title, tone: s.tone, lines: s.lines.map((line) => clip(line, 300)) })),
    indicatorLookups: {
      total: lookups.length,
      notFullyBlocked: lookups.filter((l) => l.blocked < l.lookups).length,
      top: lookups.slice(0, 10).map((l) => ({ device: clip(l.device, 60), indicator: clip(l.indicator, 100), lookups: l.lookups, blocked: l.blocked, lastSeen: l.lastSeen })),
    },
    exploitedOnDevices: {
      total: exploited.length,
      top: exploited.slice(0, 10).map((e) => ({ cve: e.cveId, name: clip(e.name, 100), device: clip(e.device, 60), software: clip(e.software, 60), fixedIn: e.fixed ?? null, due: e.due ?? null })),
    },
    evidence: {
      contacted: contacted.length,
      newThisPeriod: contacted.filter((f) => f.at >= since).length,
      gaps: findings.length - contacted.length,
      top: contacted.slice(0, 10).map((f) => ({ device: clip(f.device ?? "unknown device", 60), indicator: clip(defang(String(f.indicator ?? "")), 100), source: f.source, at: f.at })),
      agents: Number(lastReport?.n ?? 0),
      lastAgentReport: lastReport?.at ?? null,
    },
  };
}

// `node server/summary.mjs [days]`: prints the summary of TS_DATA_DIR's database as one line of JSON.
if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const days = Math.min(Math.max(Number.parseInt(process.argv[2] ?? "7", 10) || 7, 1), 90);
  const file = path.join(readConfig(process.env).dataDirectory, "theyspy.db");
  try {
    const db = new DatabaseSync(file, { readOnly: true });
    process.stdout.write(`${JSON.stringify(summarize(db, { days, env: process.env }))}\n`);
    db.close();
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ theyspy: productVersion, error: clip(error instanceof Error ? error.message : String(error), 300) })}\n`);
    process.exitCode = 1;
  }
}
