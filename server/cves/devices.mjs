import { serviceProducts } from "./match.mjs";

// CVEs per device (docs/PLAN.md M6): the software a targeted check found listening on a device
// (product and version from banners), looked up at its exact version. The owner can accept a CVE as
// a known risk or mark it fixed; a later check that still finds the same version reopens a "fixed".

// Where a version came from, as each CVE line says it. A Debian or Ubuntu package keeps its upstream
// version when it is patched, so a CVE matched from one may already be fixed there.
const sourceWords = { agent: "agent", protec: "Protec", "protec-dpkg": "Protec, Debian package: may already be patched; your updates are what fix it" };

/**
 * @param {{
 *   db: import("node:sqlite").DatabaseSync,
 *   fleet: ReturnType<typeof import("../fleet/registry.mjs").createFleet>,
 *   services: (deviceId: number) => { port: number, product: string | null, version: string | null, lastSeen: string }[],
 *   reported?: (deviceId: number) => { vendor: string, product: string, version: string | null, label: string | null, source: string, seen_at: string }[],
 *   software: ReturnType<typeof import("./lookup.mjs").createSoftwareLookup>,
 *   audit: ReturnType<typeof import("../audit.mjs").createAuditLog>,
 *   now?: () => Date,
 * }} deps
 */
export function createDeviceCves({ db, fleet, services, software, audit, now = () => new Date(), reported = () => [] }) {
  const q = {
    decisions: db.prepare("SELECT cve_id, status, note, at, actor FROM cve_decisions WHERE device_id = ?"),
    decide: db.prepare(`INSERT INTO cve_decisions (device_id, cve_id, status, note, at, actor) VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT (device_id, cve_id) DO UPDATE SET status = excluded.status, note = excluded.note, at = excluded.at, actor = excluded.actor`),
    undecide: db.prepare("DELETE FROM cve_decisions WHERE device_id = ? AND cve_id = ?"),
  };

  const api = {
    /** The software on a device that CVEs can be matched against, and what cannot be matched yet. */
    inventory(deviceId) {
      const items = [];
      for (const s of services(deviceId)) {
        if (!s.product) continue;
        const cpes = serviceProducts[s.product] ?? [];
        items.push({ product: s.product, version: s.version, port: s.port, seen: s.lastSeen, cpes, matchable: Boolean(s.version && cpes.length) });
      }
      // What the device's agent or its manual profile says it runs (OS, browsers).
      for (const r of reported(deviceId)) {
        items.push({ product: r.label ?? r.product, version: r.version, port: null, source: r.source, seen: r.seen_at, cpes: [[r.vendor, r.product]], matchable: Boolean(r.version) });
      }
      return items;
    },

    /** Every CVE for the device's software, with the owner's decision and what fixes it. */
    async forDevice(deviceId) {
      const device = fleet.get(deviceId);
      if (!device) throw Object.assign(new Error("No such device"), { status: 404 });
      const decisions = new Map(q.decisions.all(deviceId).map((r) => [/** @type {any} */ (r).cve_id, r]));
      const byCve = new Map();
      const inventory = api.inventory(deviceId);
      for (const item of inventory.filter((i) => i.matchable)) {
        for (const [vendor, product] of item.cpes) {
          for (const c of await software.lookup({ vendor, product, version: item.version })) {
            const e = byCve.get(c.cveId) ?? { ...c, software: [], seen: "" };
            e.software.push(`${item.product} ${item.version}${item.port ? ` (port ${item.port})` : ` (${sourceWords[item.source] ?? "profile"})`}`);
            if (item.seen > e.seen) e.seen = item.seen;
            byCve.set(c.cveId, e);
          }
        }
      }
      const list = [...byCve.values()].map(({ seen, ...c }) => {
        const d = /** @type {any} */ (decisions.get(c.cveId));
        // "Fixed" is the owner's word until a check after it still finds the same version.
        const decision = d ? { status: d.status, note: d.note, at: d.at, by: d.actor, contradicted: d.status === "fixed" && seen > d.at } : null;
        return { ...c, software: [...new Set(c.software)], decision };
      });
      return {
        device: { id: device.id, name: device.name, ip: device.ip },
        inventory,
        cves: list,
        open: list.filter((c) => !c.decision || c.decision.contradicted).length,
        exploited: list.filter((c) => c.kev && (!c.decision || c.decision.contradicted)).length,
      };
    },

    /**
     * Records the owner's decision: "accepted" (a known risk), "fixed", or null to reopen.
     * @param {number} deviceId @param {string} cveId @param {"accepted" | "fixed" | null} status @param {string | null} note @param {string} actor
     */
    decide(deviceId, cveId, status, note, actor) {
      if (!fleet.get(deviceId)) throw Object.assign(new Error("No such device"), { status: 404 });
      if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) throw Object.assign(new Error("Not a CVE id"), { status: 400 });
      if (status === null) q.undecide.run(deviceId, cveId);
      else if (status === "accepted" || status === "fixed") q.decide.run(deviceId, cveId, status, note ? String(note).slice(0, 500) : null, now().toISOString(), actor);
      else throw Object.assign(new Error("status must be accepted, fixed or null"), { status: 400 });
      audit.record(actor, "cves.decided", cveId, { deviceId, status, note });
    },
  };
  return api;
}
