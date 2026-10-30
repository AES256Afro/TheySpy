import { matchSoftware } from "./cves/match.mjs";
import { defang } from "./iocs/parse.mjs";

// The read-only view other tools get (API, MCP) and the alerts use: devices, indicator lookups,
// exploited CVEs on devices, a domain's history, the week's status.

/**
 * @param {{
 *   fleet: ReturnType<typeof import("./fleet/registry.mjs").createFleet>,
 *   sentinel: ReturnType<typeof import("./pihole/sentinel.mjs").createSentinel>,
 *   cves: ReturnType<typeof import("./cves/store.mjs").createCveStore>,
 *   deviceCves: ReturnType<typeof import("./cves/devices.mjs").createDeviceCves>,
 *   digest: () => ReturnType<typeof import("./digest.mjs").createDigest>,
 *   now?: () => Date,
 * }} deps
 * @returns {import("./integrations.mjs").ReadModel & { kevMatches: (ids: string[]) => { cveId: string, devices: string[] }[] }}
 */
export function createReadModel({ fleet, sentinel, cves, deviceCves, digest, now = () => new Date() }) {
  const realDevices = () => fleet.list().filter((d) => d.network?.kind !== "docker");

  /** KEV CVEs that name a product (vendor:product) a device runs, at a version they cover. */
  function exploited(onlyIds = null) {
    const out = [];
    const wanted = onlyIds ? new Set(onlyIds) : null;
    for (const device of realDevices()) {
      for (const item of deviceCves.inventory(device.id)) {
        for (const [vendor, product] of item.cpes) {
          for (const row of cves.list({ zeroDay: true, product: `${vendor}:${product}`, limit: 200 }).rows) {
            if (wanted && !wanted.has(row.cveId)) continue;
            if (!row.products.includes(`${vendor}:${product}`)) continue;
            const full = cves.get(row.cveId);
            const hit = full?.cpeMatches?.length ? matchSoftware({ vendor, product, version: item.version }, full.cpeMatches) : { confidence: "product", fixed: null };
            if (!hit) continue; // NVD's ranges say this version is not affected
            out.push({ cveId: row.cveId, name: row.kev?.name ?? row.description?.slice(0, 120) ?? null, kevAdded: row.kev?.added ?? null, due: row.kev?.due ?? null, ransomware: row.kev?.ransomware ?? false,
              reportedBy: row.zeroDaySources.map((s) => s.source),
              device: device.name, deviceIp: device.ip, software: `${item.product} ${item.version ?? "(version hidden)"}`, confidence: hit.confidence, fixed: hit.fixed ?? null });
          }
        }
      }
    }
    return out;
  }

  return {
    devices: ({ onlineOnly = false } = {}) => realDevices().filter((d) => !onlineOnly || d.online).map((d) => ({
      name: d.name, nameFrom: d.nameFrom, ip: d.ip, mac: d.mac, vendor: d.vendor, kind: d.kind ?? d.guess?.label ?? null, network: d.network?.label ?? null,
      online: d.online, trusted: d.trusted, isNew: d.isNew, inPihole: d.inPihole, firstSeen: d.firstSeen, lastSeen: d.lastSeen,
    })),
    indicatorLookups(days = 30) {
      const since = new Date(now().getTime() - days * 86_400_000).toISOString();
      const names = fleet.namesByIp();
      return sentinel.hits().filter((h) => h.lastSeen >= since).map((h) => ({
        device: names[h.clientIp]?.name ?? h.clientName ?? h.clientIp, clientIp: h.clientIp, domain: defang(h.domain), indicator: defang(h.indicator),
        lookups: h.lookups, blocked: h.blocked, firstSeen: h.firstSeen, lastSeen: h.lastSeen,
      }));
    },
    exploitedOnDevices: () => exploited(),
    kevMatches(ids) {
      const byCve = new Map();
      for (const m of exploited(ids)) byCve.set(m.cveId, [...new Set([...(byCve.get(m.cveId) ?? []), m.device])]);
      return [...byCve].map(([cveId, devices]) => ({ cveId, devices }));
    },
    async checkDomain(input) {
      const domain = String(input).trim().toLowerCase().replaceAll("[.]", ".");
      const indicator = sentinel.hits().some((h) => h.domain === domain || h.indicator === domain);
      if (!sentinel.effective().mode) return { domain: defang(domain), connected: false, indicator, clients: [] };
      const until = now().getTime() / 1000;
      const lookups = await sentinel.source().lookupsOf(domain, { from: until - 30 * 86400, until });
      const names = fleet.namesByIp();
      const byClient = new Map();
      for (const l of lookups) {
        const e = byClient.get(l.clientIp) ?? { device: names[l.clientIp]?.name ?? l.clientName ?? l.clientIp, ip: l.clientIp, lookups: 0, blocked: 0, last: l.at };
        e.lookups += 1;
        if (/BLOCK|GRAVITY|REGEX|DENYLIST|SPECIAL/.test(l.status)) e.blocked += 1;
        if (l.at > e.last) e.last = l.at;
        byClient.set(l.clientIp, e);
      }
      return { domain: defang(domain), connected: true, indicator, days: 30, lookups: lookups.length, clients: [...byClient.values()].sort((a, b) => b.lookups - a.lookups) };
    },
    status: () => digest().compose(7),
  };
}
