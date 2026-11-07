// The Overview (docs/PLAN.md M15): one endpoint that composes what the home screen needs from what
// is already computed, whichever layout the owner chose. Four questions in order of harm, what
// could not be checked, the last day's events, and one row per device.

const day = 86_400_000;

// Audit actions that are not events the owner needs to see on the home screen.
const quiet = [/^job\./, /^theyspy\./, /^appearance\./, /^owner\./, /^fleet\.device_edited$/, /^fleet\.checked$/];

/**
 * @param {{
 *   fleet: ReturnType<typeof import("./fleet/registry.mjs").createFleet>,
 *   sentinel: ReturnType<typeof import("./pihole/sentinel.mjs").createSentinel>,
 *   read: ReturnType<typeof import("./readmodel.mjs").createReadModel>,
 *   exposure: ReturnType<typeof import("./exposure.mjs").createExposure>,
 *   agents: ReturnType<typeof import("./agents.mjs").createAgents>,
 *   audit: ReturnType<typeof import("./audit.mjs").createAuditLog>,
 *   now?: () => Date,
 * }} deps
 */
export function createOverview({ fleet, sentinel, read, exposure, agents, audit, now = () => new Date() }) {
  /** One audit entry as a line: what, when, how serious. Null for the ones not worth showing. */
  function describe(entry) {
    const { at, action, target, detail: d = {} } = entry;
    if (quiet.some((re) => re.test(action))) return null;
    const list = (v) => (Array.isArray(v) ? v.map(String) : []);
    switch (action) {
      case "fleet.new_device": return { at, action, tone: "warn", text: `New device ${d.hostname ?? d.vendor ?? ""} ${d.ip ?? target ?? ""}`.replace(/\s+/g, " ").trim(), link: "/fleet" };
      case "fleet.inventoried": return { at, action, tone: "none", text: `First inventory: ${d.devices} devices from ${d.source}`, link: "/fleet" };
      case "fleet.devices_merged": return { at, action, tone: "none", text: `Merged ${list(d.merged).length || (d.merged?.length ?? 1)} device record(s)`, link: "/fleet" };
      case "pihole.indicator_lookups": return { at, action, tone: d.allowed ? "bad" : "warn", text: `${list(d.clients).join(", ")} looked up ${list(d.indicators).join(", ").replaceAll(".", "[.]")}: ${d.lookups} lookup(s), ${d.allowed ? `${d.allowed} not blocked` : "all blocked"}`, link: "/pihole" };
      case "cves.kev_added": return { at, action, tone: "warn", text: `CISA KEV added ${list(d.cves).join(", ")}`, link: "/intel" };
      case "cves.zero_day_reported": return { at, action, tone: "warn", text: `Exploitation reported: ${list(d.cves).join(", ")} (${list(d.sources).join(", ")})`, link: "/intel" };
      case "agent.indicator_found": return { at, action, tone: "bad", text: `${d.device ?? "A device"}: indicator trace(s) found by ${d.source ?? "the agent"}`, link: "/evidence" };
      case "agent.report": case "agent.reported": return { at, action, tone: "none", text: `Agent report from ${d.device ?? target ?? "a device"}${d.gaps ? ` · ${d.gaps} gap(s)` : ""}`, link: "/evidence" };
      case "pihole.unreachable": return { at, action, tone: "bad", text: `Pi-hole unreachable: ${d.error ?? ""}`, link: "/pihole" };
      case "blocklists.update_quarantined": return { at, action, tone: "warn", text: `Blocklist update held: ${d.name ?? target}`, link: "/blocklists" };
      case "sites.indicator_lookups": return { at, action, tone: "bad", text: `${d.site}: a device reached an indicator address`, link: "/sites" };
      default: return { at, action, tone: "none", text: target ? `${action} ${target}` : action, link: null };
    }
  }

  const overview = {
    compose() {
      const at = now();
      const since24 = new Date(at.getTime() - day).toISOString();
      const byAddress = fleet.deviceByAddress();
      const lookups = /** @type {any[]} */ (read.indicatorLookups(7));
      const notBlocked = lookups.filter((l) => l.blocked < l.lookups);
      const exploited = /** @type {any[]} */ (read.exploitedOnDevices());
      const ex = exposure.overview();
      const devices = fleet.list().filter((d) => d.network?.kind !== "docker");
      const newDevices = devices.filter((d) => d.isNew);
      const watch = sentinel.watch.status();

      const gaps = [];
      for (const d of ex.devices) for (const f of d.factors) if (f.state === "unknown") gaps.push({ deviceId: d.id, device: d.name, check: f.label, evidence: f.evidence, fix: f.fix });
      for (const f of ex.network) if (f.state === "unknown") gaps.push({ deviceId: null, device: null, check: f.label, evidence: f.evidence, fix: f.fix });

      const perDevice = new Map(devices.map((d) => [d.id, { hits: 0, notBlocked: 0, kev: 0 }]));
      for (const l of lookups) {
        const id = byAddress.get(l.clientIp);
        const row = id === undefined ? null : perDevice.get(id);
        if (row) { row.hits += l.lookups; row.notBlocked += l.lookups - l.blocked; }
      }
      for (const e of exploited) {
        const id = byAddress.get(e.deviceIp);
        const row = id === undefined ? null : perDevice.get(id);
        if (row) row.kev += 1;
      }
      const scored = new Map(ex.devices.map((d) => [d.id, d]));
      const rows = devices.map((d) => {
        const p = perDevice.get(d.id) ?? { hits: 0, notBlocked: 0, kev: 0 };
        const s = scored.get(d.id);
        const agent = agents.agentFor(d.id);
        return {
          id: d.id, name: d.name, ip: d.ip, kind: d.kind ?? d.guess?.label ?? null, online: d.online, isNew: d.isNew, trusted: d.trusted, lastSeen: d.lastSeen,
          hits: p.hits, notBlocked: p.notBlocked, kev: p.kev, exposure: s ? { known: s.known, of: s.of, score: s.score, tone: s.tone } : null,
          agentAt: agent?.lastReportAt ?? null, attention: p.notBlocked > 0 ? 3 : p.kev > 0 || p.hits > 0 ? 2 : d.isNew ? 1 : 0,
        };
      }).sort((a, b) => b.attention - a.attention || b.hits - a.hits || b.kev - a.kev);

      return {
        at: at.toISOString(),
        status: { pihole: Boolean(sentinel.effective().mode), watch: Boolean(watch.enabled && !watch.lastError), devices: devices.length, online: devices.filter((d) => d.online).length },
        questions: {
          contacts: { count: notBlocked.length, lookups: notBlocked.reduce((n, l) => n + l.lookups - l.blocked, 0), top: notBlocked.slice(0, 5).map((l) => ({ ...l, deviceId: byAddress.get(l.clientIp) ?? null })) },
          exploited: { count: exploited.length, devices: [...new Set(exploited.map((e) => e.device))].slice(0, 8), top: exploited.slice(0, 5).map((e) => ({ cveId: e.cveId, device: e.device, deviceId: byAddress.get(e.deviceIp) ?? null, software: e.software, fixed: e.fixed ?? null })) },
          newDevices: { count: newDevices.length, names: newDevices.slice(0, 8).map((d) => ({ id: d.id, name: d.name, ip: d.ip })) },
          network: { failing: ex.network.filter((f) => f.state === "fail").length, unknown: ex.network.filter((f) => f.state === "unknown").length, of: ex.network.length, factors: ex.network },
        },
        gaps: gaps.slice(0, 30),
        gapsTotal: gaps.length,
        events: audit.list(300).filter((e) => e.at >= since24).map(describe).filter(Boolean).slice(0, 60),
        devices: rows,
      };
    },
  };
  return overview;
}
