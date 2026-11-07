// Which device an address belonged to at a given time (docs/PLAN.md M16, B22). A home network's
// DHCP hands the same address to different devices over months, so "every address this device has
// held" is not enough: a hit recorded under 192.168.1.30 in January is the tablet's, and the laptop
// that takes .30 in November must not inherit it. `device_addresses` records when each device held
// each address; a hit carries when it happened; this joins the two.

/** A day either side: leases outlive the last lookup Pi-hole saw, and precede the first. */
export const holderSlackMs = 24 * 3_600_000;

/**
 * @typedef {{ deviceId: number, first: string, last: string }} Holding
 * @typedef {Map<string, Holding[]>} Holders address → holdings, oldest first
 */

/**
 * The device that held `ip` at `at`. A lease stays with the device that had it until another
 * device is seen with the address, so each holding runs from a little before its first sighting
 * (the slack) to a little before the next holder's first sighting; the latest holding is
 * open-ended. Before the first known holder: null — nobody can be credited, and the hit stays
 * visible under its address on Pi-hole Sentinel.
 * @param {Holders} holders @param {string} ip @param {string} at ISO time @param {{ slackMs?: number }} [options]
 * @returns {number | null}
 */
export function holderAt(holders, ip, at, { slackMs = holderSlackMs } = {}) {
  const list = holders.get(ip);
  if (!list?.length) return null;
  const t = Date.parse(at);
  if (Number.isNaN(t)) return null;
  let best = null;
  for (let i = 0; i < list.length; i += 1) {
    const from = Date.parse(list[i].first) - slackMs;
    const to = i === list.length - 1 ? Number.POSITIVE_INFINITY : Date.parse(list[i + 1].first) - slackMs;
    if (t >= from && t < to) best = list[i];
  }
  return best ? best.deviceId : null;
}

/**
 * Groups hit events by the device that held each one's address at the time, like `sentinel.hits()`
 * groups them by address: one group per device × indicator × domain × via.
 * @param {{ at: string, indicator: string, domain: string, via: string, clientIp: string, clientName?: string | null, blocked: number, status?: string | null, tier?: string | null, confidence?: string | null, source?: string | null }[]} events
 * @param {Holders} holders
 * @returns {Map<number | null, { indicator: string, domain: string, via: string, clientIp: string, clientName: string | null, firstSeen: string, lastSeen: string, lookups: number, blocked: number, lastStatus: string | null, tier: string | null, confidence: string | null, source: string | null }[]>}
 */
export function attributeHits(events, holders, options = {}) {
  const byDevice = new Map();
  const groups = new Map();
  for (const e of events) {
    const deviceId = holderAt(holders, e.clientIp, e.at, options);
    const key = `${deviceId}\u0000${e.indicator}\u0000${e.domain}\u0000${e.via}\u0000${e.clientIp}`;
    let g = groups.get(key);
    if (!g) {
      g = { indicator: e.indicator, domain: e.domain, via: e.via, clientIp: e.clientIp, clientName: e.clientName ?? null, firstSeen: e.at, lastSeen: e.at, lookups: 0, blocked: 0, lastStatus: e.status ?? null, tier: e.tier ?? null, confidence: e.confidence ?? null, source: e.source ?? null, lastContext: null };
      groups.set(key, g);
      if (!byDevice.has(deviceId)) byDevice.set(deviceId, []);
      byDevice.get(deviceId).push(g);
    }
    g.lookups += 1;
    g.blocked += Number(e.blocked) ? 1 : 0;
    if (e.at < g.firstSeen) g.firstSeen = e.at;
    if (e.at >= g.lastSeen) { g.lastSeen = e.at; g.lastStatus = e.status ?? g.lastStatus; }
    // The minute around the newest hit that has one (M39).
    if (e.context && (!g.lastContext || e.at >= g.lastContext.at)) g.lastContext = { at: e.at, queries: e.context };
    if (!g.clientName && e.clientName) g.clientName = e.clientName;
  }
  for (const list of byDevice.values()) list.sort((a, b) => (a.lastSeen < b.lastSeen ? 1 : a.lastSeen > b.lastSeen ? -1 : 0));
  return byDevice;
}
