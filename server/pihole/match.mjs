// Matching Pi-hole's DNS log against indicators. A query matches an indicator when its name IS the
// indicator or a subdomain of it ("noas.powerium.net" matches "powerium.net"; "notpowerium.net"
// does not), the same label-boundary rule zero-breach's scanner uses. When several indicators
// match one name, only the most specific counts: it is one lookup, not several contacts.

/** FTL's numeric query status, as stored in pihole-FTL.db, by name. */
export const statusNames = Object.freeze([
  "UNKNOWN", "GRAVITY", "FORWARDED", "CACHE", "REGEX", "DENYLIST", "EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL",
  "EXTERNAL_BLOCKED_NXRA", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME", "RETRIED", "RETRIED_DNSSEC", "IN_PROGRESS",
  "DBBUSY", "SPECIAL_DOMAIN", "CACHE_STALE", "EXTERNAL_BLOCKED_EDE15",
]);

// The statuses that mean the client did not get a real answer (the same set BoxPilot's Pi-hole
// adapter counts as blocked). Pi-hole 5 called DENYLIST "BLACKLIST".
const blockedNames = new Set(["GRAVITY", "REGEX", "DENYLIST", "BLACKLIST", "EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME", "BLACKLIST_CNAME", "DBBUSY", "SPECIAL_DOMAIN", "EXTERNAL_BLOCKED_EDE15"]);
const cnameStatuses = new Set(["GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME", "BLACKLIST_CNAME"]);

export const isBlocked = (status) => blockedNames.has(String(status ?? "").toUpperCase());
export const statusName = (status) => (typeof status === "number" ? statusNames[status] ?? `STATUS_${status}` : String(status ?? "UNKNOWN").toUpperCase());

const normalise = (name) => String(name ?? "").trim().toLowerCase().replace(/\.+$/, "");

/**
 * @param {import("../iocs/parse.mjs").IocSet} set
 */
export function createMatcher(set) {
  const domains = new Map(set.indicators.filter((ind) => ind.type === "domain").map((ind) => [ind.value, ind]));
  return {
    size: domains.size,
    domains: [...domains.keys()],
    /** The most specific indicator a name falls under, or null. */
    match(name) {
      const labels = normalise(name).split(".");
      for (let i = 0; i < labels.length - 1; i += 1) {
        const hit = domains.get(labels.slice(i).join("."));
        if (hit) return hit;
      }
      return null;
    },
  };
}

/**
 * @typedef {{ queryId: number, at: string, domain: string, cname: string | null, status: string, clientIp: string, clientName: string | null }} DnsQuery
 * @typedef {DnsQuery & { indicator: string, tier: string, via: "query" | "cname", blocked: boolean }} HitEvent
 */

/** A row from Pi-hole's /api/queries as a DnsQuery. */
export function fromApi(row) {
  return {
    queryId: Number(row.id),
    at: new Date(Number(row.time) * 1000).toISOString(),
    domain: normalise(row.domain),
    cname: row.cname ? normalise(row.cname) : null,
    status: statusName(row.status),
    clientIp: String(row.client?.ip ?? ""),
    clientName: row.client?.name || null,
  };
}

/**
 * The queries that touched an indicator, by their own name or by a CNAME Pi-hole blocked.
 * @param {Iterable<DnsQuery>} queries
 * @param {ReturnType<typeof createMatcher>} matcher
 * @returns {HitEvent[]}
 */
export function findHits(queries, matcher) {
  const hits = [];
  for (const q of queries) {
    const direct = matcher.match(q.domain);
    const viaCname = !direct && q.cname && cnameStatuses.has(q.status) ? matcher.match(q.cname) : null;
    const ind = direct ?? viaCname;
    if (!ind) continue;
    hits.push({ ...q, indicator: ind.value, tier: ind.tier, via: direct ? "query" : "cname", blocked: isBlocked(q.status) });
  }
  return hits;
}
