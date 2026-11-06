import net from "node:net";

// Address helpers for discovery: IPv4 ranges for sweeps and the scope guard, and MAC addresses.

/** @param {string} ip */
export function ipv4ToInt(ip) {
  if (!net.isIPv4(ip)) return null;
  return ip.split(".").reduce((n, octet) => n * 256 + Number(octet), 0);
}

/** @param {number} n */
export const intToIpv4 = (n) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");

/**
 * "192.168.1.0/24" (or a bare address, as /32) → its first and last address as integers.
 * @param {string} cidr
 */
export function parseCidr(cidr) {
  const [address, bits = "32", ...rest] = String(cidr).trim().split("/");
  const prefix = Number(bits);
  const start = ipv4ToInt(address);
  if (rest.length || start === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32 || !/^\d+$/.test(bits)) return null;
  const size = 2 ** (32 - prefix);
  const first = Math.floor(start / size) * size;
  return { cidr: `${intToIpv4(first)}/${prefix}`, prefix, first, last: first + size - 1, size };
}

/** @param {string} ip @param {string} cidr */
export function inCidr(ip, cidr) {
  const n = ipv4ToInt(ip);
  const range = parseCidr(cidr);
  return n !== null && range !== null && n >= range.first && n <= range.last;
}

/** The most addresses one sweep builds a list of: a /22, which is what the scope guard allows. */
export const maxSweepAddresses = 1024;

/**
 * The addresses a sweep of a range visits: all but the network and broadcast addresses. A range
 * too big to sweep fails here as well as in the scope guard, so no caller can ask this to
 * allocate sixteen million strings.
 */
export function hostsOf(cidr) {
  const range = parseCidr(cidr);
  if (!range) return [];
  if (range.size > maxSweepAddresses) throw Object.assign(new Error(`${range.cidr} holds ${range.size} addresses; one sweep visits at most ${maxSweepAddresses}`), { status: 400 });
  if (range.prefix >= 31) return Array.from({ length: range.size }, (_, i) => intToIpv4(range.first + i));
  return Array.from({ length: range.size - 2 }, (_, i) => intToIpv4(range.first + 1 + i));
}

// Addresses that are not on the public internet: private, loopback, link-local (which is where
// cloud metadata lives), carrier-grade NAT, documentation, multicast and reserved. Used by the
// website check to refuse a name pointed somewhere it may not reach, and by pacing to tell the
// owner's own machines from outside services.
const nonPublic = new net.BlockList();
for (const [a, p] of /** @type {[string, number][]} */ ([["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]])) nonPublic.addSubnet(a, p, "ipv4");
for (const [a, p] of /** @type {[string, number][]} */ ([["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8], ["64:ff9b::", 96], ["2001:db8::", 32]])) nonPublic.addSubnet(a, p, "ipv6");

/** @param {string} ip */
export function isPublicAddress(ip) {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) return isPublicAddress(mapped[1]);
  const family = net.isIP(ip);
  return family !== 0 && !nonPublic.check(ip, family === 6 ? "ipv6" : "ipv4");
}

/** Names that can only ever resolve on a local network, or over the owner's own tailnet. */
const localSuffixes = Object.freeze([".local", ".lan", ".internal", ".home.arpa", ".ts.net", ".localhost"]);

/**
 * Whether a host can only be a machine on the owner's own network. Pacing uses it so Pi-hole and
 * the other connectors are not rationed like a public feed; it answers only for what is certainly
 * local, and anything it is unsure of is treated as outside.
 * @param {string} host
 */
export function isOwnNetworkHost(host) {
  const h = String(host ?? "").toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  if (!h) return false;
  if (h === "localhost") return true;
  if (net.isIP(h)) return !isPublicAddress(h);
  // A single-label name ("pihole", "nas") has no public meaning.
  if (!h.includes(".")) return true;
  return localSuffixes.some((suffix) => h.endsWith(suffix));
}

export const privateRanges = Object.freeze(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]);

/** The /24 an IPv4 address is in. */
export const slash24 = (ip) => (net.isIPv4(ip) ? `${ip.split(".").slice(0, 3).join(".")}.0/24` : null);

/** "AA-BB-CC-DD-EE-FF" or "aabb.ccdd.eeff" → "aa:bb:cc:dd:ee:ff"; null for anything else. */
export function normaliseMac(value) {
  const hex = String(value ?? "").toLowerCase().replace(/[^0-9a-f]/g, "");
  if (hex.length !== 12 || /^0{12}$|^f{12}$/.test(hex)) return null;
  return hex.match(/../g).join(":");
}

/**
 * Whether a MAC is locally administered: phones and laptops use such random "private" addresses
 * per Wi-Fi network, so no vendor can be looked up and the address may change.
 */
export const isRandomisedMac = (mac) => Boolean(mac) && (parseInt(mac.slice(1, 2), 16) & 2) === 2;
