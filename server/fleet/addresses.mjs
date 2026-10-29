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

/** The addresses a sweep of a range visits: all but the network and broadcast addresses. */
export function hostsOf(cidr) {
  const range = parseCidr(cidr);
  if (!range) return [];
  if (range.prefix >= 31) return Array.from({ length: range.size }, (_, i) => intToIpv4(range.first + i));
  return Array.from({ length: range.size - 2 }, (_, i) => intToIpv4(range.first + 1 + i));
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
