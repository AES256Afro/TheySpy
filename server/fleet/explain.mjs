import { inCidr, isRandomisedMac, slash24 } from "./addresses.mjs";

// Turning what is known about an address into words: which network it is on, what kind of device it
// probably is, and the best name for it with where that name came from. So the Fleet (and every
// screen that shows an address) says "iPhone, on your router's Wi-Fi" rather than "192.168.8.218".

/** Docker gives containers MACs starting 02:42, whatever network they are on. */
export const isDockerMac = (mac) => Boolean(mac) && mac.toLowerCase().startsWith("02:42:");

/** Which network an address is on, relative to the router Pi-hole's host uses. */
export function networkOf(ip, gateway, mac = null) {
  if (!ip) return null;
  if (isDockerMac(mac)) return { kind: "docker", label: "Docker container", detail: `A container on a Docker network on the Pi-hole host (its MAC starts 02:42, Docker's prefix): an app asking Pi-hole, not a separate device.` };
  if (ip.startsWith("127.") || ip === "::1") return { kind: "local", label: "This machine", detail: "The machine Pi-hole runs on, asking itself." };
  if (inCidr(ip, "100.64.0.0/10")) return { kind: "tailscale", label: "Tailscale", detail: "An address on your tailnet: the device reaches Pi-hole over Tailscale, from home or anywhere." };
  if (gateway && slash24(ip) === slash24(gateway)) {
    return ip === gateway
      ? { kind: "router", label: "Your router", detail: `The router itself (${gateway}): its own lookups, and those it forwards for devices.` }
      : { kind: "lan", label: "Your router's network", detail: `On ${slash24(gateway)}, behind your router at ${gateway}: a device on your Wi-Fi or wired network.` };
  }
  if (/^172\.(1[6-9]|2\d|3[01])\.\d+\.1$/.test(ip)) return { kind: "docker", label: "Docker network", detail: "The gateway of a Docker network on the Pi-hole host: lookups from containers there appear from this address, not a separate device." };
  if (inCidr(ip, "172.16.0.0/12")) return { kind: "docker", label: "Docker network", detail: "An address on a Docker network on the Pi-hole host: a container, not a separate device." };
  if (inCidr(ip, "10.0.0.0/8") || inCidr(ip, "192.168.0.0/16")) return { kind: "other", label: "Another private network", detail: `On ${slash24(ip)}, not the router's network: a VPN, a second router, or a virtual machine.` };
  return { kind: "public", label: "Public address", detail: "A public internet address: Pi-hole is answering queries from outside your network." };
}

/** @type {[RegExp, string, string][]} */
const kinds = [
  [/iphone/i, "phone", "iPhone"], [/ipad/i, "tablet", "iPad"], [/watch/i, "watch", "Apple Watch"], [/macbook|imac|\bmac\b|mac-?mini|mac\./i, "computer", "Mac"],
  [/android|pixel|galaxy|sm-[a-z]\d/i, "phone", "Android phone"], [/(^|[^a-z])tv|roku|chromecast|firetv|fire-tv|shield|appletv|bravia|webos/i, "tv", "TV or streamer"],
  [/printer|epson|brother|canon|hp[-_ ]?(laser|office|envy)/i, "printer", "Printer"], [/nas|mycloud|synology|diskstation|qnap|wd ?cloud/i, "storage", "Network storage"],
  [/console|gl-inet|router|openwrt|unifi|eero|orbi|deco/i, "router", "Router"], [/xbox|playstation|ps[45]|switch/i, "console", "Games console"],
  [/echo|alexa|homepod|nest|google-home/i, "speaker", "Smart speaker"], [/camera|cam\b|ring|wyze|arlo/i, "camera", "Camera"],
];
/** @type {[RegExp, string][]} */
const vendorKinds = [
  [/apple/i, "Apple device"], [/western digital|synology|qnap/i, "Network storage"], [/gl technologies|tp-link|netgear|ubiquiti|eero|asus.*router/i, "Router or access point"],
  [/espressif|tuya|shelly|sonoff/i, "Smart-home gadget"], [/azurewave|intel corporate|liteon|realtek|murata/i, "Computer (by its Wi-Fi chip)"], [/asustek|dell|lenovo|hewlett|micro-star/i, "Computer"],
  [/samsung|google|oneplus|xiaomi|motorola/i, "Phone, tablet or TV"], [/amazon/i, "Amazon device (Echo, Fire TV, Kindle)"], [/sonos/i, "Sonos speaker"], [/raspberry/i, "Raspberry Pi"],
];

/** A likely kind of device, from its names and its MAC's vendor. */
export function guessKind({ names = [], vendor = null, mac = null }) {
  if (isDockerMac(mac)) return { kind: "container", label: "Docker container", from: "its MAC (Docker's prefix)" };
  for (const n of names) for (const [re, kind, label] of kinds) if (n && re.test(n)) return { kind, label, from: "its name" };
  if (vendor) for (const [re, label] of vendorKinds) if (re.test(vendor)) return { kind: null, label, from: "the MAC's maker" };
  if (mac && isRandomisedMac(mac)) return { kind: null, label: "Phone, tablet or laptop", from: "its private Wi-Fi address" };
  return null;
}

/** "Mac.tail6233fa.ts.net" → "Mac"; "nas.lan" → "nas". */
export const shortName = (name) => (name ? String(name).replace(/\.$/, "").split(".")[0] : name);

const nameSources = [["pihole", "your Pi-hole label"], ["router", "your router"], ["tailscale", "Tailscale"], ["reverse", "reverse DNS"]];

/** The best name and where it came from: your label, then Pi-hole's, the router's, Tailscale's. */
export function bestName({ label, names = {}, hostname, vendor, mac, ip }) {
  if (label) return { name: label, from: "your label in TheySpy" };
  for (const [key, from] of nameSources) if (names[key]) return { name: key === "pihole" ? names[key] : shortName(names[key]), from };
  if (hostname && hostname !== "pi.hole") return { name: shortName(hostname), from: "Pi-hole's network table" };
  const kind = guessKind({ names: [hostname], vendor, mac });
  if (kind) return { name: `${kind.label} at ${ip}`, from: `a guess from ${kind.from}` };
  return { name: ip ?? mac, from: "no name known yet" };
}
