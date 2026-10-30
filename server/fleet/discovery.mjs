import { execFile } from "node:child_process";
import { promises as dnsPromises } from "node:dns";
import { readFile } from "node:fs/promises";
import net from "node:net";
import { promisify } from "node:util";
import { hostsOf, inCidr, normaliseMac, parseCidr, slash24 } from "./addresses.mjs";

// Discovery (docs/PLAN.md M4): what feeds the device registry.
//  - Pi-hole's network table: every DNS client by MAC with its addresses (passive, every 5 minutes).
//  - The kernel's neighbour (ARP) table: MACs of hosts this machine has talked to on the LAN.
//  - A sweep of the networks the owner chose: an unprivileged TCP "ping" to a few common ports, where
//    a connection or a refusal (a reset) both mean the host is up; then the neighbour table for MACs
//    and reverse DNS for names. Nothing outside TS_SCAN_RANGES is ever probed.

const sweepPorts = [443, 80, 22, 445, 62078, 8009, 7000, 554];
const maxPrefix = 22; // the largest network one sweep visits: 1,022 hosts

/** Pi-hole's network table → observations (an "ip-…" entry is an address with no known MAC). */
export function fromPiholeNetwork(devices) {
  const out = [];
  for (const d of devices) {
    const mac = String(d.hwaddr ?? "").startsWith("ip-") ? null : normaliseMac(d.hwaddr);
    for (const a of d.ips ?? []) {
      const seen = Math.max(Number(a.lastSeen ?? 0), Number(d.lastQuery ?? 0));
      if (!a.ip || !seen || a.ip.startsWith("127.") || a.ip === "::1") continue;
      out.push({ ip: String(a.ip), mac, hostname: a.name || null, vendor: d.macVendor || null, seenAt: new Date(seen * 1000).toISOString() });
    }
  }
  return out;
}

/** /proc/net/arp (Linux) → complete entries. */
export function parseProcArp(text) {
  return text.split("\n").slice(1).map((line) => line.trim().split(/\s+/)).filter((f) => f.length >= 4 && f[2] === "0x2")
    .map((f) => ({ ip: f[0], mac: normaliseMac(f[3]) })).filter((e) => e.mac);
}

/** `arp -an` (macOS, BSD) → complete entries. */
export function parseArpAn(text) {
  const out = [];
  for (const m of text.matchAll(/\(([\d.]+)\) at ([0-9a-f:]+) /gi)) {
    const mac = normaliseMac(m[2].split(":").map((p) => p.padStart(2, "0")).join(""));
    if (mac) out.push({ ip: m[1], mac });
  }
  return out;
}

async function readNeighbours() {
  try {
    return parseProcArp(await readFile("/proc/net/arp", "utf8"));
  } catch {
    try {
      const { stdout } = await promisify(execFile)("arp", ["-an"], { timeout: 5000 });
      return parseArpAn(stdout);
    } catch {
      return [];
    }
  }
}

/** Whether a host answers on any of the ports: an open port or a refused one both mean it is up. */
function probe(ip, ports, timeoutMs) {
  return ports.reduce((previous, port) => previous.then((found) => found ?? new Promise((resolve) => {
    const socket = net.connect({ host: ip, port });
    const done = (result) => { socket.destroy(); resolve(result); };
    socket.setTimeout(timeoutMs, () => done(null));
    socket.once("connect", () => done({ port, answer: "open" }));
    socket.once("error", (error) => done(/** @type {any} */ (error).code === "ECONNREFUSED" ? { port, answer: "refused" } : null));
  })), Promise.resolve(/** @type {{ port: number, answer: string } | null} */ (null)));
}

async function reverseName(resolver, ip) {
  try { return (await resolver.reverse(ip))[0] ?? null; } catch { return null; }
}

/**
 * @param {{
 *   fleet: ReturnType<typeof import("./registry.mjs").createFleet>,
 *   sentinel: ReturnType<typeof import("../pihole/sentinel.mjs").createSentinel>,
 *   settings: ReturnType<typeof import("../db.mjs").createSettingsStore>,
 *   audit: ReturnType<typeof import("../audit.mjs").createAuditLog>,
 *   scanRanges: string[],
 *   now?: () => Date,
 *   neighbours?: () => Promise<{ ip: string, mac: string }[]>,
 *   probeHost?: (ip: string) => Promise<{ port: number, answer: string } | null>,
 *   reverse?: (ip: string) => Promise<string | null>,
 *   reverseVia?: (server: string, ip: string) => Promise<string | null>,
 * }} deps
 */
export function createDiscovery({ fleet, sentinel, settings, audit, scanRanges, now = () => new Date(), neighbours = readNeighbours, probeHost, reverse, reverseVia }) {
  const resolver = new dnsPromises.Resolver({ timeout: 1500, tries: 1 });
  const probeOne = probeHost ?? ((ip) => probe(ip, sweepPorts, 700));
  const reverseOne = reverse ?? ((ip) => reverseName(resolver, ip));
  const allowed = (ip) => scanRanges.some((range) => inCidr(ip, range));
  // Asking a particular DNS server for an address's name: the router (which knows its DHCP clients'
  // names) and Tailscale's MagicDNS (which knows the tailnet's).
  const askServer = reverseVia ?? (async (server, ip) => {
    const r = new dnsPromises.Resolver({ timeout: 1500, tries: 1 });
    r.setServers([server]);
    try { return (await r.reverse(ip))[0] ?? null; } catch { return null; }
  });

  /** Names for devices from your Pi-hole client labels, your router and Tailscale. */
  async function learnNames(labels, gateway, log) {
    const devices = fleet.list();
    // Every client you set up in Pi-hole (Group management → Clients), labelled or not: a device you
    // already know, flagged so it can be trusted in one step.
    const listed = new Map(labels.map((l) => [l.client.toLowerCase(), l]));
    let named = 0;
    for (const d of devices) {
      const entry = (d.mac && listed.get(d.mac)) ?? (d.ip && listed.get(d.ip)) ?? null;
      const label = entry?.label ?? null;
      const flag = entry ? "listed" : null;
      if (label !== (d.names.pihole ?? null) || flag !== (d.names.piholeClient ?? null)) fleet.setNames(d.id, { pihole: label, piholeClient: flag });
      if (label) named += 1;
    }
    const stale = (d) => !d.names.checkedAt || now().getTime() - Date.parse(d.names.checkedAt) > 6 * 3_600_000;
    const queue = devices.filter((d) => d.ip && stale(d) && d.network?.kind !== "docker" && d.network?.kind !== "local");
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(8, queue.length) }, async () => {
      while (next < queue.length) {
        const d = queue[next++];
        const tailnet = inCidr(d.ip, "100.64.0.0/10");
        const router = !tailnet && gateway ? await askServer(gateway, d.ip) : null;
        const tailscale = await askServer("100.100.100.100", d.ip);
        fleet.setNames(d.id, { router: router && !/\.ts\.net\.?$/.test(router) ? router : null, tailscale: tailscale ?? (router && /\.ts\.net\.?$/.test(router) ? router : null), checkedAt: now().toISOString() });
      }
    }));
    if (named || queue.length) log(`Names: ${named} from your Pi-hole labels; asked ${gateway ? "the router and " : ""}Tailscale about ${queue.length} addresses.`);
  }

  const discovery = {
    scanRanges: () => scanRanges,

    /**
     * Whether a network may be swept: an IPv4 range of at most /22, entirely inside one of
     * TS_SCAN_RANGES. Returns its canonical form, or throws a 400.
     * @param {string} cidr
     */
    checkTarget(cidr) {
      const range = parseCidr(cidr);
      if (!range) throw Object.assign(new Error(`"${cidr}" is not an IPv4 network such as 192.168.1.0/24`), { status: 400 });
      if (range.prefix < maxPrefix) throw Object.assign(new Error(`${range.cidr} is too large to sweep; split it into /${maxPrefix} or smaller`), { status: 400 });
      const inside = scanRanges.some((r) => { const a = parseCidr(r); return a && range.first >= a.first && range.last <= a.last; });
      if (!inside) throw Object.assign(new Error(`${range.cidr} is outside the ranges TheySpy may scan (TS_SCAN_RANGES: ${scanRanges.join(", ")})`), { status: 403 });
      return range.cidr;
    },

    targets: () => settings.get("fleet_targets") ?? [],
    setTargets(targets, actor) {
      if (!Array.isArray(targets) || targets.length > 8) throw Object.assign(new Error("targets must be a list of up to 8 networks"), { status: 400 });
      const clean = [...new Set(targets.map((t) => discovery.checkTarget(String(t))))];
      settings.set("fleet_targets", clean);
      audit.record(actor, "fleet.targets_set", null, { targets: clean });
      return clean;
    },

    /** Networks worth sweeping: the /24s the registry's devices are in, inside the scan ranges. */
    suggestions() {
      const counts = new Map();
      for (const d of fleet.list()) {
        const net24 = d.ip && slash24(d.ip);
        if (net24 && allowed(d.ip)) counts.set(net24, (counts.get(net24) ?? 0) + 1);
      }
      return [...counts].sort((a, b) => b[1] - a[1]).map(([cidr, devices]) => ({ cidr, devices }));
    },

    /**
     * Reads Pi-hole's network table and the neighbour table into the registry.
     * @param {{ log?: (line: string) => void }} [options]
     */
    async sync({ log = () => {} } = {}) {
      const inventory = fleet.isEmpty();
      let fromPihole = 0;
      if (sentinel.effective().mode) {
        const observations = fromPiholeNetwork(await sentinel.source().networkDevices()).filter((o) => allowed(o.ip));
        fleet.observe(observations, "pihole", { inventory });
        fromPihole = observations.length;
        log(`Pi-hole's network table: ${fromPihole} addresses.`);
      }
      const { clients: labels, gateway } = sentinel.effective().mode ? await sentinel.source().clientLabels().catch(() => ({ clients: [], gateway: null })) : { clients: [], gateway: null };
      if (gateway) settings.set("fleet_gateway", gateway);
      const seenAt = now().toISOString();
      const arp = (await neighbours()).filter((e) => allowed(e.ip));
      fleet.observe(arp.map((e) => ({ ...e, seenAt })), "arp", { inventory });
      if (arp.length) log(`Neighbour table: ${arp.length} addresses with MACs.`);
      await learnNames(labels, gateway ?? settings.get("fleet_gateway"), log);
      const { merged } = fleet.consolidate("system");
      if (merged.length) log(`Merged ${merged.length} Tailscale address${merged.length === 1 ? "" : "es"} into the devices they belong to.`);
      const result = { pihole: fromPihole, arp: arp.length, devices: fleet.list().length };
      settings.set("fleet_last_sync", { at: seenAt, ...result });
      return result;
    },

    /**
     * Sweeps networks (the owner's targets by default): probes every address, then records the
     * hosts that answered with the MAC and name found for them.
     * @param {{ targets?: string[], log?: (line: string) => void, concurrency?: number, record?: boolean }} [options]
     *   record: false for a targeted check's one-address sweep, which is not "the last sweep"
     */
    async sweep({ targets, log = () => {}, concurrency = 64, record = true } = {}) {
      const networks = (targets ?? discovery.targets()).map((t) => discovery.checkTarget(t));
      if (!networks.length) throw Object.assign(new Error("Choose the networks to sweep first"), { status: 400 });
      const started = now().toISOString();
      const alive = [];
      for (const cidr of networks) {
        const hosts = hostsOf(cidr).filter(allowed);
        log(`Sweeping ${cidr}: ${hosts.length} addresses.`);
        let next = 0;
        await Promise.all(Array.from({ length: Math.min(concurrency, hosts.length) }, async () => {
          while (next < hosts.length) {
            const ip = hosts[next++];
            const answer = await probeOne(ip);
            if (answer) alive.push({ ip, ...answer });
          }
        }));
      }
      const macs = new Map((await neighbours()).map((e) => [e.ip, e.mac]));
      const known = new Map(fleet.list().map((d) => [d.ip, d]));
      const observations = [];
      for (const host of alive) {
        const hostname = known.get(host.ip)?.hostname ? null : await reverseOne(host.ip);
        observations.push({ ip: host.ip, mac: macs.get(host.ip) ?? null, hostname, seenAt: now().toISOString() });
      }
      const created = fleet.observe(observations, "sweep");
      const result = { at: started, networks, alive: alive.length, withMac: observations.filter((o) => o.mac).length, newDevices: created.length };
      if (record) settings.set("fleet_last_sweep", result);
      log(`${alive.length} hosts answered${result.withMac ? `, ${result.withMac} with a MAC` : ""}; ${created.length} new.`);
      return result;
    },

    lastSync: () => settings.get("fleet_last_sync") ?? null,
    lastSweep: () => settings.get("fleet_last_sweep") ?? null,
  };
  return discovery;
}

/** @param {ReturnType<typeof createDiscovery>} discovery */
export function fleetJobKinds(discovery) {
  return {
    "fleet.sync": {
      title: "Read Pi-hole's network table",
      direct: true,
      async run({ log }) { return discovery.sync({ log }); },
    },
    "fleet.sweep": {
      title: "Sweep the network for devices",
      direct: true,
      async run({ log, params }) { return discovery.sweep({ targets: params?.targets, log }); },
    },
  };
}
