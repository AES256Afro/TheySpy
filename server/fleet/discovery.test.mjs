import { describe, expect, it } from "vitest";
import { fakePihole, testClock, testServices } from "../test-helpers.mjs";
import { fromPiholeNetwork, parseArpAn, parseProcArp } from "./discovery.mjs";

const piholeNetwork = [
  { id: 1, hwaddr: "a4:c1:38:00:00:19", interface: "eth0", firstSeen: 1793300000, lastQuery: 1793303880, numQueries: 10, macVendor: "Google, Inc.", ips: [{ ip: "192.168.1.42", name: "pixel.lan", lastSeen: 1793303880 }, { ip: "fe80::1", name: null, lastSeen: 1793303880 }] },
  { id: 2, hwaddr: "ip-192.168.1.77", interface: "eth0", firstSeen: 1793300000, lastQuery: 1793303000, numQueries: 3, macVendor: "", ips: [{ ip: "192.168.1.77", name: null, lastSeen: 1793303000 }] },
  { id: 3, hwaddr: "ip-127.0.0.1", interface: "lo", firstSeen: 1793300000, lastQuery: 1793303000, numQueries: 4, macVendor: "", ips: [{ ip: "127.0.0.1", name: "localhost", lastSeen: 1793303000 }] },
];

describe("discovery", () => {
  it("reads Pi-hole's network table, the kernel's neighbour table and macOS's arp", () => {
    expect(fromPiholeNetwork(piholeNetwork).map((o) => [o.ip, o.mac, o.hostname])).toEqual([["192.168.1.42", "a4:c1:38:00:00:19", "pixel.lan"], ["fe80::1", "a4:c1:38:00:00:19", null], ["192.168.1.77", null, null]]);
    const proc = "IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.1      0x1         0x2         00:11:22:33:44:55     *        eth0\n192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n";
    expect(parseProcArp(proc)).toEqual([{ ip: "192.168.1.1", mac: "00:11:22:33:44:55" }]);
    expect(parseArpAn("? (192.168.1.20) at f0:18:98:0:a:c on en0 ifscope [ethernet]\n? (192.168.1.255) at (incomplete) on en0 [ethernet]\n")).toEqual([{ ip: "192.168.1.20", mac: "f0:18:98:00:0a:0c" }]);
  });

  it("syncs Pi-hole's devices into the registry, leaving out loopback and addresses outside the scan ranges", async () => {
    const pihole = fakePihole({ network: piholeNetwork });
    const { discovery, fleet, sentinel } = testServices({ piholeFetch: pihole.fetchImpl, network: { neighbours: async () => [{ ip: "192.168.1.1", mac: "00:11:22:33:44:55" }, { ip: "8.8.8.8", mac: "00:11:22:33:44:56" }] } });
    sentinel.configure({ mode: "api", url: "http://192.0.2.5", password: "pihole-pass" }, "owner");
    expect(await discovery.sync()).toMatchObject({ pihole: 2, arp: 1, devices: 3 });
    expect(fleet.list().map((d) => d.ip).sort()).toEqual(["192.168.1.1", "192.168.1.42", "192.168.1.77"]);
    expect(fleet.list().find((d) => d.ip === "192.168.1.42")).toMatchObject({ vendor: "Google, Inc.", hostname: "pixel.lan" });
    expect(discovery.suggestions()).toEqual([{ cidr: "192.168.1.0/24", devices: 3 }]);
    // Pi-hole's table and the neighbour table together are the first inventory: nothing is "new".
    expect(fleet.list().filter((d) => d.isNew)).toEqual([]);
  });

  it("refuses networks outside the scan ranges or too large to sweep", () => {
    const { discovery } = testServices({ scanRanges: ["192.168.1.0/24", "10.0.0.0/8"] });
    expect(discovery.checkTarget("192.168.1.130/25")).toBe("192.168.1.128/25");
    expect(() => discovery.checkTarget("192.168.2.0/24")).toThrow(/outside the ranges/);
    expect(() => discovery.checkTarget("8.8.8.0/24")).toThrow(/outside the ranges/);
    expect(() => discovery.checkTarget("10.0.0.0/16")).toThrow(/too large/);
    expect(() => discovery.checkTarget("example.com")).toThrow(/not an IPv4 network/);
    expect(() => discovery.setTargets(["192.168.1.0/24", "1.1.1.0/24"], "owner")).toThrow(/outside/);
    expect(discovery.setTargets(["192.168.1.0/24", "192.168.1.9/24"], "owner")).toEqual(["192.168.1.0/24"]);
  });

  it("sweeps: hosts that answer or refuse are up, named from reverse DNS, with MACs from the neighbour table", async () => {
    const probed = [];
    const answers = { "192.168.1.1": { port: 443, answer: "open" }, "192.168.1.88": { port: 80, answer: "refused" } };
    const { discovery, fleet, audit } = testServices({
      now: testClock(),
      network: {
        probeHost: async (ip) => { probed.push(ip); return answers[ip] ?? null; },
        neighbours: async () => [{ ip: "192.168.1.88", mac: "3c:a9:f4:00:00:21" }],
        reverse: async (ip) => (ip === "192.168.1.88" ? "esp-plug.lan" : null),
      },
    });
    fleet.observe([{ ip: "192.168.1.1", mac: "00:11:22:33:44:55", hostname: "router", seenAt: "2026-10-29T11:00:00.000Z" }], "pihole");
    await expect(discovery.sweep()).rejects.toThrow(/Choose the networks/);
    discovery.setTargets(["192.168.1.0/24"], "owner");
    const result = await discovery.sweep({ concurrency: 8 });
    expect(probed).toHaveLength(254);
    expect(result).toMatchObject({ networks: ["192.168.1.0/24"], alive: 2, withMac: 1, newDevices: 1 });
    expect(fleet.list().find((d) => d.ip === "192.168.1.88")).toMatchObject({ mac: "3c:a9:f4:00:00:21", hostname: "esp-plug.lan", isNew: true });
    expect(audit.list(20).find((e) => e.action === "fleet.new_device").detail).toMatchObject({ ip: "192.168.1.88", source: "sweep" });
  });
});
