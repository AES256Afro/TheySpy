import { describe, expect, it } from "vitest";
import { fakePihole, testServices } from "../test-helpers.mjs";
import { classify } from "./targeted.mjs";

const at = Date.parse("2026-10-28T21:14:02Z") / 1000;

describe("targeted check", () => {
  it("tells addresses, MACs, networks, hostnames and domains apart", () => {
    expect(classify("192.168.1.42")).toEqual({ kind: "ip", value: "192.168.1.42" });
    expect(classify("A4-C1-38-5E-02-19")).toEqual({ kind: "mac", value: "a4:c1:38:5e:02:19" });
    expect(classify("192.168.1.0/24")).toEqual({ kind: "network", value: "192.168.1.0/24" });
    expect(classify("noas-edge[.]example")).toEqual({ kind: "name", value: "noas-edge.example" });
    expect(classify("nas")).toEqual({ kind: "name", value: "nas" });
    expect(() => classify("rm -rf /")).toThrow(/is not an address/);
    expect(() => classify("")).toThrow(/Type an address/);
  });

  it("checks a device's ports, keeps what it found, and adds Pi-hole's view of it", async () => {
    const queries = [{ id: 1, time: at, type: "A", domain: "fearevolve.com", cname: null, status: "FORWARDED", client: { ip: "192.168.1.10", name: "nas.lan" } }];
    const pihole = fakePihole({ queries });
    const open = [{ port: 22, proto: "tcp", service: "ssh", banner: "SSH-2.0-OpenSSH_9.6p1", product: "OpenSSH", version: "9.6p1", tls: null, risk: null }, { port: 23, proto: "tcp", service: "telnet", banner: null, product: null, version: null, tls: null, risk: "Telnet: remote login with no encryption; a favourite of IoT botnets." }];
    const portsAsked = [];
    const { checker, sentinel, fleet } = testServices({ piholeFetch: pihole.fetchImpl, network: { probeHost: async () => ({ port: 22, answer: "open" }), checkPortsImpl: async (_ip, ports) => { portsAsked.push(ports.length); return open; } } });
    sentinel.configure({ mode: "api", url: "http://192.0.2.5", password: "pihole-pass" }, "owner");
    await sentinel.hunt();
    const r = await checker.run({ query: "192.168.1.10", profile: "standard" }, "owner");
    expect(r).toMatchObject({ kind: "device", ip: "192.168.1.10", up: true });
    expect(portsAsked[0]).toBeGreaterThan(50);
    expect(r.services.map((s) => [s.port, s.product])).toEqual([[22, "OpenSSH"], [23, null]]);
    expect(r.dns).toMatchObject({ connected: true, totalLookups: 1, hits: [expect.objectContaining({ domain: "fearevolve.com" })] });
    expect(checker.get(r.id)).toMatchObject({ query: "192.168.1.10", profile: "standard", ip: "192.168.1.10" });
    // The device is in the registry now, so its MAC-less entry can be found by name or address later.
    expect(fleet.list().find((d) => d.ip === "192.168.1.10")).toBeTruthy();
    expect(checker.recent()[0]).toMatchObject({ query: "192.168.1.10", kind: "ip" });
  });

  it("reads Pi-hole's history for a domain without sending anything to it", async () => {
    const queries = [1, 2, 3].map((i) => ({ id: i, time: at + i, type: "A", domain: i === 3 ? "cdn.noas-edge.example" : "noas-edge.example", cname: null, status: i === 2 ? "GRAVITY" : "FORWARDED", client: { ip: "192.168.1.42", name: "pixel.lan" } }));
    const probed = [];
    const { checker, sentinel } = testServices({ piholeFetch: fakePihole({ queries }).fetchImpl, network: { probeHost: async (ip) => { probed.push(ip); return null; } } });
    sentinel.configure({ mode: "api", url: "http://192.0.2.5", password: "pihole-pass" }, "owner");
    const r = await checker.run({ query: "noas-edge[.]example", profile: "standard" }, "owner");
    expect(r).toMatchObject({ kind: "domain", domain: "noas-edge.example", lookups: 3, clients: [{ ip: "192.168.1.42", lookups: 3, blocked: 1, name: "pixel.lan" }] });
    expect(r.clients[0].names.sort()).toEqual(["cdn.noas-edge.example", "noas-edge.example"]);
    expect(probed).toEqual([]);
  });

  it("refuses what it must not touch", async () => {
    const { checker } = testServices({ network: { lookup: async (name) => (name === "example.com" ? "93.184.216.34" : null) } });
    await expect(checker.run({ query: "8.8.8.8", profile: "quick" }, "owner")).rejects.toThrow(/outside the ranges/);
    await expect(checker.run({ query: "192.168.1.0/24", profile: "deep" }, "owner")).rejects.toThrow(/can only be swept/);
    await expect(checker.run({ query: "aa:bb:cc:dd:ee:ff", profile: "quick" }, "owner")).rejects.toThrow(/No device with MAC/);
    // A public name is a domain, never scanned; without Pi-hole there is nothing to read.
    await expect(checker.run({ query: "example.com", profile: "deep" }, "owner")).rejects.toThrow(/connect Pi-hole/);
    await expect(checker.run({ query: "192.168.1.5", profile: "nmap" }, "owner")).rejects.toThrow(/profile must be/);
  });
});
