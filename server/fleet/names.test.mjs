import { describe, expect, it } from "vitest";
import { fakePihole, testServices } from "../test-helpers.mjs";
import { bestName, guessKind, networkOf } from "./explain.mjs";

const net = (hwaddr, ip, lastSeen = 1793303880) => ({ id: 1, hwaddr, interface: "eno1", firstSeen: 1793300000, lastQuery: lastSeen, numQueries: 10, macVendor: "", ips: [{ ip, name: null, lastSeen }] });

describe("Fleet names and breadcrumbs", () => {
  it("says which network an address is on, relative to the router", () => {
    expect(networkOf("192.168.8.218", "192.168.8.1")).toMatchObject({ kind: "lan", label: "Your router's network" });
    expect(networkOf("192.168.8.1", "192.168.8.1")).toMatchObject({ kind: "router" });
    expect(networkOf("100.64.0.42", "192.168.8.1")).toMatchObject({ kind: "tailscale" });
    expect(networkOf("172.18.0.1", "192.168.8.1")).toMatchObject({ kind: "docker", detail: expect.stringMatching(/containers/) });
    expect(networkOf("10.8.0.5", "192.168.8.1")).toMatchObject({ kind: "other" });
    expect(networkOf("192.168.48.3", "192.168.8.1", "02:42:c0:a8:30:03")).toMatchObject({ kind: "docker", label: "Docker container" });
    expect(guessKind({ mac: "02:42:ac:17:00:02" })).toMatchObject({ label: "Docker container" });
  });

  it("names a device by your label, then Pi-hole's, the router's, Tailscale's, and guesses otherwise", () => {
    expect(bestName({ label: "Kitchen iPad", names: { pihole: "iPad" }, ip: "x" })).toEqual({ name: "Kitchen iPad", from: "your label in TheySpy" });
    expect(bestName({ names: { router: "Mac.tail0000aa.ts.net", tailscale: "mac" }, ip: "x" })).toEqual({ name: "Mac", from: "your router" });
    expect(bestName({ names: {}, vendor: "Western Digital Corporation", ip: "192.168.8.165" })).toEqual({ name: "Network storage at 192.168.8.165", from: "a guess from the MAC's maker" });
    expect(bestName({ names: {}, mac: "ea:f1:83:00:00:98", ip: "192.168.8.134" })).toMatchObject({ name: "Phone, tablet or laptop at 192.168.8.134" });
    expect(guessKind({ names: ["iphone182.tail0000aa.ts.net"] })).toMatchObject({ kind: "phone", label: "iPhone" });
  });

  it("takes your Pi-hole client labels and asks the router and Tailscale for names", async () => {
    const pihole = fakePihole({ gateway: "192.168.8.1", network: [net("30:c5:99:00:00:3a", "192.168.8.140"), net("ea:f1:83:00:00:98", "192.168.8.134"), net("ip-100.64.0.42", "100.64.0.42"), net("0a:9c:b4:00:00:e0", "172.18.0.1")] });
    pihole.state.clients.push({ client: "30:c5:99:00:00:3a", comment: "BlackBox", groups: [0] }, { client: "ea:f1:83:00:00:98", comment: "Apple Watch", groups: [0] });
    const asked = [];
    const answers = { "192.168.8.1 192.168.8.140": "BlackBox.tail0000aa.ts.net", "100.100.100.100 100.64.0.42": "iphone182.tail0000aa.ts.net" };
    const { discovery, fleet, sentinel } = testServices({ piholeFetch: pihole.fetchImpl, scanRanges: ["192.168.0.0/16", "172.16.0.0/12", "100.64.0.0/10"], network: { reverseVia: async (server, ip) => { asked.push(`${server} ${ip}`); return answers[`${server} ${ip}`] ?? null; } } });
    sentinel.configure({ mode: "api", url: "http://192.0.2.5/admin", password: "pihole-pass" }, "owner");
    await discovery.sync();
    const by = Object.fromEntries(fleet.list().map((d) => [d.ip, d]));
    expect(by["192.168.8.140"]).toMatchObject({ name: "BlackBox", nameFrom: "your Pi-hole label", network: { kind: "lan" }, names: { pihole: "BlackBox", tailscale: "BlackBox.tail0000aa.ts.net" } });
    expect(by["192.168.8.134"]).toMatchObject({ name: "Apple Watch", guess: { label: "Apple Watch" } });
    expect(by["100.64.0.42"]).toMatchObject({ name: "iphone182", nameFrom: "Tailscale", network: { kind: "tailscale" }, guess: { kind: "phone" } });
    expect(by["172.18.0.1"].network.kind).toBe("docker");
    expect(asked.some((a) => a.endsWith("172.18.0.1"))).toBe(false); // a Docker gateway is not a device to name
    expect(fleet.namesByIp()["192.168.8.140"]).toMatchObject({ name: "BlackBox", network: "Your router's network" });
    // Names are not asked for again within six hours.
    asked.length = 0;
    await discovery.sync();
    expect(asked).toEqual([]);
  });
});
