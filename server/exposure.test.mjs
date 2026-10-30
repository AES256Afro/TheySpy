import { describe, expect, it } from "vitest";
import { fakePihole, testClock, testServices } from "./test-helpers.mjs";
import { inStarlink, kits, scoreOf } from "./exposure.mjs";


describe("ad exposure", () => {
  it("scores only what is known, and tells Starlink addresses from others", () => {
    expect(scoreOf([{ state: "pass" }, { state: "fail" }, { state: "unknown" }, { state: "na" }])).toEqual({ score: 50, tone: "warn", known: 2, of: 3 });
    expect(scoreOf([{ state: "unknown" }]).score).toBeNull();
    // One passing check out of seven is a number, not a green light.
    expect(scoreOf([{ state: "pass" }, ...Array(6).fill({ state: "unknown" })])).toMatchObject({ score: 100, tone: "unknown", known: 1, of: 7 });
    const feed = "98.97.0.0/16,US,US-CA,,\n2605:59c0::/32,US,,,\n";
    expect(inStarlink("98.97.14.2", feed)).toBe(true);
    expect(inStarlink("203.0.113.5", feed)).toBe(false);
    expect(kits.apple.body()).toContain("<key>allowApplePersonalizedAdvertising</key><false/>");
    expect(kits.windows.body()).toContain('"DisabledByGroupPolicy"=dword:00000001');
  });

  it("moves a phone from red to green as the kit is applied, each factor flipping with its evidence (M8 exit criterion)", async () => {
    const now = testClock("2026-10-30T12:00:00.000Z");
    const { exposure, fleet, agents, sentinel } = testServices({ now, piholeFetch: fakePihole().fetchImpl });
    sentinel.configure({ mode: "api", url: "http://192.0.2.5", password: "pihole-pass" }, "owner");
    fleet.observe([{ ip: "192.168.8.218", mac: "c4:5b:ac:88:22:8d", hostname: "iphone", seenAt: "2026-10-28T09:00:00.000Z" }], "arp");
    const id = fleet.list()[0].id;
    fleet.edit(id, { label: "iPhone", kind: "phone" }, "owner");
    // Before: the phone skips Pi-hole, loads ads, has its ad ID on, sends no GPC, and its browser has an exploited bug.
    agents.observe(id, { gpc: false, adBlocked: false, dnsThroughPihole: false, browser: "Safari 26.0", browserExact: true, exploited: 1, at: now().toISOString() });
    agents.setProfile(id, { os: "ios", osVersion: "26.7.1", adId: "on" }, "owner");
    const before = exposure.overview().devices.find((d) => d.name === "iPhone");
    expect(before).toMatchObject({ tone: "bad", score: 17 });
    expect(before.factors.filter((f) => f.state === "fail").map((f) => f.id)).toEqual(["dns", "blocker", "adid", "gpc", "patched"]);

    // The kit: ad ID deleted, Private DNS off, a blocker, GPC and an updated browser; then This device again.
    now.advance(3_600_000);
    agents.setProfile(id, { os: "ios", osVersion: "26.7.2", adId: "off" }, "owner");
    agents.observe(id, { gpc: true, adBlocked: true, dnsThroughPihole: true, browser: "Brave 1.84", browserExact: true, exploited: 0, at: now().toISOString() });
    const after = exposure.overview().devices.find((d) => d.name === "iPhone");
    expect(after).toMatchObject({ tone: "good", score: 100 });
    const evidence = Object.fromEntries(after.factors.map((f) => [f.id, `${f.state}: ${f.evidence}`]));
    expect(evidence).toEqual({
      dns: "pass: This device’s own check: a test name reached Pi-hole.",
      blocker: "pass: This device’s check: Google’s ad script did not load.",
      adid: "pass: Recorded as off in its profile.",
      gpc: "pass: Sent by Brave 1.84.",
      patched: "pass: None of the versions TheySpy knows for it is known to be exploited.",
      clean: "pass: No lookups of indicator addresses in Pi-hole’s history.",
      scan: "na: Phones are checked with MVT; other devices cannot run the agent.",
    });
  });

  it("checks the connection only when asked, and keeps no address", async () => {
    const webFetch = async (url) => new Response(String(url).includes("trace") ? "fl=1\nip=98.97.14.2\nloc=US\n" : "98.97.0.0/16,US,,,\n");
    const { exposure, settings } = testServices({ webFetch });
    expect(exposure.overview().network.find((f) => f.id === "egress").state).toBe("unknown");
    expect(await exposure.checkEgress("owner")).toMatchObject({ starlink: true, cgnat: false });
    expect(JSON.stringify(settings.get("exposure_egress"))).not.toContain("98.97");
    expect(exposure.overview().network.find((f) => f.id === "egress").state).toBe("fail");
  });
});
