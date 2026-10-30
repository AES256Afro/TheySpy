import { describe, expect, it } from "vitest";
import { testClock, testServices } from "../test-helpers.mjs";

const at = (iso) => new Date(iso).toISOString();

describe("device registry", () => {
  it("takes the first observations as the inventory, then announces each new MAC once", () => {
    const { fleet, audit } = testServices({ now: testClock("2026-10-29T12:00:00Z") });
    fleet.observe([{ ip: "192.168.1.20", mac: "f0:18:98:00:00:0c", hostname: "macbook", seenAt: at("2026-10-29T11:59:00Z") }, { ip: "192.168.1.42", mac: "a4:c1:38:00:00:19", seenAt: at("2026-10-29T11:00:00Z") }], "pihole");
    expect(fleet.list().every((d) => !d.isNew)).toBe(true);
    expect(fleet.list().find((d) => d.ip === "192.168.1.20")).toMatchObject({ online: true, name: "macbook" });
    expect(fleet.list().find((d) => d.ip === "192.168.1.42").online).toBe(false);

    const created = fleet.observe([{ ip: "192.168.1.88", mac: "3c:a9:f4:00:00:21", seenAt: at("2026-10-29T11:59:30Z") }], "sweep");
    fleet.observe([{ ip: "192.168.1.88", mac: "3c:a9:f4:00:00:21", seenAt: at("2026-10-29T11:59:40Z") }], "pihole");
    expect(created).toHaveLength(1);
    expect(fleet.list().find((d) => d.ip === "192.168.1.88")).toMatchObject({ isNew: true, sources: { sweep: expect.any(String), pihole: expect.any(String) } });
    const announced = audit.list(50).filter((e) => e.action === "fleet.new_device");
    expect(announced).toHaveLength(1);
    expect(audit.list(50).filter((e) => e.action === "fleet.inventoried")).toHaveLength(1);
  });

  it("merges an IP-only device into its MAC when one turns up, keeping what the owner set", () => {
    const { fleet } = testServices();
    fleet.observe([{ ip: "192.168.1.5", mac: "d8:3a:dd:00:00:01", seenAt: at("2026-10-29T10:00:00Z") }], "pihole");
    fleet.observe([{ ip: "192.168.1.61", seenAt: at("2026-10-29T10:01:00Z") }], "sweep");
    const tv = fleet.list().find((d) => d.ip === "192.168.1.61");
    fleet.edit(tv.id, { label: "LG TV", tags: ["IoT", "iot", " living room "] }, "owner");
    fleet.observe([{ ip: "192.168.1.61", mac: "64:95:6c:00:00:aa", vendor: "LG Electronics", seenAt: at("2026-10-29T10:02:00Z") }], "arp");
    const devices = fleet.list();
    expect(devices).toHaveLength(2);
    expect(devices.find((d) => d.ip === "192.168.1.61")).toMatchObject({ mac: "64:95:6c:00:00:aa", label: "LG TV", tags: ["iot", "living room"], vendor: "LG Electronics", firstSeen: at("2026-10-29T10:01:00Z") });
  });

  it("follows a device to a new address and records the change", () => {
    const { fleet } = testServices();
    fleet.observe([{ ip: "192.168.1.42", mac: "a4:c1:38:00:00:19", hostname: "pixel", seenAt: at("2026-10-29T09:00:00Z") }], "pihole");
    fleet.observe([{ ip: "192.168.1.43", mac: "a4:c1:38:00:00:19", hostname: "pixel-9", seenAt: at("2026-10-29T10:00:00Z") }], "pihole");
    // An older report of the old address does not move it back.
    fleet.observe([{ ip: "192.168.1.42", mac: "a4:c1:38:00:00:19", seenAt: at("2026-10-29T09:30:00Z") }], "arp");
    const [device] = fleet.list();
    expect(device).toMatchObject({ ip: "192.168.1.43", hostname: "pixel-9", addresses: 2 });
    expect(fleet.get(device.id).events.map((e) => e.kind)).toEqual(["name_changed", "ip_changed", "inventoried"]);
  });

  it("lets the owner label and trust a device, which acknowledges it", () => {
    const { fleet } = testServices();
    fleet.observe([{ ip: "192.168.1.1", mac: "00:11:32:00:00:7a", seenAt: at("2026-10-29T10:00:00Z") }], "pihole");
    fleet.observe([{ ip: "192.168.1.9", mac: "00:11:32:00:00:7b", seenAt: at("2026-10-29T10:00:00Z") }], "pihole");
    const nas = fleet.list().find((d) => d.ip === "192.168.1.9");
    expect(nas.isNew).toBe(true);
    expect(fleet.edit(nas.id, { label: "Synology", trusted: true, owner: "Sam" }, "owner")).toMatchObject({ label: "Synology", trusted: true, owner: "Sam", isNew: false });
    expect(() => fleet.edit(nas.id, { tags: "x" }, "owner")).toThrow(/tags must be a list/);
    fleet.forget(nas.id, "owner");
    expect(fleet.get(nas.id)).toBeNull();
  });

  describe("one device, all its addresses", () => {
    // BigBox's own fleet: each device seen at home and again over Tailscale.
    function homeAndTailnet() {
      const t = testServices({ now: testClock("2026-10-30T20:00:00Z") });
      const seenAt = at("2026-10-30T19:59:00Z");
      t.fleet.observe([
        { ip: "192.168.8.10", mac: "d8:3a:dd:00:00:10", seenAt },
        { ip: "192.168.8.186", mac: "3e:11:22:33:44:55", seenAt },
        { ip: "192.168.8.218", mac: "f0:18:98:00:00:21", seenAt },
        { ip: "192.168.8.99", mac: "6a:00:00:00:00:99", seenAt },
      ], "pihole");
      t.fleet.observe([{ ip: "100.67.166.48", seenAt }, { ip: "100.78.167.117", seenAt }, { ip: "100.116.232.42", seenAt }], "pihole");
      const id = (ip) => t.fleet.list().find((d) => d.ip === ip).id;
      t.fleet.setNames(id("192.168.8.10"), { pihole: "BigBox", piholeClient: "listed" });
      t.fleet.setNames(id("192.168.8.186"), { pihole: "iPad", piholeClient: "listed" });
      t.fleet.setNames(id("192.168.8.218"), { pihole: "iPhone", piholeClient: "listed" });
      t.fleet.setNames(id("192.168.8.99"), { tailscale: "iphone.tail6233fa.ts.net" });
      t.fleet.setNames(id("100.67.166.48"), { tailscale: "bigbox.tail6233fa.ts.net" });
      t.fleet.setNames(id("100.78.167.117"), { tailscale: "ipad173.tail6233fa.ts.net" });
      t.fleet.setNames(id("100.116.232.42"), { tailscale: "iphone182.tail6233fa.ts.net" });
      return { ...t, id };
    }

    it("merges a Tailscale address into the home device its name proves, and keeps the home address first", () => {
      const { fleet, audit } = homeAndTailnet();
      const { merged } = fleet.consolidate();
      expect(merged).toEqual([{ from: "100.67.166.48", into: "192.168.8.10", name: "bigbox" }]);
      const bigbox = fleet.list().find((d) => d.names.pihole === "BigBox");
      expect(bigbox).toMatchObject({ ip: "192.168.8.10", homeIp: "192.168.8.10", tailscaleIp: "100.67.166.48", names: { tailscale: "bigbox.tail6233fa.ts.net", pihole: "BigBox" } });
      expect(fleet.get(bigbox.id)).toMatchObject({ homeIp: "192.168.8.10", tailscaleIp: "100.67.166.48" });
      expect(fleet.list()).toHaveLength(6);
      expect(audit.list(50).some((e) => e.action === "fleet.devices_merged")).toBe(true);
      // Nothing left that the names prove: a second run merges nothing.
      expect(fleet.consolidate().merged).toEqual([]);
    });

    it("suggests the uncertain pairs, merges on the owner's word, and forgets a pair said to be two devices", () => {
      const { fleet, id } = homeAndTailnet();
      fleet.consolidate();
      const pairs = fleet.suggestions().map((s) => [s.from.ip, s.into.ip].sort().join(" + "));
      expect(pairs).toContain("100.78.167.117 + 192.168.8.186");
      expect(pairs).toContain("100.116.232.42 + 192.168.8.218");
      // Two real (non-private) MACs are two devices, never suggested.
      expect(pairs.some((p) => p.includes("192.168.8.10"))).toBe(false);
      const ipad = fleet.suggestions().find((s) => s.from.ip === "100.78.167.117");
      expect(ipad.into.ip).toBe("192.168.8.186");
      expect(fleet.mergeDevices(ipad.from.id, ipad.into.id, "owner")).toMatchObject({ homeIp: "192.168.8.186", tailscaleIp: "100.78.167.117" });
      fleet.notSame(id("100.116.232.42"), id("192.168.8.218"), "owner");
      expect(fleet.suggestions().some((s) => [s.from.ip, s.into.ip].includes("192.168.8.218") && [s.from.ip, s.into.ip].includes("100.116.232.42"))).toBe(false);
      expect(() => fleet.mergeDevices(ipad.into.id, ipad.into.id, "owner")).toThrow(/two different/);
    });

    it("counts tailnet and Pi-hole client devices as yours, unless the owner said otherwise", () => {
      const { fleet, id } = homeAndTailnet();
      const iphone = id("192.168.8.218");
      fleet.edit(iphone, { trusted: false }, "owner");
      const { trusted } = fleet.consolidate();
      expect(trusted).toBeGreaterThan(0);
      expect(fleet.get(id("192.168.8.10")).trusted).toBe(true);
      expect(fleet.get(id("100.116.232.42")).trusted).toBe(true);
      expect(fleet.get(iphone).trusted).toBe(false);
    });
  });
});
