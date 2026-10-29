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
});
