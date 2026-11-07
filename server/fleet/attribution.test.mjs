import { describe, expect, it } from "vitest";
import { attributeHits, holderAt } from "./attribution.mjs";

const holders = new Map([
  ["192.168.1.30", [
    { deviceId: 1, first: "2026-01-10T10:00:00.000Z", last: "2026-02-01T10:00:00.000Z" }, // the tablet
    { deviceId: 2, first: "2026-11-07T11:00:00.000Z", last: "2026-11-07T11:00:00.000Z" }, // the laptop, current
  ]],
]);

describe("who held an address when (M16, B22)", () => {
  it("credits a time to the device that had the lease then: from a little before its first sighting until the next holder appears", () => {
    expect(holderAt(holders, "192.168.1.30", "2026-01-12T10:00:00.000Z")).toBe(1);
    expect(holderAt(holders, "192.168.1.30", "2026-06-01T00:00:00.000Z")).toBe(1); // nobody else seen yet: still the tablet's lease
    expect(holderAt(holders, "192.168.1.30", "2026-11-06T13:00:00.000Z")).toBe(2); // the laptop's lease, a little before Pi-hole first saw it
    expect(holderAt(holders, "192.168.1.30", "2026-11-05T13:00:00.000Z")).toBe(1); // more than the slack before: the tablet's
    expect(holderAt(holders, "192.168.1.30", "2026-12-25T00:00:00.000Z")).toBe(2); // still the current holder
    expect(holderAt(holders, "192.168.1.30", "2025-12-01T00:00:00.000Z")).toBeNull(); // before anyone known
    expect(holderAt(holders, "10.0.0.1", "2026-11-07T09:00:00.000Z")).toBeNull();
    expect(holderAt(holders, "192.168.1.30", "not a time")).toBeNull();
  });

  it("groups hits per device the way sentinel.hits() groups them per address", () => {
    const events = [
      { at: "2026-01-12T10:00:00.000Z", indicator: "c2.example", domain: "c2.example", via: "query", clientIp: "192.168.1.30", clientName: "old-tablet", blocked: 0, status: "FORWARDED", tier: "cc" },
      { at: "2026-01-12T10:01:00.000Z", indicator: "c2.example", domain: "c2.example", via: "query", clientIp: "192.168.1.30", clientName: "old-tablet", blocked: 1, status: "GRAVITY", tier: "cc" },
      { at: "2026-11-07T11:30:00.000Z", indicator: "c2.example", domain: "c2.example", via: "query", clientIp: "192.168.1.30", clientName: "new-laptop", blocked: 0, status: "FORWARDED", tier: "cc" },
    ];
    const byDevice = attributeHits(events, holders);
    expect(byDevice.get(1)).toEqual([expect.objectContaining({ indicator: "c2.example", lookups: 2, blocked: 1, firstSeen: "2026-01-12T10:00:00.000Z", lastSeen: "2026-01-12T10:01:00.000Z", lastStatus: "GRAVITY", clientName: "old-tablet" })]);
    expect(byDevice.get(2)).toEqual([expect.objectContaining({ lookups: 1, blocked: 0, clientName: "new-laptop" })]);
  });
});
