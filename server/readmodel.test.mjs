import { describe, expect, it } from "vitest";
import { testClock, testServices } from "./test-helpers.mjs";

describe("the read model's indicator lookups (M23, B32)", () => {
  it("reports the window's own lookups, credited to the device that held the address then", () => {
    const { db, fleet, read } = testServices({ now: testClock("2026-11-07T12:00:00Z") });
    // The tablet held .30 in July; the laptop has had it since 6 November.
    fleet.observe([{ ip: "192.168.1.30", mac: "a4:c1:38:00:00:01", hostname: "tablet", seenAt: "2026-07-01T10:00:00.000Z" }], "pihole", { inventory: true });
    fleet.observe([{ ip: "192.168.1.30", mac: "a4:c1:38:00:00:02", hostname: "laptop", seenAt: "2026-11-06T10:00:00.000Z" }], "pihole");
    const hit = db.prepare("INSERT INTO ioc_hit_events (source, query_id, at, indicator, domain, via, client_ip, client_name, status, blocked, found_by, found_at) VALUES ('api', ?, ?, 'c2.example', 'c2.example', 'query', '192.168.1.30', NULL, ?, ?, 'hunt', ?)");
    for (let i = 0; i < 500; i += 1) hit.run(1000 + i, new Date(Date.parse("2026-07-02T00:00:00Z") + i * 60_000).toISOString(), "FORWARDED", 0, "2026-07-03T00:00:00.000Z");
    hit.run(9999, "2026-11-07T09:00:00.000Z", "GRAVITY", 1, "2026-11-07T09:00:30.000Z");
    // This week: one lookup, blocked, the laptop's - not 501 with 500 that got through.
    expect(read.indicatorLookups(7)).toEqual([expect.objectContaining({ device: "laptop", indicator: "c2[.]example", lookups: 1, blocked: 1, firstSeen: "2026-11-07T09:00:00.000Z" })]);
    // The year: the tablet's 500 and the laptop's one, apart.
    expect(read.indicatorLookups(365).map((l) => [l.device, l.lookups, l.blocked])).toEqual([["laptop", 1, 1], ["tablet", 500, 0]]);
  });
});
