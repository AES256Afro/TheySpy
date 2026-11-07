import { describe, expect, it } from "vitest";
import { testClock, testServices } from "./test-helpers.mjs";

const at = (iso) => new Date(iso).toISOString();

describe("the overview (M15)", () => {
  it("composes from a fresh database without an error, and says what it cannot see", () => {
    const { overview } = testServices({ now: testClock("2026-11-07T12:00:00Z") });
    const o = overview.compose();
    expect(o.status).toMatchObject({ pihole: false, watch: false, devices: 0, online: 0 });
    expect(o.questions.contacts.count).toBe(0);
    expect(o.questions.exploited.count).toBe(0);
    expect(o.questions.newDevices.count).toBe(0);
    expect(o.questions.network.of).toBe(3);
    expect(o.devices).toEqual([]);
    expect(Array.isArray(o.events)).toBe(true);
  });

  it("puts a device that reached an unblocked indicator first, under any address it has held", () => {
    const { overview, fleet, db } = testServices({ now: testClock("2026-11-07T12:00:00Z"), piholeEnv: { url: "http://pihole.lan", password: "x", write: false } });
    fleet.observe([{ ip: "192.168.1.30", mac: "f0:18:98:00:00:aa", hostname: "laptop", seenAt: at("2026-11-01T10:00:00Z") }, { ip: "192.168.1.9", mac: "00:11:32:00:00:7a", hostname: "nas", seenAt: at("2026-11-01T10:00:00Z") }], "pihole", { inventory: true });
    db.prepare("INSERT INTO ioc_hit_events (source, query_id, at, indicator, domain, via, client_ip, client_name, status, blocked, found_by, found_at) VALUES ('pihole', 1, ?, 'adfection-c2.example', 'adfection-c2.example', 'query', '192.168.1.30', 'laptop', 'FORWARDED', 0, 'hunt', ?)")
      .run(at("2026-11-06T21:14:00Z"), at("2026-11-06T21:15:00Z"));
    fleet.observe([{ ip: "192.168.1.31", mac: "f0:18:98:00:00:aa", seenAt: at("2026-11-07T11:55:00Z") }], "pihole"); // a new lease
    const o = overview.compose();
    expect(o.questions.contacts).toMatchObject({ count: 1, lookups: 1 });
    expect(o.devices[0]).toMatchObject({ name: "laptop", ip: "192.168.1.31", hits: 1, notBlocked: 1, attention: 3 });
    expect(o.devices[1]).toMatchObject({ name: "nas", hits: 0, attention: 0 });
  });

  it("turns the last day's audit entries into lines, newest first, and leaves jobs out", () => {
    const { overview, audit } = testServices({ now: testClock("2026-11-07T12:00:00Z") });
    audit.record("system", "job.started", "job:1");
    audit.record("system", "fleet.new_device", "aa:bb:cc:00:00:01", { ip: "192.168.1.88", vendor: "Espressif", source: "sweep" });
    audit.record("system", "cves.kev_added", null, { cves: ["CVE-2026-4127"] });
    const lines = overview.compose().events;
    expect(lines.some((e) => e.action.startsWith("job."))).toBe(false);
    const mine = lines.filter((e) => ["cves.kev_added", "fleet.new_device"].includes(e.action));
    expect(mine.map((e) => e.action)).toEqual(["cves.kev_added", "fleet.new_device"]);
    expect(mine[1]).toMatchObject({ tone: "warn", text: "New device Espressif 192.168.1.88", link: "/fleet" });
  });
});

describe("M16 C27", () => {
  it("shows a line for the actions it knows and nothing for the rest", () => {
    const { overview, audit } = testServices({ now: testClock("2026-11-07T12:00:00Z") });
    audit.record("system", "blocklists.updated", "hagezi-normal", { name: "HaGeZi Normal", entries: 2391106 });
    audit.record("owner", "some.future_action", "x");
    const lines = overview.compose().events;
    expect(lines.find((e) => e.action === "blocklists.updated")).toMatchObject({ text: "Blocklist updated: HaGeZi Normal · 2,391,106 entries", link: "/blocklists" });
    expect(lines.some((e) => e.action === "some.future_action")).toBe(false);
    expect(lines.every((e) => !/^[a-z]+\.[a-z_]+( |$)/.test(e.text))).toBe(true);
  });
});
