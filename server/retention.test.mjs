import { describe, expect, it } from "vitest";
import { createRetention, defaultPolicy } from "./retention.mjs";
import { testClock, testServices } from "./test-helpers.mjs";

const iso = (now, daysAgo) => new Date(now().getTime() - daysAgo * 86_400_000).toISOString();

function build(options = {}) {
  const now = testClock("2026-11-07T12:00:00.000Z");
  const services = testServices({ now, ...options });
  const retention = createRetention({ db: services.db, settings: services.settings, audit: services.audit, now });
  return { ...services, retention, now };
}

describe("retention (M35)", () => {
  it("removes what has aged out and keeps what is young, unfinished, or an agent's latest", () => {
    const { db, retention, now, fleet } = build();
    fleet.observe([{ ip: "192.168.1.20", mac: "f0:18:98:00:00:0c", hostname: "macbook", seenAt: now().toISOString() }], "pihole");
    const [device] = fleet.list();
    const hit = db.prepare("INSERT INTO ioc_hit_events (source, query_id, at, indicator, domain, via, client_ip, status, blocked, found_by, found_at) VALUES ('pihole', ?, ?, 'fearevolve.com', 'fearevolve.com', 'query', '192.168.1.20', 'FORWARDED', 0, 'hunt', ?)");
    hit.run(1, iso(now, 400), iso(now, 400));
    hit.run(2, iso(now, 10), iso(now, 10));
    const job = db.prepare("INSERT INTO jobs (kind, title, params, status, actor, created_at) VALUES ('noop', 'x', '{}', ?, 'owner', ?)");
    job.run("succeeded", iso(now, 100));
    job.run("queued", iso(now, 100));
    job.run("succeeded", iso(now, 5));
    const check = db.prepare("INSERT INTO checks (query, kind, profile, started_at, finished_at, actor) VALUES ('192.168.1.20', 'ip', 'standard', ?, ?, 'owner')");
    check.run(iso(now, 400), iso(now, 400));
    check.run(iso(now, 400), null);
    db.prepare("INSERT INTO device_events (device_id, at, kind) VALUES (?, ?, 'ip_changed')").run(device.id, iso(now, 400));
    db.prepare("INSERT INTO cve_events (cve_id, at, kind) VALUES ('CVE-2020-0001', ?, 'kev_added')").run(iso(now, 400));
    db.prepare("INSERT INTO agents (id, device_id, name, secret_sealed, enrolled_at) VALUES (1, ?, 'macbook', 'sealed', ?)").run(device.id, iso(now, 500));
    const report = db.prepare("INSERT INTO agent_reports (agent_id, at, verdict, report) VALUES (1, ?, 'clean', '{}')");
    report.run(iso(now, 300));
    report.run(iso(now, 200));
    const auditBefore = Number(db.prepare("SELECT COUNT(*) AS n FROM audit_log").get().n);
    db.prepare("INSERT INTO audit_log (at, actor, action) VALUES (?, 'owner', 'old.thing')").run(iso(now, 100));

    const lines = [];
    const summary = retention.trim({ log: (line) => lines.push(line) });

    expect(summary.removed).toEqual({ hits: 1, audit: 1, jobs: 1, checks: 1, events: 2, reports: 1 });
    expect(db.prepare("SELECT query_id FROM ioc_hit_events").all()).toEqual([{ query_id: 2 }]);
    expect(db.prepare("SELECT status FROM jobs ORDER BY id").all().map((r) => r.status)).toEqual(["queued", "succeeded"]);
    expect(db.prepare("SELECT finished_at FROM checks").all()).toEqual([{ finished_at: null }]);
    // The agent's latest report stays although it is older than the policy.
    expect(db.prepare("SELECT at FROM agent_reports").all()).toEqual([{ at: iso(now, 200) }]);
    expect(Number(db.prepare("SELECT COUNT(*) AS n FROM audit_log").get().n)).toBe(auditBefore + 1); // the trim's own entry
    expect(lines.join("\n")).toContain("Finished jobs: 1 removed, older than 90 days.");
    expect(summary.compacted).toBe(false);
  });

  it("compacts the file once a tenth of it is free, and says so", () => {
    const { db, retention, now } = build();
    const filler = db.prepare("INSERT INTO audit_log (at, actor, action, detail) VALUES (?, 'owner', 'bulk', ?)");
    const blob = "x".repeat(4000);
    for (let i = 0; i < 300; i++) filler.run(iso(now, 100), blob);
    const before = retention.size().bytes;
    const summary = retention.trim();
    expect(summary.removed.audit).toBe(300);
    expect(summary.compacted).toBe(true);
    expect(retention.size().bytes).toBeLessThan(before);
    expect(retention.size().lastTrim).toEqual(summary);
  });

  it("reports the file's size and the tables by weight", () => {
    const { retention } = build();
    const size = retention.size();
    expect(size.bytes).toBeGreaterThan(0);
    const names = size.tables.map((t) => t.name);
    expect(names).toContain("cves");
    expect(names).toContain("ioc_hit_events");
    const iocs = size.tables.find((t) => t.name === "iocs");
    expect(iocs.rows).toBeGreaterThan(0);
    // Node's SQLite has dbstat, so the bytes are known and the heaviest table comes first.
    expect(size.tables[0].bytes).toBeGreaterThanOrEqual(size.tables.at(-1).bytes);
  });

  it("takes a policy in whole days within the limits and refuses the rest by name", () => {
    const { retention, audit } = build();
    expect(retention.policy()).toEqual(defaultPolicy);
    expect(retention.configure({ audit: 30, hits: "730" }, "owner")).toMatchObject({ audit: 30, hits: 730, jobs: 90 });
    expect(retention.policy()).toMatchObject({ audit: 30, hits: 730 });
    expect(audit.list(1)[0]).toMatchObject({ action: "retention.saved", detail: { audit: 30 } });
    for (const bad of [{ jobs: 3 }, { jobs: 5000 }, { jobs: "90.5" }, { jobs: -1 }]) {
      expect(() => retention.configure(bad, "owner")).toThrow("Finished jobs: between 7 and 3650 days");
    }
    expect(retention.policy().jobs).toBe(90);
  });
});
