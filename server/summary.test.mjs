import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { openDatabase } from "./db.mjs";
import { summarize } from "./summary.mjs";
import { testClock, testServices } from "./test-helpers.mjs";

const dirs = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

function seeded() {
  const dir = mkdtempSync(path.join(os.tmpdir(), "theyspy-summary-"));
  dirs.push(dir);
  const file = path.join(dir, "theyspy.db");
  const now = testClock();
  const { db, fleet } = testServices({ db: openDatabase(file), now });
  fleet.observe([{ ip: "192.168.1.20", mac: "f0:18:98:00:00:0c", hostname: "kids-ipad", seenAt: "2026-10-29T11:59:00.000Z" }], "pihole");
  const [device] = fleet.list();
  const hit = db.prepare("INSERT INTO ioc_hit_events (source, query_id, at, indicator, domain, via, client_ip, client_name, status, blocked, found_by, found_at) VALUES ('api', ?, ?, 'fearevolve.com', 'cdn.fearevolve.com', 'query', '192.168.1.20', NULL, ?, ?, 'watch', ?)");
  hit.run(1, "2026-10-28T10:00:00.000Z", "FORWARDED", 0, "2026-10-28T10:00:05.000Z");
  hit.run(2, "2026-10-28T11:00:00.000Z", "GRAVITY", 1, "2026-10-28T11:00:05.000Z");
  db.prepare("INSERT INTO findings (device_id, source, kind, indicator, at) VALUES (?, 'agent', 'contacted', 'fearevolve.com', '2026-10-29T09:00:00.000Z')").run(device.id);
  db.prepare("INSERT INTO findings (device_id, source, kind, detail, at) VALUES (?, 'agent', 'gap', 'Safari history not readable', '2026-10-29T09:00:00.000Z')").run(device.id);
  db.close();
  return { dir, file, now };
}

describe("summary for tools on the same machine", () => {
  it("reads a database read-only and says what matters, defanged and bounded", () => {
    const { file, now } = seeded();
    const before = statSync(file).mtimeMs;
    const db = new DatabaseSync(file, { readOnly: true });
    const s = summarize(db, { now });
    db.close();
    expect(s.indicatorLookups).toMatchObject({ total: 1, notFullyBlocked: 1, top: [{ device: "kids-ipad", indicator: "fearevolve[.]com", lookups: 2, blocked: 1 }] });
    expect(s.evidence).toMatchObject({ contacted: 1, newThisPeriod: 1, gaps: 1, top: [{ device: "kids-ipad", indicator: "fearevolve[.]com", source: "agent" }] });
    expect(s.sections.map((x) => x.title)).toContain("Spyware and ad-intelligence");
    expect(s.sections.find((x) => x.title === "Spyware and ad-intelligence").tone).toBe("bad");
    expect(JSON.stringify(s)).not.toContain("fearevolve.com");
    expect(statSync(file).mtimeMs).toBe(before);
  });

  it("runs as a command in the image: one line of JSON, and an error as JSON too", () => {
    const { dir } = seeded();
    const script = new URL("./summary.mjs", import.meta.url).pathname;
    const out = JSON.parse(execFileSync(process.execPath, [script, "7"], { env: { ...process.env, TS_DATA_DIR: dir }, encoding: "utf8" }));
    expect(out).toMatchObject({ days: 7, indicatorLookups: { total: expect.any(Number) }, evidence: { contacted: 1 } });
    let failed;
    try { execFileSync(process.execPath, [script], { env: { ...process.env, TS_DATA_DIR: path.join(dir, "missing") }, encoding: "utf8" }); } catch (error) { failed = error; }
    expect(failed.status).toBe(1);
    expect(JSON.parse(failed.stdout)).toMatchObject({ error: expect.any(String) });
  });
});
