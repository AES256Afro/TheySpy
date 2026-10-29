import { describe, expect, it } from "vitest";
import { createAuditLog } from "./audit.mjs";
import { openDatabase } from "./db.mjs";
import { createJobRunner } from "./jobs.mjs";
import { testServices } from "./test-helpers.mjs";

describe("job runner", () => {
  it("runs the no-op job and records it in the audit log", async () => {
    const { jobs, audit } = testServices();
    const queued = jobs.enqueue("noop", { actor: "owner" });
    expect(queued.status).toMatch(/queued|running/);
    await jobs.idle();
    const done = jobs.get(queued.id);
    expect(done.status).toBe("succeeded");
    expect(done.log).toContain("Nothing to do");
    expect(audit.list().map((entry) => entry.action).filter((action) => action.startsWith("job.")).reverse()).toEqual(["job.queued", "job.started", "job.succeeded"]);
  });

  it("records a failing job as failed with its error", async () => {
    const db = openDatabase(":memory:");
    const audit = createAuditLog(db);
    const jobs = createJobRunner({ db, audit, kinds: { boom: { title: "Boom", run: async () => { throw new Error("kaboom"); } } } });
    const { id } = jobs.enqueue("boom", { actor: "owner" });
    await jobs.idle();
    expect(jobs.get(id)).toMatchObject({ status: "failed", result: { error: "kaboom" } });
    expect(audit.list()[0]).toMatchObject({ action: "job.failed", detail: { error: "kaboom" } });
  });

  it("refuses unknown kinds", () => {
    const { jobs } = testServices();
    expect(() => jobs.enqueue("rm -rf", { actor: "owner" })).toThrow(/Unknown job kind/);
  });

  it("marks jobs left running by a previous process as interrupted", () => {
    const db = openDatabase(":memory:");
    const audit = createAuditLog(db);
    db.prepare("INSERT INTO jobs (kind, title, status, actor, created_at) VALUES ('noop', 'x', 'running', 'owner', '2026-10-29T00:00:00Z')").run();
    const jobs = createJobRunner({ db, audit });
    expect(jobs.list()[0].status).toBe("interrupted");
    expect(audit.list()[0].action).toBe("job.interrupted");
  });
});
