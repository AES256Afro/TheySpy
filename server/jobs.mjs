/**
 * Job kinds. Every action that does work (a scan, a feed sync, a Pi-hole push) is a job: queued,
 * run one at a time, logged line by line, and recorded in the audit log when it starts and ends.
 * Later milestones add kinds here; the runner does not change.
 * @type {Record<string, { title: string, run: (context: { log: (line: string) => void, params: any }) => Promise<unknown> }>}
 */
export const jobKinds = {
  noop: {
    title: "Check the job runner",
    async run({ log }) {
      log("Nothing to do. The job runner, its log and the audit trail are working.");
      return { ok: true };
    },
  },
};

/**
 * @param {{
 *   db: import("node:sqlite").DatabaseSync,
 *   audit: ReturnType<typeof import("./audit.mjs").createAuditLog>,
 *   kinds?: typeof jobKinds,
 *   now?: () => Date,
 * }} options
 */
export function createJobRunner({ db, audit, kinds = jobKinds, now = () => new Date() }) {
  const insert = db.prepare("INSERT INTO jobs (kind, title, params, status, actor, created_at) VALUES (?, ?, ?, 'queued', ?, ?)");
  const start = db.prepare("UPDATE jobs SET status = 'running', started_at = ? WHERE id = ?");
  const appendLog = db.prepare("UPDATE jobs SET log = log || ? WHERE id = ?");
  const finish = db.prepare("UPDATE jobs SET status = ?, result = ?, finished_at = ? WHERE id = ?");
  const nextQueued = db.prepare("SELECT id, kind, params FROM jobs WHERE status = 'queued' ORDER BY id LIMIT 1");
  const byId = db.prepare("SELECT * FROM jobs WHERE id = ?");
  const recent = db.prepare("SELECT id, kind, title, status, actor, created_at, started_at, finished_at FROM jobs ORDER BY id DESC LIMIT ?");

  // A job still marked running belonged to a process that is gone. Say so instead of pretending it runs.
  const stranded = db.prepare("SELECT id FROM jobs WHERE status = 'running'").all();
  for (const row of stranded) {
    const id = Number(/** @type {any} */ (row).id);
    finish.run("interrupted", null, now().toISOString(), id);
    audit.record("system", "job.interrupted", `job:${id}`, { reason: "TheySpy restarted while it ran" });
  }

  let draining = null;

  async function runOne(row) {
    const id = Number(row.id);
    const kind = kinds[row.kind];
    start.run(now().toISOString(), id);
    audit.record(`job:${id}`, "job.started", row.kind);
    const log = (line) => appendLog.run(`${now().toISOString()} ${line}\n`, id);
    try {
      if (!kind) throw new Error(`Unknown job kind "${row.kind}"`);
      const result = await kind.run({ log, params: JSON.parse(row.params) });
      finish.run("succeeded", JSON.stringify(result ?? null), now().toISOString(), id);
      audit.record(`job:${id}`, "job.succeeded", row.kind);
    } catch (error) {
      log(`Failed: ${error.message}`);
      finish.run("failed", JSON.stringify({ error: error.message }), now().toISOString(), id);
      audit.record(`job:${id}`, "job.failed", row.kind, { error: error.message });
    }
  }

  function drain() {
    if (!draining) {
      draining = (async () => {
        for (let row = nextQueued.get(); row; row = nextQueued.get()) await runOne(row);
      })().finally(() => { draining = null; });
    }
    return draining;
  }

  function parse(row) {
    if (!row) return null;
    const job = /** @type {any} */ (row);
    return { ...job, params: job.params ? JSON.parse(job.params) : undefined, result: job.result ? JSON.parse(job.result) : null };
  }

  return {
    kinds: Object.entries(kinds).map(([id, kind]) => ({ id, title: kind.title })),
    /**
     * @param {string} kind
     * @param {{ actor: string, params?: object }} options
     */
    enqueue(kind, { actor, params = {} }) {
      if (!Object.hasOwn(kinds, kind)) throw Object.assign(new Error(`Unknown job kind "${kind}"`), { status: 400 });
      const { lastInsertRowid } = insert.run(kind, kinds[kind].title, JSON.stringify(params), actor, now().toISOString());
      const id = Number(lastInsertRowid);
      audit.record(actor, "job.queued", `job:${id}`, { kind });
      void drain();
      return parse(byId.get(id));
    },
    /** @param {number} id */
    get(id) { return parse(byId.get(id)); },
    /** @param {number} [limit] */
    list(limit = 50) { return recent.all(Math.min(Math.max(limit, 1), 200)).map(parse); },
    /** Resolves once the queue is empty. */
    idle() { return draining ?? Promise.resolve(); },
  };
}
