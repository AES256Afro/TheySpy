/**
 * The audit log: every change and every job, with who and when. Rows are never updated or deleted.
 * @param {import("node:sqlite").DatabaseSync} db
 * @param {{ now?: () => Date }} [options]
 */
export function createAuditLog(db, { now = () => new Date() } = {}) {
  const insert = db.prepare("INSERT INTO audit_log (at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)");
  const recent = db.prepare("SELECT id, at, actor, action, target, detail FROM audit_log ORDER BY id DESC LIMIT ?");
  return {
    /**
     * @param {string} actor "owner", "system", or a job id such as "job:12"
     * @param {string} action dotted verb, e.g. "job.queued", "appearance.saved"
     * @param {string | null} [target]
     * @param {unknown} [detail] stored as JSON
     */
    record(actor, action, target = null, detail = undefined) {
      insert.run(now().toISOString(), actor, action, target, detail === undefined ? null : JSON.stringify(detail));
    },
    /** @param {number} [limit] */
    list(limit = 100) {
      return recent.all(Math.min(Math.max(limit, 1), 500)).map((row) => {
        const entry = /** @type {any} */ (row);
        return { ...entry, detail: entry.detail ? JSON.parse(entry.detail) : null };
      });
    },
  };
}
