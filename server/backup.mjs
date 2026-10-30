import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

// Backups (docs/PLAN.md M10). BoxPilot backs TheySpy up by stopping it and archiving /data, which
// is consistent because a clean stop closes the database. This is the other way: a copy taken while
// TheySpy runs, with SQLite's VACUUM INTO (one file, no WAL), checked before it is handed over.

/** What a restore must bring back, counted. @param {DatabaseSync} db */
export function contentsOf(db) {
  const count = (table) => Number(/** @type {any} */ (db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get()).n);
  return {
    schema: Number(/** @type {any} */ (db.prepare("PRAGMA user_version").get()).user_version),
    devices: count("devices"), findings: count("findings"), agents: count("agents"), settings: count("settings"),
    indicators: count("iocs"), blocklists: count("blocklist_sources"), audit: count("audit_log"),
  };
}

/**
 * @param {{ db: DatabaseSync, audit: ReturnType<typeof import("./audit.mjs").createAuditLog>, now?: () => Date }} deps
 */
export function createBackup({ db, audit, now = () => new Date() }) {
  return {
    /**
     * Writes a consistent copy to a new temporary file and checks it opens, passes SQLite's
     * integrity check and holds what the live database holds. The caller removes `dir` after use.
     */
    snapshot() {
      const dir = mkdtempSync(path.join(os.tmpdir(), "theyspy-backup-"));
      const file = path.join(dir, `theyspy-${now().toISOString().slice(0, 10)}.db`);
      try {
        db.prepare("VACUUM INTO ?").run(file);
        const copy = new DatabaseSync(file, { readOnly: true });
        try {
          const integrity = /** @type {any} */ (copy.prepare("PRAGMA integrity_check").get()).integrity_check;
          if (integrity !== "ok") throw new Error(`the copy failed SQLite's integrity check: ${integrity}`);
          const contents = contentsOf(copy);
          audit.record("owner", "backup.downloaded", null, contents);
          return { dir, file, contents };
        } finally {
          copy.close();
        }
      } catch (error) {
        rmSync(dir, { recursive: true, force: true });
        throw error;
      }
    },
  };
}
