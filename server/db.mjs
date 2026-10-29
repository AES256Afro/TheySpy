import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

/**
 * Schema changes, in order. Each runs once inside a transaction and bumps `PRAGMA user_version`.
 * Add new tables in the milestone that first needs them; never edit a migration that has shipped.
 */
export const migrations = [
  // M0: settings, owner sessions, the job queue and the audit log.
  `CREATE TABLE settings (
     key TEXT PRIMARY KEY,
     value TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );
   CREATE TABLE sessions (
     id TEXT PRIMARY KEY,
     created_at TEXT NOT NULL,
     last_seen_at TEXT NOT NULL,
     expires_at TEXT NOT NULL,
     user_agent TEXT
   );
   CREATE TABLE jobs (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     kind TEXT NOT NULL,
     title TEXT NOT NULL,
     params TEXT NOT NULL DEFAULT '{}',
     status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'interrupted')),
     actor TEXT NOT NULL,
     log TEXT NOT NULL DEFAULT '',
     result TEXT,
     created_at TEXT NOT NULL,
     started_at TEXT,
     finished_at TEXT
   );
   CREATE INDEX jobs_created ON jobs (created_at DESC);
   CREATE TABLE audit_log (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     at TEXT NOT NULL,
     actor TEXT NOT NULL,
     action TEXT NOT NULL,
     target TEXT,
     detail TEXT
   );
   CREATE INDEX audit_at ON audit_log (at DESC);`,
];

/**
 * Opens (or creates) the database and brings it up to the latest migration.
 * @param {string} file A path, or ":memory:" for tests.
 */
export function openDatabase(file) {
  if (file !== ":memory:") mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  migrate(db);
  return db;
}

/** @param {DatabaseSync} db */
export function migrate(db) {
  const current = Number(/** @type {any} */ (db.prepare("PRAGMA user_version").get()).user_version);
  for (let index = current; index < migrations.length; index += 1) {
    db.exec("BEGIN");
    try {
      db.exec(migrations[index]);
      db.exec(`PRAGMA user_version = ${index + 1}`);
      db.exec("COMMIT");
    } catch (error) {
      db.exec("ROLLBACK");
      throw new Error(`Migration ${index + 1} failed: ${error.message}`, { cause: error });
    }
  }
  return migrations.length;
}

/** Small typed helpers over the settings table. */
export function createSettingsStore(/** @type {DatabaseSync} */ db, { now = () => new Date() } = {}) {
  const read = db.prepare("SELECT value FROM settings WHERE key = ?");
  const write = db.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at");
  const remove = db.prepare("DELETE FROM settings WHERE key = ?");
  return {
    /** @param {string} key */
    get(key) {
      const row = /** @type {any} */ (read.get(key));
      return row ? JSON.parse(row.value) : undefined;
    },
    /** @param {string} key @param {unknown} value */
    set(key, value) { write.run(key, JSON.stringify(value), now().toISOString()); },
    /** @param {string} key */
    delete(key) { remove.run(key); },
  };
}
