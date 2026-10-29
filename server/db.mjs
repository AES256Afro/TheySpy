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
  // M1: indicator sets. Every version ever fetched is kept with its raw text and provenance, so
  // what was applied, and why it was trusted, can be shown later. `iocs` is the active set.
  `CREATE TABLE ioc_versions (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     feed TEXT NOT NULL,
     status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'superseded', 'rejected')),
     sha256 TEXT NOT NULL,
     asof TEXT,
     count INTEGER NOT NULL,
     raw TEXT NOT NULL,
     provenance TEXT NOT NULL,
     diff TEXT,
     fetched_at TEXT NOT NULL,
     decided_at TEXT,
     decided_by TEXT
   );
   CREATE INDEX ioc_versions_feed ON ioc_versions (feed, status);
   CREATE TABLE iocs (
     value TEXT NOT NULL,
     feed TEXT NOT NULL,
     type TEXT NOT NULL CHECK (type IN ('domain', 'ip', 'sha256')),
     tier TEXT NOT NULL,
     confidence TEXT NOT NULL,
     source TEXT NOT NULL,
     version_id INTEGER NOT NULL REFERENCES ioc_versions (id),
     PRIMARY KEY (feed, value)
   );
   CREATE INDEX iocs_value ON iocs (value);`,
  // M2: Pi-hole. One row per DNS query that matched an indicator (the query's own id and time make
  // it unique, so overlapping hunts never double-count), each hunt, and each denylist push with
  // exactly what it added, so a rollback removes only that.
  `CREATE TABLE ioc_hit_events (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     source TEXT NOT NULL,
     query_id INTEGER NOT NULL,
     at TEXT NOT NULL,
     indicator TEXT NOT NULL,
     domain TEXT NOT NULL,
     via TEXT NOT NULL CHECK (via IN ('query', 'cname')),
     client_ip TEXT NOT NULL,
     client_name TEXT,
     status TEXT NOT NULL,
     blocked INTEGER NOT NULL,
     found_by TEXT NOT NULL,
     found_at TEXT NOT NULL,
     UNIQUE (source, query_id, at, indicator)
   );
   CREATE INDEX ioc_hit_events_indicator ON ioc_hit_events (indicator, client_ip);
   CREATE TABLE pihole_hunts (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     mode TEXT NOT NULL,
     from_at TEXT NOT NULL,
     until_at TEXT NOT NULL,
     indicators INTEGER NOT NULL,
     queries_seen INTEGER NOT NULL,
     new_hits INTEGER NOT NULL,
     finished_at TEXT NOT NULL
   );
   CREATE TABLE pihole_pushes (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     status TEXT NOT NULL CHECK (status IN ('active', 'rolled_back')),
     entries TEXT NOT NULL,
     pushed_at TEXT NOT NULL,
     pushed_by TEXT NOT NULL,
     rolled_back_at TEXT,
     rolled_back_by TEXT
   );`,
  // M3: the blocklist library. Every list TheySpy knows of (found in a directory, added by the
  // owner, or built in), and each fetched version with its domains as one gzip blob, kept so a
  // change can be diffed, held for review, or rolled back to.
  `CREATE TABLE blocklist_sources (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     key TEXT NOT NULL UNIQUE,
     directory TEXT NOT NULL,
     name TEXT NOT NULL,
     description TEXT,
     url TEXT,
     homepage TEXT,
     license TEXT,
     syntax TEXT,
     categories TEXT NOT NULL,
     curated INTEGER NOT NULL DEFAULT 0,
     status TEXT NOT NULL CHECK (status IN ('candidate', 'enabled', 'disabled')),
     deprecated INTEGER NOT NULL DEFAULT 0,
     discovered_at TEXT NOT NULL,
     etag TEXT,
     last_modified TEXT,
     last_checked_at TEXT,
     last_changed_at TEXT,
     failures INTEGER NOT NULL DEFAULT 0,
     last_error TEXT,
     active_version_id INTEGER
   );
   CREATE INDEX blocklist_sources_status ON blocklist_sources (status);
   CREATE TABLE blocklist_versions (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     source_id INTEGER NOT NULL REFERENCES blocklist_sources (id),
     status TEXT NOT NULL CHECK (status IN ('active', 'superseded', 'quarantined', 'rejected')),
     sha256 TEXT NOT NULL,
     count INTEGER NOT NULL,
     added INTEGER NOT NULL,
     removed INTEGER NOT NULL,
     sample TEXT NOT NULL,
     reasons TEXT NOT NULL,
     domains BLOB NOT NULL,
     fetched_at TEXT NOT NULL,
     decided_at TEXT,
     decided_by TEXT
   );
   CREATE INDEX blocklist_versions_source ON blocklist_versions (source_id, status);`,
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
