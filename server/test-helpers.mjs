import { createAuditLog } from "./audit.mjs";
import { createAuth } from "./auth.mjs";
import { createSettingsStore, openDatabase } from "./db.mjs";
import { createJobRunner } from "./jobs.mjs";

/** A clock tests can move. */
export function testClock(start = "2026-10-29T12:00:00.000Z") {
  let at = Date.parse(start);
  const now = () => new Date(at);
  now.advance = (ms) => { at += ms; };
  return now;
}

/**
 * Everything the app needs, in memory.
 * @param {{ adminPassword?: string | null, sessionSecret?: string | null, now?: () => Date, db?: import("node:sqlite").DatabaseSync }} [options]
 */
export function testServices({ adminPassword = "correct horse", sessionSecret = "test-secret", now = testClock(), db = openDatabase(":memory:") } = {}) {
  const settings = createSettingsStore(db, { now });
  const audit = createAuditLog(db, { now });
  const auth = createAuth({ db, settings, audit, adminPassword, sessionSecret, now });
  const jobs = createJobRunner({ db, audit, now });
  return { db, settings, audit, auth, jobs, now };
}
