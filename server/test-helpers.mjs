import { readFileSync } from "node:fs";
import { createAuditLog } from "./audit.mjs";
import { createAuth } from "./auth.mjs";
import { createSettingsStore, openDatabase } from "./db.mjs";
import { createIocStore } from "./iocs/store.mjs";
import { createIocUpdater, iocJobKinds } from "./iocs/updater.mjs";
import { createJobRunner, jobKinds } from "./jobs.mjs";

/** A clock tests can move. */
export function testClock(start = "2026-10-29T12:00:00.000Z") {
  let at = Date.parse(start);
  const now = () => new Date(at);
  now.advance = (ms) => { at += ms; };
  return now;
}

/** Bytes of a vendored zero-breach file. */
export const vendored = (path) => readFileSync(new URL(`../third_party/zero-breach/${path}`, import.meta.url));

/**
 * A stand-in for GitHub: serves the vendored v0.1.8 release by default; `files` overrides or adds
 * paths (a value of null answers 404).
 * @param {Record<string, string | Buffer | null>} [files]
 */
export function fakeGitHub(files = {}) {
  const release = "release-signatures/v0.1.8/";
  const base = {
    "https://api.github.com/repos/interplains/zero-breach/releases/latest": JSON.stringify({ tag_name: "v0.1.8" }),
    [`https://raw.githubusercontent.com/interplains/zero-breach/main/${release}SHA256SUMS.txt`]: vendored(`${release}SHA256SUMS.txt`),
    [`https://raw.githubusercontent.com/interplains/zero-breach/main/${release}SHA256SUMS.txt.asc`]: vendored(`${release}SHA256SUMS.txt.asc`),
    "https://raw.githubusercontent.com/interplains/zero-breach/v0.1.8/iocs/adfection_iocs.txt": vendored("iocs/adfection_iocs.txt"),
    "https://raw.githubusercontent.com/interplains/zero-breach/main/iocs/adfection_iocs.txt": vendored("iocs/adfection_iocs.txt"),
    "https://raw.githubusercontent.com/interplains/zero-breach/main/iocs/adfection_iocs.txt.sha256": vendored("iocs/adfection_iocs.txt.sha256"),
  };
  const table = { ...base, ...files };
  const requested = [];
  /** @type {typeof fetch & { requested: string[] }} */
  const fetchImpl = Object.assign(async (url) => {
    requested.push(String(url));
    const body = table[String(url)];
    if (body === undefined || body === null) return new Response("not found", { status: 404 });
    return new Response(body, { status: 200 });
  }, { requested });
  return fetchImpl;
}

/**
 * Everything the app needs, in memory, with the bundled indicator set seeded.
 * @param {{ adminPassword?: string | null, sessionSecret?: string | null, now?: () => Date, db?: import("node:sqlite").DatabaseSync, fetchImpl?: typeof fetch }} [options]
 */
export function testServices({ adminPassword = "correct horse", sessionSecret = "test-secret", now = testClock(), db = openDatabase(":memory:"), fetchImpl = fakeGitHub() } = {}) {
  const settings = createSettingsStore(db, { now });
  const audit = createAuditLog(db, { now });
  const auth = createAuth({ db, settings, audit, adminPassword, sessionSecret, now });
  const iocStore = createIocStore({ db, audit, now });
  iocStore.seedBundled();
  const updater = createIocUpdater({ fetchImpl });
  const jobs = createJobRunner({ db, audit, now, kinds: { ...jobKinds, ...iocJobKinds({ store: iocStore, updater, settings, now }) } });
  return { db, settings, audit, auth, jobs, iocStore, updater, now };
}
