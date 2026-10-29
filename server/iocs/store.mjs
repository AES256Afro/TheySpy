import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { IocError, parseIocText } from "./parse.mjs";
import { parseChecksums, readPublicKey, verifyDetached } from "./openpgp.mjs";

export const feed = "zero-breach";
const vendored = (path) => readFileSync(new URL(`../../third_party/zero-breach/${path}`, import.meta.url));
export const sha256 = (data) => createHash("sha256").update(data).digest("hex");

/**
 * The difference between two sets: added and removed values, and values whose tier, confidence or
 * source changed (that changes what a hit means even though the value did not move).
 * @param {import("./parse.mjs").IocSet | null} before
 * @param {import("./parse.mjs").IocSet} after
 */
export function diffSets(before, after) {
  const old = new Map((before?.indicators ?? []).map((ind) => [ind.value, ind]));
  const now = new Map(after.indicators.map((ind) => [ind.value, ind]));
  const added = [...now.values()].filter((ind) => !old.has(ind.value));
  const removed = [...old.values()].filter((ind) => !now.has(ind.value));
  const changed = [];
  for (const [value, ind] of now) {
    const was = old.get(value);
    if (!was) continue;
    const fields = ["tier", "confidence", "source"].filter((field) => was[field] !== ind[field]).map((field) => ({ field, from: was[field], to: ind[field] }));
    if (fields.length) changed.push({ value, type: ind.type, fields });
  }
  return { added, removed, changed, asof: { from: before?.asof ?? null, to: after.asof } };
}

/**
 * Indicator versions and the active set, in SQLite. The first start seeds the bundled copy of
 * zero-breach's set, after checking it against the signed v0.1.8 manifest that ships beside it.
 * @param {{ db: import("node:sqlite").DatabaseSync, audit: ReturnType<typeof import("../audit.mjs").createAuditLog>, now?: () => Date }} options
 */
export function createIocStore({ db, audit, now = () => new Date() }) {
  const insertVersion = db.prepare("INSERT INTO ioc_versions (feed, status, sha256, asof, count, raw, provenance, diff, fetched_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
  const versionById = db.prepare("SELECT * FROM ioc_versions WHERE id = ?");
  const activeVersion = db.prepare("SELECT * FROM ioc_versions WHERE feed = ? AND status = 'active'");
  const pendingVersions = db.prepare("SELECT id FROM ioc_versions WHERE feed = ? AND status = 'pending'");
  const setStatus = db.prepare("UPDATE ioc_versions SET status = ?, decided_at = ?, decided_by = ? WHERE id = ?");
  const versions = db.prepare("SELECT id, status, sha256, asof, count, provenance, fetched_at, decided_at, decided_by FROM ioc_versions WHERE feed = ? ORDER BY id DESC LIMIT 50");
  const deleteIocs = db.prepare("DELETE FROM iocs WHERE feed = ?");
  const insertIoc = db.prepare("INSERT INTO iocs (value, feed, type, tier, confidence, source, version_id) VALUES (?, ?, ?, ?, ?, ?, ?)");
  const allIocs = db.prepare("SELECT value, type, tier, confidence, source FROM iocs WHERE feed = ? ORDER BY value");

  const summarise = (row) => row && {
    id: Number(row.id), status: row.status, sha256: row.sha256, asof: row.asof, count: Number(row.count),
    provenance: JSON.parse(row.provenance), fetchedAt: row.fetched_at, decidedAt: row.decided_at ?? null, decidedBy: row.decided_by ?? null,
    ...(row.diff ? { diff: JSON.parse(row.diff) } : {}),
  };

  function transaction(work) {
    db.exec("BEGIN IMMEDIATE");
    try {
      const result = work();
      db.exec("COMMIT");
      return result;
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
    }
  }

  function activate(id, actor) {
    const row = /** @type {any} */ (versionById.get(id));
    // Parse again from the stored bytes: what becomes active is exactly what was checked.
    if (sha256(Buffer.from(row.raw, "utf8")) !== row.sha256) throw new IocError(`version ${id} no longer matches its recorded hash`);
    const set = parseIocText(row.raw);
    transaction(() => {
      const current = /** @type {any} */ (activeVersion.get(row.feed));
      if (current) setStatus.run("superseded", now().toISOString(), actor, current.id);
      setStatus.run("active", now().toISOString(), actor, id);
      deleteIocs.run(row.feed);
      for (const ind of set.indicators) insertIoc.run(ind.value, row.feed, ind.type, ind.tier, ind.confidence, ind.source, id);
    });
    return set;
  }

  const store = {
    /** The active set as parsed indicators (what exports and matching use). */
    activeSet() {
      const row = /** @type {any} */ (activeVersion.get(feed));
      if (!row) return null;
      return { asof: row.asof, indicators: allIocs.all(feed).map((r) => ({ .../** @type {any} */ (r) })) };
    },
    active: () => summarise(activeVersion.get(feed)),
    pending: () => {
      const row = pendingVersions.get(feed);
      return row ? summarise(versionById.get(Number(/** @type {any} */ (row).id))) : null;
    },
    get: (id) => summarise(versionById.get(id)),
    history: () => versions.all(feed).map(summarise),

    /** Seeds the bundled set once, on a database that has never had one. */
    seedBundled() {
      if (activeVersion.get(feed)) return null;
      const raw = vendored("iocs/adfection_iocs.txt");
      const digest = sha256(raw);
      const published = vendored("iocs/adfection_iocs.txt.sha256").toString("utf8").split(/\s+/)[0].toLowerCase();
      const key = readPublicKey(vendored("release-signatures/v0.1.8/archivegenocide-signing-key.asc").toString("utf8"));
      const manifest = vendored("release-signatures/v0.1.8/SHA256SUMS.txt");
      const signed = verifyDetached(manifest, vendored("release-signatures/v0.1.8/SHA256SUMS.txt.asc").toString("utf8"), key);
      if (digest !== published || parseChecksums(manifest.toString("utf8")).get("adfection_iocs.txt") !== digest) {
        throw new IocError("the bundled indicator file does not match its published or signed hash");
      }
      const set = parseIocText(raw.toString("utf8"));
      const provenance = { track: "bundled", release: "v0.1.8", signedBy: key.fingerprint, signedAt: signed.signedAt.toISOString(), note: "Shipped with TheySpy; checked against zero-breach's signed v0.1.8 manifest." };
      const id = Number(insertVersion.run(feed, "pending", digest, set.asof, set.indicators.length, raw.toString("utf8"), JSON.stringify(provenance), null, now().toISOString()).lastInsertRowid);
      activate(id, "system");
      audit.record("system", "iocs.seeded", `ioc-version:${id}`, { count: set.indicators.length, asof: set.asof, sha256: digest });
      return id;
    },

    /**
     * Records a fetched set as the one pending candidate (replacing any older pending one).
     * Returns null when it is byte-identical to the active set.
     * @param {{ raw: string, provenance: object, actor: string }} candidate
     */
    recordCandidate({ raw, provenance, actor }) {
      const digest = sha256(Buffer.from(raw, "utf8"));
      const current = /** @type {any} */ (activeVersion.get(feed));
      if (current?.sha256 === digest) return null;
      const set = parseIocText(raw);
      const diff = diffSets(store.activeSet(), set);
      return transaction(() => {
        for (const row of pendingVersions.all(feed)) setStatus.run("superseded", now().toISOString(), actor, Number(/** @type {any} */ (row).id));
        const id = Number(insertVersion.run(feed, "pending", digest, set.asof, set.indicators.length, raw, JSON.stringify(provenance), JSON.stringify(diff), now().toISOString()).lastInsertRowid);
        audit.record(actor, "iocs.update_found", `ioc-version:${id}`, { added: diff.added.length, removed: diff.removed.length, changed: diff.changed.length, sha256: digest });
        return store.get(id);
      });
    },

    /** Makes a pending version the active set. */
    apply(id, actor) {
      const row = summarise(versionById.get(id));
      if (!row || row.status !== "pending") throw Object.assign(new Error("Only a pending update can be applied"), { status: 409 });
      const set = activate(id, actor);
      audit.record(actor, "iocs.applied", `ioc-version:${id}`, { count: set.indicators.length, asof: set.asof, sha256: row.sha256 });
      return store.get(id);
    },

    reject(id, actor) {
      const row = summarise(versionById.get(id));
      if (!row || row.status !== "pending") throw Object.assign(new Error("Only a pending update can be rejected"), { status: 409 });
      setStatus.run("rejected", now().toISOString(), actor, id);
      audit.record(actor, "iocs.rejected", `ioc-version:${id}`);
      return store.get(id);
    },
  };
  return store;
}
