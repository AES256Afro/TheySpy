import express from "express";
import { citation, exportFormats, renderExport, sources, tierDescriptions } from "./exports.mjs";
import { defang } from "./parse.mjs";
import { tracks } from "./updater.mjs";

const defangOne = (ind) => ({ value: defang(ind.value), type: ind.type, tier: ind.tier, confidence: ind.confidence, source: ind.source });

/** Indicators in a version's diff, defanged: the browser never receives a fetchable indicator. */
function defangDiff(diff) {
  if (!diff) return null;
  return {
    added: diff.added.map(defangOne),
    removed: diff.removed.map(defangOne),
    changed: diff.changed.map((c) => ({ ...c, value: defang(c.value) })),
    asof: diff.asof,
  };
}

const summary = (version) => version && { ...version, diff: undefined, ...(version.diff ? { changes: { added: version.diff.added.length, removed: version.diff.removed.length, changed: version.diff.changed.length } } : {}) };

/**
 * /api/iocs: the active set, updates waiting for review, history and exports. Mounted behind sign-in.
 * @param {{
 *   store: ReturnType<typeof import("./store.mjs").createIocStore>,
 *   jobs: ReturnType<typeof import("../jobs.mjs").createJobRunner>,
 *   settings: ReturnType<typeof import("../db.mjs").createSettingsStore>,
 *   audit: ReturnType<typeof import("../audit.mjs").createAuditLog>,
 * }} deps
 */
export function iocRoutes({ store, jobs, settings, audit }) {
  const router = express.Router();

  router.get("/", (_req, res) => {
    const set = store.activeSet();
    const counts = { total: 0, byType: {}, byTier: {} };
    for (const ind of set?.indicators ?? []) {
      counts.total += 1;
      counts.byType[ind.type] = (counts.byType[ind.type] ?? 0) + 1;
      counts.byTier[ind.tier] = (counts.byTier[ind.tier] ?? 0) + 1;
    }
    res.json({
      active: summary(store.active()),
      pending: summary(store.pending()),
      counts,
      track: settings.get("ioc_track") ?? "release",
      tracks,
      lastCheck: settings.get("ioc_last_check") ?? null,
      tiers: tierDescriptions,
      sources: Object.fromEntries(Object.entries(sources).map(([key, [publisher, title, date, url]]) => [key, { publisher, title, date, url }])),
      exports: Object.entries(exportFormats).map(([id, f]) => ({ id, file: f.file, label: f.label })),
    });
  });

  router.get("/indicators", (_req, res) => {
    const set = store.activeSet();
    res.json({ indicators: (set?.indicators ?? []).map((ind) => ({ ...defangOne(ind), citation: citation(ind.source) })) });
  });

  router.get("/versions", (_req, res) => res.json({ versions: store.history().map(summary) }));
  router.get("/versions/:id", (req, res) => {
    const version = store.get(Number(req.params.id));
    if (!version) return res.status(404).json({ error: "No such version" });
    res.json({ version: { ...version, diff: defangDiff(version.diff) } });
  });

  router.post("/check", (_req, res) => res.status(202).json({ job: jobs.enqueue("ioc.check", { actor: "owner" }) }));

  router.post("/versions/:id/apply", (req, res) => {
    const version = store.get(Number(req.params.id));
    if (!version || version.status !== "pending") return res.status(409).json({ error: "Only a pending update can be applied" });
    res.status(202).json({ job: jobs.enqueue("ioc.apply", { actor: "owner", params: { versionId: version.id } }) });
  });

  router.post("/versions/:id/reject", (req, res) => res.json({ version: summary(store.reject(Number(req.params.id), "owner")) }));

  router.put("/settings", (req, res) => {
    const track = req.body?.track;
    if (!tracks.includes(track)) return res.status(400).json({ error: `track must be one of ${tracks.join(", ")}` });
    settings.set("ioc_track", track);
    audit.record("owner", "iocs.track_changed", null, { track });
    res.json({ track });
  });

  router.get("/export/:format", (req, res) => {
    const format = req.params.format;
    const entry = exportFormats[format];
    const set = store.activeSet();
    if (!entry) return res.status(404).json({ error: "Unknown export format" });
    if (!set) return res.status(409).json({ error: "No indicator set is active yet" });
    res.set({ "Content-Type": `${entry.type}; charset=utf-8`, "Content-Disposition": `attachment; filename="${entry.file}"` });
    res.send(renderExport(/** @type {keyof typeof exportFormats} */ (format), set));
  });

  return router;
}
