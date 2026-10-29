import express from "express";
import { citation } from "../iocs/exports.mjs";
import { defang } from "../iocs/parse.mjs";

/**
 * /api/pihole, behind sign-in. Indicators leave the server defanged; client addresses and names
 * are the owner's own network, shown as they are.
 * @param {{
 *   sentinel: ReturnType<typeof import("./sentinel.mjs").createSentinel>,
 *   jobs: ReturnType<typeof import("../jobs.mjs").createJobRunner>,
 *   settings: ReturnType<typeof import("../db.mjs").createSettingsStore>,
 * }} deps
 */
export function piholeRoutes({ sentinel, jobs, settings }) {
  const router = express.Router();

  router.get("/", (_req, res) => {
    const coverage = sentinel.lastCoverage();
    const preview = sentinel.pushPreview();
    res.json({
      config: sentinel.publicConfig(),
      lastTest: settings.get("pihole_last_test") ?? null,
      lastHunt: sentinel.lastHunt(),
      watch: sentinel.watch.status(),
      coverage: coverage && {
        at: coverage.at, stale: Boolean(coverage.stale), asof: coverage.asof, total: coverage.total, blocked: coverage.blocked, fullyBlocked: coverage.fullyBlocked, allowlisted: coverage.allowlisted,
        notFullyBlocked: coverage.results.filter((r) => !(r.blocked && r.subdomainsBlocked)).map((r) => ({ domain: defang(r.domain), blocked: r.blocked, subdomainsBlocked: r.subdomainsBlocked, allowlisted: r.allowlisted, by: r.by })),
      },
      // The real names travel only as an opaque list the push endpoint checks against the indicator set.
      preview: preview && { checkedAt: preview.checkedAt, count: preview.domains.length, domains: preview.domains.map(defang), skippedAllowlisted: preview.skippedAllowlisted.map(defang), token: Buffer.from(JSON.stringify(preview.domains)).toString("base64url") },
      pushes: sentinel.pushes(),
    });
  });

  router.get("/hits", (_req, res) => {
    res.json({ hits: sentinel.hits().map((h) => ({ ...h, indicator: defang(h.indicator), domain: defang(h.domain), citation: h.source ? citation(h.source) : null })) });
  });

  router.put("/settings", (req, res) => res.json({ config: sentinel.configure(req.body ?? {}, "owner") }));

  const start = (kind, params) => (_req, res) => res.status(202).json({ job: jobs.enqueue(kind, { actor: "owner", params }) });
  router.post("/test", start("pihole.test"));
  router.post("/coverage", start("pihole.coverage"));
  router.post("/hunt", (req, res) => {
    const windowDays = req.body?.windowDays === undefined ? undefined : Number(req.body.windowDays);
    if (windowDays !== undefined && !(Number.isInteger(windowDays) && windowDays >= 1 && windowDays <= 365)) return res.status(400).json({ error: "window must be 1 to 365 days" });
    res.status(202).json({ job: jobs.enqueue("pihole.hunt", { actor: "owner", params: { windowDays } }) });
  });

  // The push takes back the preview's token, so the owner approves exactly the list they were shown.
  router.post("/push", (req, res) => {
    let domains;
    try { domains = JSON.parse(Buffer.from(String(req.body?.token ?? ""), "base64url").toString("utf8")); } catch { domains = null; }
    if (!Array.isArray(domains) || !domains.length || !domains.every((d) => typeof d === "string")) return res.status(400).json({ error: "Approve a push from the current preview" });
    res.status(202).json({ job: jobs.enqueue("pihole.push", { actor: "owner", params: { domains } }) });
  });
  router.post("/pushes/:id/rollback", (req, res) => res.status(202).json({ job: jobs.enqueue("pihole.rollback", { actor: "owner", params: { pushId: Number(req.params.id) } }) }));

  return router;
}
