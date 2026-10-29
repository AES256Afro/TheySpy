import express from "express";
import { attributions } from "./feeds.mjs";

/**
 * /api/cves, behind sign-in: the aggregated CVE list, one CVE, and updating the feeds.
 * @param {{ cves: ReturnType<typeof import("./store.mjs").createCveStore>, jobs: ReturnType<typeof import("../jobs.mjs").createJobRunner> }} deps
 */
export function cveRoutes({ cves, jobs }) {
  const router = express.Router();
  router.get("/", (req, res) => {
    const f = req.query;
    const filters = {
      kev: f.kev === "1", zeroDay: f.zeroDay === "1", minEpss: f.minEpss ? Number(f.minEpss) : undefined,
      q: f.q ? String(f.q).slice(0, 100) : undefined, product: f.product ? String(f.product).slice(0, 60) : undefined,
      severity: ["critical", "high", "medium", "low"].includes(String(f.severity)) ? String(f.severity) : undefined,
      limit: f.limit ? Number(f.limit) : 50, offset: f.offset ? Number(f.offset) : 0,
    };
    if (filters.minEpss !== undefined && !(filters.minEpss >= 0 && filters.minEpss <= 1)) return res.status(400).json({ error: "minEpss must be between 0 and 1" });
    res.json({ ...cves.list(filters), stats: cves.stats(), events: cves.recentEvents(15), attributions });
  });
  router.get("/:id", (req, res) => {
    if (!/^CVE-\d{4}-\d{4,}$/i.test(req.params.id)) return res.status(400).json({ error: "Not a CVE id" });
    const cve = cves.get(req.params.id);
    if (!cve) return res.status(404).json({ error: "Not in TheySpy's CVE list yet" });
    res.json({ cve });
  });
  router.post("/update", (_req, res) => res.status(202).json({ job: jobs.enqueue("cves.update", { actor: "owner" }) }));
  return router;
}
