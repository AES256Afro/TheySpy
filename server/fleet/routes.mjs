import express from "express";

/**
 * /api/fleet, behind sign-in: the device registry, discovery settings and runs.
 * @param {{
 *   fleet: ReturnType<typeof import("./registry.mjs").createFleet>,
 *   discovery: ReturnType<typeof import("./discovery.mjs").createDiscovery>,
 *   jobs: ReturnType<typeof import("../jobs.mjs").createJobRunner>,
 * }} deps
 */
export function fleetRoutes({ fleet, discovery, jobs }) {
  const router = express.Router();
  const id = (req) => Number(req.params.id);

  router.get("/", (_req, res) => {
    const devices = fleet.list();
    res.json({
      devices,
      counts: { total: devices.length, online: devices.filter((d) => d.online).length, isNew: devices.filter((d) => d.isNew).length, untrusted: devices.filter((d) => !d.trusted).length, randomised: devices.filter((d) => d.randomisedMac).length },
      targets: discovery.targets(), suggestions: discovery.suggestions(), scanRanges: discovery.scanRanges(),
      lastSync: discovery.lastSync(), lastSweep: discovery.lastSweep(), events: fleet.recentEvents(20),
    });
  });
  router.get("/devices/:id", (req, res) => {
    const device = fleet.get(id(req));
    if (!device) return res.status(404).json({ error: "No such device" });
    res.json({ device });
  });
  router.put("/devices/:id", (req, res) => res.json({ device: fleet.edit(id(req), req.body ?? {}, "owner") }));
  router.delete("/devices/:id", (req, res) => { fleet.forget(id(req), "owner"); res.json({ forgotten: true }); });
  router.put("/targets", (req, res) => res.json({ targets: discovery.setTargets(req.body?.targets, "owner") }));
  router.post("/sync", (_req, res) => res.status(202).json({ job: jobs.enqueue("fleet.sync", { actor: "owner" }) }));
  router.post("/sweep", (req, res) => {
    // A one-off sweep of other networks is checked here, before it is queued.
    const targets = Array.isArray(req.body?.targets) ? req.body.targets.map((t) => discovery.checkTarget(String(t))) : undefined;
    if (!targets && !discovery.targets().length) return res.status(400).json({ error: "Choose the networks to sweep first" });
    res.status(202).json({ job: jobs.enqueue("fleet.sweep", { actor: "owner", params: targets ? { targets } : {} }) });
  });
  return router;
}
