import express from "express";
import { classify } from "./targeted.mjs";

/**
 * /api/fleet, behind sign-in: the device registry, discovery settings and runs.
 * @param {{
 *   fleet: ReturnType<typeof import("./registry.mjs").createFleet>,
 *   discovery: ReturnType<typeof import("./discovery.mjs").createDiscovery>,
 *   checker: ReturnType<typeof import("./targeted.mjs").createTargetedCheck>,
 *   oui: ReturnType<typeof import("./oui.mjs").createOui>,
 *   web: ReturnType<typeof import("../web/scan.mjs").createWebScanner>,
 *   deviceCves: ReturnType<typeof import("../cves/devices.mjs").createDeviceCves>,
 *   sentinel: ReturnType<typeof import("../pihole/sentinel.mjs").createSentinel>,
 *   library: ReturnType<typeof import("../blocklists/library.mjs").createBlocklistLibrary>,
 *   jobs: ReturnType<typeof import("../jobs.mjs").createJobRunner>,
 *   netalertx: ReturnType<typeof import("./netalertx.mjs").createNetAlertX>,
 * }} deps
 */
export function fleetRoutes({ fleet, discovery, checker, oui, web, deviceCves, sentinel, library, jobs, netalertx }) {
  const router = express.Router();

  // NetAlertX, both ways (netalertx.mjs): connect, sync now, preview and fill empty fields there.
  router.get("/netalertx", (_req, res) => res.json(netalertx.config()));
  router.put("/netalertx", (req, res) => res.json(netalertx.configure(req.body ?? {}, "owner")));
  router.post("/netalertx/test", async (_req, res) => res.json(await netalertx.test()));
  router.post("/netalertx/sync", async (_req, res) => res.json(await netalertx.pull("owner")));
  router.get("/netalertx/preview", async (_req, res) => res.json(await netalertx.preview()));
  router.post("/netalertx/push", async (_req, res) => res.json(await netalertx.push("owner")));
  const id = (req) => Number(req.params.id);

  router.get("/", (_req, res) => {
    const devices = fleet.list();
    res.json({
      devices,
      counts: { total: devices.length, online: devices.filter((d) => d.online).length, isNew: devices.filter((d) => d.isNew).length, untrusted: devices.filter((d) => !d.trusted).length, randomised: devices.filter((d) => d.randomisedMac).length, piholeUntrusted: devices.filter((d) => d.inPihole && !d.trusted).length },
      targets: discovery.targets(), suggestions: discovery.suggestions(), scanRanges: discovery.scanRanges(),
      lastSync: discovery.lastSync(), lastSweep: discovery.lastSweep(), events: fleet.recentEvents(20), vendors: oui.status(),
    });
  });
  // Address → best name, so every screen can say who an address is.
  router.get("/names", (_req, res) => res.json({ names: fleet.namesByIp() }));

  // What a device has been doing, from Pi-hole: how much it looks up, its top sites, and what was
  // blocked and by which of TheySpy's lists.
  router.get("/devices/:id/activity", async (req, res) => {
    const device = fleet.get(id(req));
    if (!device) return res.status(404).json({ error: "No such device" });
    if (!device.ip || !sentinel.effective().mode) return res.json({ connected: Boolean(sentinel.effective().mode), total: 0, top: [], blocked: [] });
    const until = Date.now() / 1000;
    const { rows } = await sentinel.source().domainCounts({ client: device.ip, from: until - 86400, until });
    const total = rows.reduce((n, r) => n + r.queries, 0);
    const blockedRows = rows.filter((r) => r.blocked > 0).sort((a, b) => b.blocked - a.blocked).slice(0, 15);
    const matches = library.matchNames(blockedRows.map((r) => r.domain));
    res.json({
      connected: true, total, blockedTotal: rows.reduce((n, r) => n + r.blocked, 0),
      top: rows.filter((r) => r.queries > r.blocked).sort((a, b) => b.queries - a.queries).slice(0, 12).map((r) => ({ domain: r.domain, queries: r.queries })),
      blocked: blockedRows.map((r) => ({ domain: r.domain, blocked: r.blocked, lists: [...(matches.get(r.domain)?.lists ?? [])].slice(0, 3) })),
    });
  });
  router.get("/devices/:id", (req, res) => {
    const device = fleet.get(id(req));
    if (!device) return res.status(404).json({ error: "No such device" });
    res.json({ device });
  });
  router.put("/devices/:id", (req, res) => res.json({ device: fleet.edit(id(req), req.body ?? {}, "owner") }));
  router.delete("/devices/:id", (req, res) => { fleet.forget(id(req), "owner"); res.json({ forgotten: true }); });
  router.post("/trust-pihole-clients", (_req, res) => res.json({ trusted: fleet.trustPiholeClients("owner") }));
  router.put("/targets", (req, res) => res.json({ targets: discovery.setTargets(req.body?.targets, "owner") }));
  router.post("/vendors", (_req, res) => res.status(202).json({ job: jobs.enqueue("fleet.oui", { actor: "owner" }) }));
  router.post("/sync", (_req, res) => res.status(202).json({ job: jobs.enqueue("fleet.sync", { actor: "owner" }) }));
  router.post("/sweep", (req, res) => {
    // A one-off sweep of other networks is checked here, before it is queued.
    const targets = Array.isArray(req.body?.targets) ? req.body.targets.map((t) => discovery.checkTarget(String(t))) : undefined;
    if (!targets && !discovery.targets().length) return res.status(400).json({ error: "Choose the networks to sweep first" });
    res.status(202).json({ job: jobs.enqueue("fleet.sweep", { actor: "owner", params: targets ? { targets } : {} }) });
  });

  // --- targeted check ------------------------------------------------------------------------------
  router.get("/checks", (_req, res) => res.json({ checks: checker.recent(), profiles: checker.profiles(), scanRanges: discovery.scanRanges() }));
  router.get("/checks/:id", (req, res) => {
    const check = checker.get(id(req));
    if (!check) return res.status(404).json({ error: "No such check" });
    res.json({ check });
  });
  router.post("/check", (req, res) => {
    const query = String(req.body?.query ?? "");
    const profile = String(req.body?.profile ?? "standard");
    const { kind } = classify(query); // a 400 now rather than a failed job
    if (kind !== "website" && !["quick", "standard", "deep", "dns"].includes(profile)) return res.status(400).json({ error: "profile must be quick, standard, deep or dns" });
    res.status(202).json({ job: jobs.enqueue("fleet.check", { actor: "owner", params: { query, profile } }) });
  });
  // The token a public site's owner publishes so TheySpy may check it.
  router.get("/web/verification", (req, res) => {
    const host = String(req.query.host ?? "").trim().toLowerCase();
    if (!/^[a-z0-9.-]{1,253}$/.test(host)) return res.status(400).json({ error: "host must be a hostname" });
    const token = web.tokenFor(host);
    res.json({ host, token, file: `https://${host}/.well-known/theyspy-verification.txt`, txt: `theyspy-verification=${token}` });
  });
  // M6: the CVEs that apply to a device's software, and the owner's decisions about them.
  router.get("/devices/:id/cves", async (req, res) => res.json(await deviceCves.forDevice(id(req))));
  router.put("/devices/:id/cves/:cve", (req, res) => {
    const status = req.body?.status ?? null;
    deviceCves.decide(id(req), String(req.params.cve).toUpperCase(), status, req.body?.note ?? null, "owner");
    res.json({ ok: true });
  });
  router.get("/devices/:id/services", (req, res) => res.json({ services: checker.servicesOf(id(req)) }));
  return router;
}
