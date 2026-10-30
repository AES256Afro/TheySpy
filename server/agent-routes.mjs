import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import express from "express";
import { createRateLimit } from "./ratelimit.mjs";

// The agent's side of TheySpy (no owner session): enroll with a one-time token, fetch the verified
// scanner and the indicator file, and post signed reports. Mounted before the app's JSON parser so
// a report can be larger than ordinary API calls, and so its exact bytes can be checked.

const agentScript = new URL("../agent/theyspy-agent.py", import.meta.url);

/** @param {{ agents: ReturnType<typeof import("./agents.mjs").createAgents> }} deps */
export function agentPublicRoutes({ agents }) {
  const router = express.Router();
  // Unauthenticated until the token or signature is checked, so each address gets a budget.
  const enrollLimit = createRateLimit({ limit: 10, windowMs: 10 * 60_000 }).middleware();
  const reportLimit = createRateLimit({ limit: 30, windowMs: 10 * 60_000 }).middleware();
  router.post("/api/agent/enroll", enrollLimit, express.json({ limit: "16kb" }), (req, res) => res.status(201).json(agents.enroll(req.body ?? {}, req.ip)));
  router.get("/api/agent/scanner", (_req, res) => {
    const s = agents.scanner();
    res.json({ name: "zero-breach.py", version: s.version, sha256: s.sha256, iocsSha256: createHash("sha256").update(agents.indicators(), "utf8").digest("hex") });
  });
  router.get("/api/agent/zero-breach.py", (_req, res) => res.type("text/x-python").send(agents.scanner().bytes));
  router.get("/api/agent/iocs.txt", (_req, res) => res.type("text/plain").send(Buffer.from(agents.indicators(), "utf8")));
  router.post("/api/agent/report", reportLimit, express.raw({ type: "application/json", limit: "4mb" }), (req, res) => {
    const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    const timestamp = String(req.get("x-theyspy-timestamp") ?? "");
    const agent = agents.authenticate(req.get("x-theyspy-agent"), timestamp, req.get("x-theyspy-signature"), raw);
    let report;
    try { report = JSON.parse(raw.toString("utf8")); } catch { return res.status(400).json({ error: "The report is not JSON" }); }
    res.json(agents.ingest(agent, report, timestamp, req.ip));
  });
  router.get("/agent/theyspy-agent.py", (_req, res) => res.type("text/x-python").set("Content-Disposition", 'attachment; filename="theyspy-agent.py"').send(readFileSync(agentScript)));
  return router;
}

/**
 * /api/evidence, behind sign-in: findings, agents, MVT imports and device profiles.
 * @param {{ agents: ReturnType<typeof import("./agents.mjs").createAgents> }} deps
 */
export function evidenceRoutes({ agents }) {
  const router = express.Router();
  router.get("/", (_req, res) => {
    let scanner;
    try { const s = agents.scanner(); scanner = { version: s.version, sha256: s.sha256, verified: true }; } catch (error) { scanner = { verified: false, error: error.message }; }
    res.json({ findings: agents.findings(), agents: agents.list(), scanner });
  });
  router.post("/agents/enroll", (req, res) => res.status(201).json(agents.createEnrollment(req.body?.label, "owner")));
  router.delete("/agents/:id", (req, res) => { agents.revoke(Number(req.params.id), "owner"); res.json({ revoked: true }); });
  router.put("/findings/:id", (req, res) => { agents.setFindingStatus(Number(req.params.id), String(req.body?.status ?? ""), req.body?.note ?? null, "owner"); res.json({ ok: true }); });
  router.get("/findings/:id/stix", (req, res) => res.set("Content-Disposition", `attachment; filename="theyspy-finding-${Number(req.params.id)}.stix.json"`).json(agents.stix(Number(req.params.id))));
  router.post("/devices/:id/mvt", express.json({ limit: "8mb" }), (req, res) => {
    const files = Array.isArray(req.body?.files) ? req.body.files.filter((f) => f && typeof f.name === "string" && typeof f.content === "string") : [];
    if (!files.length) return res.status(400).json({ error: "Choose MVT's *_detected.json files" });
    res.json(agents.importMvt(Number(req.params.id), files, "owner"));
  });
  router.get("/devices/:id/profile", (req, res) => res.json({ profile: agents.profile(Number(req.params.id)), inventory: agents.inventory(Number(req.params.id)) }));
  router.put("/devices/:id/profile", (req, res) => res.json({ profile: agents.setProfile(Number(req.params.id), req.body ?? {}, "owner") }));
  return router;
}
