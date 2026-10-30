import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { appearanceOptions, effectiveAppearance, validateAppearance } from "./appearance.mjs";
import { sessionCookie } from "./auth.mjs";
import { iocRoutes } from "./iocs/routes.mjs";
import { piholeRoutes } from "./pihole/routes.mjs";
import { blocklistRoutes, publicListRoutes } from "./blocklists/routes.mjs";
import { fleetRoutes } from "./fleet/routes.mjs";
import { cveRoutes } from "./cves/routes.mjs";
import { adProbeUrl, dnsCheckZone, thisDeviceRoutes } from "./thisdevice.mjs";
import { integrationRoutes } from "./integrations.mjs";
import { agentPublicRoutes, evidenceRoutes } from "./agent-routes.mjs";
import { kits } from "./exposure.mjs";
import { rmSync } from "node:fs";
import { productVersion } from "./shared.mjs";

const distDirectory = fileURLToPath(new URL("../dist/", import.meta.url));

function readCookie(header, name) {
  for (const part of String(header ?? "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return undefined;
}

/**
 * The HTTP app. Kept free of listen() and process state so tests drive it directly.
 * @param {{
 *   config: ReturnType<typeof import("./config.mjs").readConfig>,
 *   settings: ReturnType<typeof import("./db.mjs").createSettingsStore>,
 *   audit: ReturnType<typeof import("./audit.mjs").createAuditLog>,
 *   auth: ReturnType<typeof import("./auth.mjs").createAuth>,
 *   jobs: ReturnType<typeof import("./jobs.mjs").createJobRunner>,
 *   iocStore: ReturnType<typeof import("./iocs/store.mjs").createIocStore>,
 *   sentinel: ReturnType<typeof import("./pihole/sentinel.mjs").createSentinel>,
 *   library: ReturnType<typeof import("./blocklists/library.mjs").createBlocklistLibrary>,
 *   baselines: ReturnType<typeof import("./blocklists/baselines.mjs").createBaselines>,
 *   fleet: ReturnType<typeof import("./fleet/registry.mjs").createFleet>,
 *   discovery: ReturnType<typeof import("./fleet/discovery.mjs").createDiscovery>,
 *   checker: ReturnType<typeof import("./fleet/targeted.mjs").createTargetedCheck>,
 *   oui: ReturnType<typeof import("./fleet/oui.mjs").createOui>,
 *   web: ReturnType<typeof import("./web/scan.mjs").createWebScanner>,
 *   software: ReturnType<typeof import("./cves/lookup.mjs").createSoftwareLookup>,
 *   deviceCves: ReturnType<typeof import("./cves/devices.mjs").createDeviceCves>,
 *   alerts: ReturnType<typeof import("./alerts.mjs").createAlerts>,
 *   digest: ReturnType<typeof import("./digest.mjs").createDigest>,
 *   read: import("./integrations.mjs").ReadModel,
 *   tokens: ReturnType<typeof import("./integrations.mjs").createApiTokens>,
 *   advisories: ReturnType<typeof import("./cves/advisories.mjs").createAdvisories>,
 *   agents: ReturnType<typeof import("./agents.mjs").createAgents>,
 *   exposure: ReturnType<typeof import("./exposure.mjs").createExposure>,
 *   cves: ReturnType<typeof import("./cves/store.mjs").createCveStore>,
 *   backup: ReturnType<typeof import("./backup.mjs").createBackup>,
 *   netalertx: ReturnType<typeof import("./fleet/netalertx.mjs").createNetAlertX>,
 *   sites: ReturnType<typeof import("./sites.mjs").createSites>,
 *   staticDirectory?: string,
 * }} deps
 */
export function createApp({ config, settings, audit, auth, jobs, iocStore, sentinel, library, baselines, fleet, discovery, checker, oui, cves, web, software, deviceCves, alerts, digest, read, tokens, advisories, agents, exposure, backup, netalertx, sites, staticDirectory = distDirectory }) {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", "loopback");

  app.use((_req, res, next) => {
    // Nothing third-party: fonts are bundled, and the app makes no outbound requests from the browser.
    res.set({
      // The two outside destinations are This device's probes: an ad-exchange script (does it load?)
      // and a one-time name under a reserved zone (does its lookup reach Pi-hole?).
      "Content-Security-Policy": `default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self' ${new URL(adProbeUrl).origin} http://*.${dnsCheckZone}; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    });
    next();
  });
  // The agent's routes take larger, signed bodies and parse them themselves (agent-routes.mjs).
  app.use(agentPublicRoutes({ agents }));
  // MVT results can be a few megabytes of JSON; that route parses them itself, after sign-in.
  const json = express.json({ limit: "64kb" });
  app.use((req, res, next) => (req.method === "POST" && /^\/api\/evidence\/devices\/\d+\/mvt$/.test(req.path) ? next() : json(req, res, next)));

  const health = (_req, res) => res.json({ ok: true, version: productVersion });
  app.get("/healthz", health);
  app.get("/api/v1/health", health);

  // Other tools read TheySpy with a bearer token: /api/v1 (JSON) and /mcp (MCP). Read-only, and
  // outside the cookie session, so the X-TheySpy CSRF rule below does not apply to them.
  const integration = integrationRoutes({ tokens, read });
  app.use("/api/v1", integration.api);
  app.use("/mcp", integration.mcp);

  // Every state-changing API call must carry this header. A cross-site form cannot set it, and
  // TheySpy never enables CORS, so it closes CSRF together with the SameSite=Strict cookie.
  app.use("/api", (req, res, next) => {
    if (req.method === "GET" || req.method === "HEAD") return next();
    if (req.get("x-theyspy") !== "1") return res.status(403).json({ error: "Missing X-TheySpy header" });
    next();
  });

  const signedIn = (req) => auth.verify(readCookie(req.headers.cookie, sessionCookie));
  const requireOwner = (req, res, next) => (signedIn(req) ? next() : res.status(401).json({ error: "Sign in first" }));

  const cookie = (value, maxAgeSeconds) =>
    `${sessionCookie}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSeconds}${config.cookieSecure ? "; Secure" : ""}`;

  app.get("/api/session", (req, res) => res.json({ signedIn: signedIn(req), version: productVersion }));

  app.post("/api/login", (req, res) => {
    const result = auth.login(req.body?.password, { ip: req.ip ?? "unknown", userAgent: req.get("user-agent") });
    if (!result.ok) {
      if ("retryAfterSeconds" in result && result.retryAfterSeconds) {
        res.set("Retry-After", String(result.retryAfterSeconds));
        return res.status(429).json({ error: `Too many attempts. Try again in ${Math.ceil(result.retryAfterSeconds / 60)} minutes.` });
      }
      return res.status(401).json({ error: "That password is not right." });
    }
    res.set("Set-Cookie", cookie(result.token, Math.floor((result.expiresAt.getTime() - Date.now()) / 1000)));
    res.json({ signedIn: true });
  });

  app.post("/api/logout", (req, res) => {
    auth.logout(readCookie(req.headers.cookie, sessionCookie));
    res.set("Set-Cookie", cookie("", 0));
    res.json({ signedIn: false });
  });

  // Appearance is readable before sign-in so the sign-in page wears the owner's branding.
  app.get("/api/appearance", (_req, res) => {
    res.json({ appearance: effectiveAppearance({ env: config.appearance, stored: settings.get("appearance") }), options: appearanceOptions });
  });
  app.put("/api/appearance", requireOwner, (req, res) => {
    const { value, errors } = validateAppearance(req.body);
    if (errors.length) return res.status(400).json({ error: errors.join("; ") });
    const stored = { ...(settings.get("appearance") ?? {}), ...value };
    settings.set("appearance", stored);
    audit.record("owner", "appearance.saved", null, value);
    res.json({ appearance: effectiveAppearance({ env: config.appearance, stored }) });
  });
  app.delete("/api/appearance", requireOwner, (_req, res) => {
    settings.delete("appearance");
    audit.record("owner", "appearance.reset");
    res.json({ appearance: effectiveAppearance({ env: config.appearance, stored: undefined }) });
  });

  app.get("/api/jobs", requireOwner, (_req, res) => res.json({ jobs: jobs.list(), kinds: jobs.kinds }));
  app.get("/api/jobs/:id", requireOwner, (req, res) => {
    const job = jobs.get(Number(req.params.id));
    return job ? res.json({ job }) : res.status(404).json({ error: "No such job" });
  });
  app.post("/api/jobs", requireOwner, (req, res) => {
    const kind = String(req.body?.kind ?? "");
    if (!jobs.kinds.some((k) => k.id === kind && k.direct)) return res.status(400).json({ error: `"${kind}" cannot be started directly` });
    const job = jobs.enqueue(kind, { actor: "owner" });
    res.status(202).json({ job });
  });

  app.use("/api/iocs", requireOwner, iocRoutes({ store: iocStore, jobs, settings, audit }));
  app.use("/api/pihole", requireOwner, piholeRoutes({ sentinel, jobs, settings }));
  app.use("/api/blocklists", requireOwner, blocklistRoutes({ library, jobs, settings, sentinel, baselines }));
  app.use("/api/fleet", requireOwner, fleetRoutes({ fleet, discovery, checker, oui, web, deviceCves, sentinel, library, jobs, netalertx }));
  app.use("/api/cves", requireOwner, cveRoutes({ cves, jobs, advisories }));
  app.use("/api/this-device", requireOwner, thisDeviceRoutes({ fleet, sentinel, software, remember: (id, observed) => agents.observe(id, observed) }));

  app.use("/api/evidence", requireOwner, evidenceRoutes({ agents }));

  // Ad exposure: the checklist per device and for the network, the egress check, the kits.
  app.get("/api/exposure", requireOwner, (_req, res) => res.json(exposure.overview()));
  app.post("/api/exposure/egress", requireOwner, async (_req, res) => res.json(await exposure.checkEgress("owner")));
  app.get("/api/exposure/kits/:id", requireOwner, (req, res) => {
    const kit = kits[/** @type {keyof typeof kits} */ (req.params.id)];
    if (!kit) return res.status(404).json({ error: "No such kit" });
    res.type(kit.type).set("Content-Disposition", `attachment; filename="${kit.filename}"`).send(kit.body(sentinel.publicConfig().url ?? ""));
  });

  // Briefing: the digest, recent alerts, where alerts go, and API/MCP tokens.
  app.get("/api/briefing", requireOwner, (req, res) => res.json({ digest: digest.compose(Number(req.query.days ?? 7) === 1 ? 1 : 7), alerts: alerts.recent(40), ntfy: alerts.config(), tokens: tokens.list() }));
  app.put("/api/briefing/ntfy", requireOwner, (req, res) => res.json({ ntfy: alerts.configure(req.body ?? {}, "owner") }));
  app.post("/api/briefing/ntfy/test", requireOwner, async (_req, res) => res.json(await alerts.test()));
  app.post("/api/briefing/send", requireOwner, async (_req, res) => {
    const d = digest.compose(7);
    await alerts.raise({ key: `digest-now:${new Date().toISOString()}`, kind: "digest", priority: "low", title: `TheySpy briefing ${d.week}`, message: d.sections.map((s) => `${s.title}: ${s.lines.join(" ")}`).join("\n\n") });
    res.json({ sent: true });
  });
  app.post("/api/briefing/tokens", requireOwner, (req, res) => res.status(201).json(tokens.create(req.body?.name, "owner")));
  app.delete("/api/briefing/tokens/:id", requireOwner, (req, res) => { tokens.revoke(Number(req.params.id), "owner"); res.json({ revoked: true }); });

  // A copy of the database taken while running, checked before it is sent (backup.mjs).
  app.get("/api/backup", requireOwner, (_req, res) => {
    const { dir, file } = backup.snapshot();
    res.download(file, path.basename(file), () => rmSync(dir, { recursive: true, force: true }));
  });
  // Other sites, read through their read-only API (sites.mjs).
  app.get("/api/sites", requireOwner, (_req, res) => res.json({ sites: sites.overview() }));
  app.post("/api/sites", requireOwner, (req, res) => res.status(201).json(sites.add(req.body ?? {}, "owner")));
  app.delete("/api/sites/:id", requireOwner, (req, res) => { sites.remove(String(req.params.id), "owner"); res.json({ removed: true }); });
  app.post("/api/sites/refresh", requireOwner, async (_req, res) => res.json({ sites: await sites.refresh() }));
  app.get("/api/audit", requireOwner, (req, res) => res.json({ entries: audit.list(Number(req.query.limit ?? 100)) }));

  app.use("/api", (_req, res) => res.status(404).json({ error: "Not found" }));
  // Compiled blocklists for Pi-hole and other DNS filters (token in the path; no sign-in).
  app.use("/lists", publicListRoutes({ library, baselines }));

  if (existsSync(path.join(staticDirectory, "index.html"))) {
    app.use(express.static(staticDirectory, { index: false, maxAge: "1h" }));
    // Client-side routes: every other GET (or HEAD) gets the app shell.
    app.use((req, res, next) => (req.method === "GET" || req.method === "HEAD" ? res.sendFile(path.join(staticDirectory, "index.html")) : next()));
  }

  app.use((error, _req, res, _next) => {
    const status = Number(error.status ?? error.statusCode ?? 500);
    if (status >= 500) console.error(error);
    res.status(status).json({ error: status >= 500 ? "Something went wrong on the server." : error.message });
  });

  return app;
}
