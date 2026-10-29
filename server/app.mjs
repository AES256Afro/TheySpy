import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { appearanceOptions, effectiveAppearance, validateAppearance } from "./appearance.mjs";
import { sessionCookie } from "./auth.mjs";
import { iocRoutes } from "./iocs/routes.mjs";
import { piholeRoutes } from "./pihole/routes.mjs";
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
 *   staticDirectory?: string,
 * }} deps
 */
export function createApp({ config, settings, audit, auth, jobs, iocStore, sentinel, staticDirectory = distDirectory }) {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", "loopback");

  app.use((_req, res, next) => {
    // Nothing third-party: fonts are bundled, and the app makes no outbound requests from the browser.
    res.set({
      "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    });
    next();
  });
  app.use(express.json({ limit: "64kb" }));

  const health = (_req, res) => res.json({ ok: true, version: productVersion });
  app.get("/healthz", health);
  app.get("/api/v1/health", health);

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

  app.get("/api/audit", requireOwner, (req, res) => res.json({ entries: audit.list(Number(req.query.limit ?? 100)) }));

  app.use("/api", (_req, res) => res.status(404).json({ error: "Not found" }));

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
