import { createHash, randomBytes } from "node:crypto";
import express from "express";
import { createRateLimit } from "./ratelimit.mjs";
import { productVersion } from "./shared.mjs";

// Reading TheySpy from other tools (docs/PLAN.md M9): a read-only JSON API at /api/v1 and an MCP
// server at /mcp, so BoxPilot's agents (or any MCP client) can ask about devices, indicator
// lookups and exploited CVEs. Both take a bearer token the owner creates; tokens are shown once
// and stored as hashes. Nothing here changes anything.

const hash = (token) => createHash("sha256").update(token).digest("hex");

/** @param {{ db: import("node:sqlite").DatabaseSync, audit: ReturnType<typeof import("./audit.mjs").createAuditLog>, now?: () => Date }} deps */
export function createApiTokens({ db, audit, now = () => new Date() }) {
  const q = {
    add: db.prepare("INSERT INTO api_tokens (name, hash, created_at) VALUES (?, ?, ?)"),
    find: db.prepare("SELECT id, name FROM api_tokens WHERE hash = ? AND revoked_at IS NULL"),
    used: db.prepare("UPDATE api_tokens SET last_used_at = ? WHERE id = ?"),
    list: db.prepare("SELECT id, name, created_at, last_used_at, revoked_at FROM api_tokens ORDER BY id DESC"),
    revoke: db.prepare("UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL"),
  };
  return {
    /** A new token: returned once, never stored in the clear. @param {string} name @param {string} actor */
    create(name, actor) {
      const label = String(name ?? "").trim().slice(0, 60);
      if (!label) throw Object.assign(new Error("Name the token after what will use it"), { status: 400 });
      const token = `tsy_${randomBytes(24).toString("base64url")}`;
      const id = Number(q.add.run(label, hash(token), now().toISOString()).lastInsertRowid);
      audit.record(actor, "api.token_created", String(id), { name: label });
      return { id, name: label, token };
    },
    /** The token's id and name from an Authorization header, or null. */
    verify(header) {
      const m = /^Bearer\s+(tsy_[A-Za-z0-9_-]{20,})$/.exec(String(header ?? ""));
      if (!m) return null;
      const row = /** @type {any} */ (q.find.get(hash(m[1])));
      if (!row) return null;
      q.used.run(now().toISOString(), row.id);
      return { id: Number(row.id), name: row.name };
    },
    list: () => q.list.all().map((raw) => { const r = /** @type {any} */ (raw); return { id: r.id, name: r.name, createdAt: r.created_at, lastUsedAt: r.last_used_at, revoked: Boolean(r.revoked_at) }; }),
    revoke(id, actor) {
      if (!Number(q.revoke.run(now().toISOString(), id).changes)) throw Object.assign(new Error("No such token"), { status: 404 });
      audit.record(actor, "api.token_revoked", String(id));
    },
  };
}

/**
 * What both the API and MCP can read.
 * @typedef {{
 *   devices: (options?: { onlineOnly?: boolean }) => object[],
 *   indicatorLookups: (days?: number) => object[],
 *   exploitedOnDevices: () => object[],
 *   checkDomain: (domain: string) => Promise<object>,
 *   status: () => object,
 * }} ReadModel
 */

const tools = [
  { name: "list_devices", title: "List devices", description: "Every device TheySpy knows on the network: its name and where the name came from, address, MAC, vendor, network (router LAN, Tailscale, Docker), whether it is online, trusted or new.",
    inputSchema: { type: "object", properties: { online_only: { type: "boolean", description: "Only devices seen in the last 15 minutes" } } } },
  { name: "list_indicator_lookups", title: "List indicator lookups", description: "Devices that looked up spyware or ad-intelligence (ADINT) indicator domains, from Pi-hole: which device, which domain (defanged), how often, whether Pi-hole blocked it.",
    inputSchema: { type: "object", properties: { days: { type: "integer", minimum: 1, maximum: 365, description: "Look back this many days (default 30)" } } } },
  { name: "list_exploited_cves_on_devices", title: "Exploited CVEs on devices", description: "CVEs in CISA's Known Exploited Vulnerabilities catalog that affect software TheySpy found on a device, with the device, the due date and what fixes it.",
    inputSchema: { type: "object", properties: {} } },
  { name: "check_domain", title: "Check a domain", description: "Which devices looked up a domain (and its subdomains) in the last 30 days, from Pi-hole's history, and whether it is a known spyware/ADINT indicator. Nothing is sent to the domain.",
    inputSchema: { type: "object", properties: { domain: { type: "string", description: "A domain name, e.g. example.com" } }, required: ["domain"] } },
  { name: "get_status", title: "Status summary", description: "This week in plain language: indicator lookups, new devices, exploited vulnerabilities in software you run, and held blocklist updates.",
    inputSchema: { type: "object", properties: {} } },
];

/** A domain name of at least two labels; defanged dots ("[.]") are accepted. @param {unknown} value */
const isDomain = (value) => typeof value === "string" && /^(?=.{3,253}$)[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(value.replace(/\[\.\]/g, "."));

/**
 * /api/v1 (JSON) and /mcp (Model Context Protocol, streamable HTTP, JSON responses).
 * @param {{ tokens: ReturnType<typeof createApiTokens>, read: ReadModel }} deps
 */
export function integrationRoutes({ tokens, read }) {
  // Wrong tokens count against the caller's address; after 30 in ten minutes it is told to wait.
  const failures = createRateLimit({ limit: 30, windowMs: 10 * 60_000 });
  const blocked = new Map();
  const perToken = createRateLimit({ limit: 120, windowMs: 60_000 });
  const requireToken = (req, res, next) => {
    const ip = req.ip ?? "unknown";
    const until = blocked.get(ip) ?? 0;
    if (until && until <= Date.now()) blocked.delete(ip);
    if (until > Date.now()) return res.set("Retry-After", String(Math.ceil((until - Date.now()) / 1000))).status(429).json({ error: "Too many wrong tokens; try again shortly" });
    const who = tokens.verify(req.get("authorization"));
    if (!who) {
      const wait = failures.hit(ip);
      if (wait) blocked.set(ip, Date.now() + wait * 1000);
      return res.status(401).set("WWW-Authenticate", 'Bearer realm="TheySpy"').json({ error: "A TheySpy API token is required (Briefing → API and MCP)" });
    }
    // A valid token still gets a budget: each domain check pages through Pi-hole's history.
    const wait = perToken.hit(String(who.id));
    if (wait) return res.set("Retry-After", String(wait)).status(429).json({ error: "Too many requests for this token; try again shortly" });
    req.token = who;
    next();
  };

  const api = express.Router();
  api.use(requireToken);
  api.get("/devices", (req, res) => res.json({ devices: read.devices({ onlineOnly: req.query.online === "1" }) }));
  api.get("/indicator-lookups", (req, res) => res.json({ lookups: read.indicatorLookups(Number(req.query.days ?? 30)) }));
  api.get("/exploited-on-devices", (_req, res) => res.json({ cves: read.exploitedOnDevices() }));
  api.get("/domains/:domain", async (req, res) => {
    if (!isDomain(req.params.domain)) return res.status(400).json({ error: "domain must be a domain name, e.g. example.com" });
    res.json(await read.checkDomain(req.params.domain));
  });
  api.get("/status", (_req, res) => res.json(read.status()));

  async function call(name, args = {}) {
    switch (name) {
      case "list_devices": return { devices: read.devices({ onlineOnly: args.online_only === true }) };
      case "list_indicator_lookups": return { lookups: read.indicatorLookups(Math.min(Math.max(Number(args.days ?? 30) || 30, 1), 365)) };
      case "list_exploited_cves_on_devices": return { cves: read.exploitedOnDevices() };
      case "check_domain": {
        if (!isDomain(args.domain)) throw Object.assign(new Error("domain must be a domain name"), { code: -32602 });
        return read.checkDomain(args.domain);
      }
      case "get_status": return read.status();
      default: throw Object.assign(new Error(`Unknown tool: ${name}`), { code: -32602 });
    }
  }

  const mcp = express.Router();
  mcp.use(requireToken);
  mcp.get("/", (_req, res) => res.status(405).set("Allow", "POST").json({ error: "This MCP server answers POST requests with JSON; it has no event stream." }));
  mcp.delete("/", (_req, res) => res.status(405).set("Allow", "POST").end());
  mcp.post("/", async (req, res) => {
    const body = req.body;
    const handle = async (msg) => {
      if (!msg || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") return { jsonrpc: "2.0", id: msg?.id ?? null, error: { code: -32600, message: "Invalid request" } };
      if (msg.id === undefined) return null; // a notification (e.g. notifications/initialized) gets no answer
      try {
        let result;
        if (msg.method === "initialize") {
          result = { protocolVersion: typeof msg.params?.protocolVersion === "string" ? msg.params.protocolVersion : "2025-06-18", capabilities: { tools: { listChanged: false } },
            serverInfo: { name: "theyspy", title: "TheySpy", version: productVersion },
            instructions: "Read-only view of a home network defended by TheySpy: devices, spyware/ADINT indicator lookups seen in Pi-hole, and exploited CVEs in software on those devices. Domains are defanged (example[.]com)." };
        } else if (msg.method === "ping") result = {};
        else if (msg.method === "tools/list") result = { tools };
        else if (msg.method === "tools/call") {
          const data = await call(msg.params?.name, msg.params?.arguments ?? {});
          result = { content: [{ type: "text", text: JSON.stringify(data, null, 2) }], structuredContent: data, isError: false };
        } else return { jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: `Method not found: ${msg.method}` } };
        return { jsonrpc: "2.0", id: msg.id, result };
      } catch (error) {
        if (error.code === -32602) return { jsonrpc: "2.0", id: msg.id, error: { code: -32602, message: error.message } };
        return { jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: error.message }], isError: true } };
      }
    };
    const answers = (Array.isArray(body) ? await Promise.all(body.map(handle)) : [await handle(body)]).filter(Boolean);
    if (!answers.length) return res.status(202).end();
    res.json(Array.isArray(body) ? answers : answers[0]);
  });
  return { api, mcp };
}
