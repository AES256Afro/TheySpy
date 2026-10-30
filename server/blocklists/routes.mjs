import { timingSafeEqual } from "node:crypto";
import net from "node:net";
import express from "express";
import { scopeKey } from "./baselines.mjs";
import { compiledLists } from "./library.mjs";
import { categories, categoryIds, groups, securityCategories } from "./taxonomy.mjs";
import { defang } from "../iocs/parse.mjs";

export const listFormats = Object.freeze({
  txt: { type: "text/plain", comment: "#", line: (d) => d, label: "Domains (Pi-hole, AdGuard Home, NextDNS)" },
  hosts: { type: "text/plain", comment: "#", line: (d) => `0.0.0.0 ${d}`, label: "hosts file" },
  adblock: { type: "text/plain", comment: "!", line: (d) => `||${d}^`, label: "Adblock / uBlock / AdGuard" },
  dnsmasq: { type: "text/plain", comment: "#", line: (d) => `address=/${d}/0.0.0.0`, label: "dnsmasq" },
  rpz: { type: "text/plain", comment: ";", line: (d) => `${d} CNAME .\n*.${d} CNAME .`, label: "Response Policy Zone" },
});

const listDefinition = (name) => compiledLists[name] ?? (categoryIds.includes(name) ? { name: categories.find((c) => c.id === name).name, description: categories.find((c) => c.id === name).description, categories: [name] } : null);

/**
 * GET /lists/<token>/<name>.<format>: what Pi-hole subscribes to. No sign-in (Pi-hole cannot sign
 * in); the random token in the path keeps the lists to people the owner gave the address to, and a
 * wrong token gets the same 404 as a wrong name. Names are a category, "security", "recommended",
 * or "baseline-<level>--<scope>" (a baseline with that scope's exceptions taken out).
 * @param {{ library: ReturnType<typeof import("./library.mjs").createBlocklistLibrary>, baselines?: ReturnType<typeof import("./baselines.mjs").createBaselines>, now?: () => Date }} deps
 */
export function publicListRoutes({ library, baselines, now = () => new Date() }) {
  const router = express.Router();
  router.get("/:token/:file", (req, res) => {
    // The token first, so a stranger cannot make TheySpy compile lists (it is slow on purpose-built sets).
    const token = Buffer.from(String(req.params.token));
    const expected = Buffer.from(library.listToken());
    if (token.length !== expected.length || !timingSafeEqual(token, expected)) return res.status(404).type("text/plain").send("Not found\n");
    const m = /^([a-z]+|baseline-([a-z]+)--(network|device-[0-9a-f-]+))\.(txt|hosts|adblock|dnsmasq|rpz)$/.exec(req.params.file);
    let definition = null;
    let compiled = null;
    if (m && m[2] && baselines) {
      compiled = baselines.compileFor(m[2], m[3]);
      if (compiled) definition = { name: `${m[2][0].toUpperCase()}${m[2].slice(1)} baseline (${m[3]})`, description: "A TheySpy baseline: its categories, minus the sites kept allowed for this scope." };
    } else if (m) {
      definition = listDefinition(m[1]);
      compiled = definition && library.compile(definition.categories);
    }
    if (!definition || !compiled) return res.status(404).type("text/plain").send("Not found\n");
    const format = listFormats[m[4]];
    const etag = `"${compiled.etag}-${m[4]}"`;
    res.set({ "Content-Type": `${format.type}; charset=utf-8`, ETag: etag, "Cache-Control": "no-cache" });
    if (req.get("if-none-match") === etag) return res.status(304).end();
    const c = format.comment;
    const head = [
      `${c} TheySpy ${definition.name} list (${m[4]})`,
      `${c} ${definition.description}`,
      `${c} ${compiled.domains.length} domains from ${compiled.sources} enabled lists, compiled ${now().toISOString()}.`,
      `${c} Names on TheySpy's never-block list (connectivity checks, certificates, updates, your pins) are left out.`,
    ];
    res.send(`${[...head, ...compiled.domains.map(format.line)].join("\n")}\n`);
  });
  return router;
}

/**
 * /api/blocklists, behind sign-in.
 * @param {{
 *   library: ReturnType<typeof import("./library.mjs").createBlocklistLibrary>,
 *   jobs: ReturnType<typeof import("../jobs.mjs").createJobRunner>,
 *   settings: ReturnType<typeof import("../db.mjs").createSettingsStore>,
 *   sentinel: ReturnType<typeof import("../pihole/sentinel.mjs").createSentinel>,
 *   baselines: ReturnType<typeof import("./baselines.mjs").createBaselines>,
 * }} deps
 */
export function blocklistRoutes({ library, jobs, settings, sentinel, baselines }) {
  const router = express.Router();
  // The address Pi-hole uses to reach TheySpy can differ from the browser's (localhost, a proxy):
  // the owner can set it; otherwise the address this page was opened at is used.
  const origin = (req) => settings.get("lists_base_url") ?? `${req.protocol}://${req.get("host")}`;
  // Adblock format: Pi-hole and AdGuard Home then block each name's subdomains too, as the source
  // lists (mostly ||name^ rules) intend; a plain-domain list would block only the exact names.
  const addressOf = (req, id) => `${origin(req)}/lists/${library.listToken()}/${id}.adblock`;

  router.get("/", (req, res) => {
    const base = `${origin(req)}/lists/${library.listToken()}`;
    const n = library.counts();
    res.json({
      sources: library.sources(),
      quarantined: library.quarantined(),
      categories: library.categoryCounts(),
      groups,
      candidateCount: library.candidates().length,
      lastDiscovery: settings.get("blocklists_last_discovery") ?? null,
      lastUpdate: settings.get("blocklists_last_update") ?? null,
      pins: library.pins(),
      listsBaseUrl: origin(req),
      listsBaseUrlSet: Boolean(settings.get("lists_base_url")),
      pihole: { connected: sentinel.publicConfig().mode === "api", write: sentinel.publicConfig().write },
      subscriptions: [...Object.entries(compiledLists).map(([id, l]) => ({ id, name: l.name, description: l.description })), ...categories.map((c) => ({ id: c.id, name: c.name, description: c.description }))]
        .map((l) => ({ ...l, url: `${base}/${l.id}.adblock`, domains: (n.lists[l.id] ?? n.categories[l.id]).domains })),
      formats: Object.entries(listFormats).map(([id, f]) => ({ id, label: f.label })),
    });
  });

  router.get("/candidates", (req, res) => {
    const text = String(req.query.q ?? "").toLowerCase();
    const category = String(req.query.category ?? "");
    const directory = String(req.query.directory ?? "");
    const all = library.candidates().filter((c) => (!text || c.name.toLowerCase().includes(text) || (c.description ?? "").toLowerCase().includes(text))
      && (!category || c.categories.includes(category)) && (!directory || c.directory === directory));
    res.json({ total: all.length, candidates: all.slice(0, 200) });
  });

  router.post("/discover", (_req, res) => res.status(202).json({ job: jobs.enqueue("blocklists.discover", { actor: "owner" }) }));
  router.post("/update", (_req, res) => res.status(202).json({ job: jobs.enqueue("blocklists.update", { actor: "owner" }) }));

  router.put("/sources/:id", async (req, res) => {
    const id = Number(req.params.id);
    let source = library.get(id);
    if (!source) return res.status(404).json({ error: "No such list" });
    if (Array.isArray(req.body?.categories)) source = library.setCategories(id, req.body.categories, "owner");
    if (req.body?.status !== undefined) {
      if (!["enabled", "disabled", "candidate"].includes(req.body.status)) return res.status(400).json({ error: "status must be enabled, disabled or candidate" });
      source = await library.setStatus(id, req.body.status, "owner");
      // A newly enabled list is fetched straight away, so it counts from now rather than tonight.
      if (req.body.status === "enabled" && source.directory !== "builtin" && !source.activeVersionId) jobs.enqueue("blocklists.update", { actor: "owner", params: { ids: [id] } });
    }
    res.json({ source });
  });

  router.post("/sources", (req, res) => {
    const source = library.addCustom(req.body ?? {}, "owner");
    jobs.enqueue("blocklists.update", { actor: "owner", params: { ids: [source.id] } });
    res.status(201).json({ source });
  });

  router.post("/versions/:id/accept", (req, res) => res.json({ version: library.decide(Number(req.params.id), true, "owner") }));
  router.post("/versions/:id/reject", (req, res) => res.json({ version: library.decide(Number(req.params.id), false, "owner") }));

  router.put("/base-url", (req, res) => {
    const raw = String(req.body?.url ?? "").trim();
    if (!raw) { settings.delete("lists_base_url"); return res.json({ listsBaseUrl: origin(req) }); }
    let u;
    try { u = new URL(raw); } catch { u = null; }
    if (!u || !["http:", "https:"].includes(u.protocol) || u.pathname !== "/" || u.username) return res.status(400).json({ error: "Give an address like http://192.168.1.5:8797" });
    settings.set("lists_base_url", u.origin);
    res.json({ listsBaseUrl: u.origin });
  });

  // Pi-hole subscriptions: which of TheySpy's lists Pi-hole has, and adding or removing one.
  router.get("/pihole", async (_req, res) => {
    try {
      res.json({ subscriptions: await sentinel.subscriptions() });
    } catch (error) {
      res.json({ subscriptions: [], error: error.message });
    }
  });
  router.post("/pihole/:id", (req, res) => {
    const definition = listDefinition(req.params.id);
    if (!definition) return res.status(404).json({ error: "No such list" });
    res.status(202).json({ job: jobs.enqueue("pihole.subscribe", { actor: "owner", params: { address: addressOf(req, req.params.id), label: definition.name } }) });
  });
  router.delete("/pihole", (req, res) => {
    const address = String(req.body?.address ?? "");
    res.status(202).json({ job: jobs.enqueue("pihole.unsubscribe", { actor: "owner", params: { address } }) });
  });

  // --- baselines -------------------------------------------------------------------------------
  router.get("/baselines", async (_req, res) => {
    res.json({ baselines: baselines.list(), categories, scopes: await baselines.scopes(), assignments: baselines.assignments(), pihole: { connected: sentinel.publicConfig().mode !== null, api: sentinel.publicConfig().mode === "api", write: sentinel.publicConfig().write } });
  });
  router.get("/baselines/preview", async (req, res) => {
    const client = req.query.client ? String(req.query.client) : undefined;
    if (client && !net.isIP(String(client))) return res.status(400).json({ error: "client must be an IP address" });
    const windowDays = Number(req.query.days ?? 7);
    if (![1, 7, 14, 30].includes(windowDays)) return res.status(400).json({ error: "days must be 1, 7, 14 or 30" });
    const preview = await baselines.preview({ client, windowDays });
    // Security sites are spyware, malware and phishing names: they leave the server defanged, like indicators.
    const safe = (site) => (site.categories.some((c) => securityCategories.includes(c)) ? { ...site, site: defang(site.site), names: site.names.map(defang) } : site);
    const shadow = preview.shadow && { ...preview.shadow, level: { ...preview.shadow.level, details: preview.shadow.level.details.map(safe) } };
    res.json({ ...preview, levels: preview.levels.map((l) => ({ ...l, details: l.details.map(safe) })), shadow });
  });
  router.put("/baselines/exceptions", (req, res) => {
    const { scope, site, keep } = req.body ?? {};
    if (typeof scope !== "string" || !/^(network|device-[0-9a-f-]+)$/i.test(scope) || typeof site !== "string" || !site) return res.status(400).json({ error: "scope and site are required" });
    res.json({ exceptions: baselines.setException(scope, site.toLowerCase().replaceAll("[.]", "."), keep !== false, "owner") });
  });
  router.post("/baselines/apply", (req, res) => {
    const { baselineId, client } = req.body ?? {};
    if (!baselines.find(baselineId)) return res.status(400).json({ error: "No such baseline" });
    if (client && !net.isIP(String(client))) return res.status(400).json({ error: "client must be an IP address" });
    res.status(202).json({ job: jobs.enqueue("baselines.apply", { actor: "owner", params: { baselineId, client: client || undefined, listsOrigin: origin(req) } }) });
  });
  router.put("/baselines/custom", (req, res) => res.json({ custom: baselines.setCustom(req.body ?? {}, "owner") }));
  router.delete("/baselines/custom", (_req, res) => { baselines.deleteCustom("owner"); res.json({ deleted: true }); });
  router.post("/baselines/shadow", (req, res) => {
    const { baselineId, client } = req.body ?? {};
    if (client && !net.isIP(String(client))) return res.status(400).json({ error: "client must be an IP address" });
    res.json({ shadow: baselines.startShadow({ baselineId, client: client || undefined }, "owner") });
  });
  router.delete("/baselines/shadow", (req, res) => {
    const client = req.body?.client || undefined;
    if (baselines.assignments()[scopeKey(client)]?.mode !== "shadow") return res.status(404).json({ error: "Nothing is in shadow mode there" });
    void baselines.remove({ client }, "owner").then((r) => res.json(r), (error) => res.status(500).json({ error: error.message }));
  });
  router.post("/baselines/remove", (req, res) => {
    res.status(202).json({ job: jobs.enqueue("baselines.remove", { actor: "owner", params: { client: req.body?.client || undefined } }) });
  });

  router.put("/pins", (req, res) => {
    if (!Array.isArray(req.body?.pins)) return res.status(400).json({ error: "pins must be a list of names" });
    res.json({ pins: library.setPins(req.body.pins, "owner") });
  });

  return router;
}
