// Multi-site (docs/PLAN.md "Later"): one TheySpy per place - home, a cabin, a parents' house - each
// watching its own DNS and changing its own Pi-hole, and this one reading the others. It reads with
// each site's read-only API token (Briefing → API and MCP there), never a password, so it can see
// but cannot change anything at a site. A lookup that got past a site's blocking raises an alert
// here, once.
//
// What a site answers is another TheySpy's data, so it is re-checked and bounded before it is kept.

import { randomBytes } from "node:crypto";

// eslint-disable-next-line no-control-regex -- stripping control characters from another site's answer is the point
const clip = (value, max = 80) => { const t = String(value ?? "").replace(/[\u0000-\u001f<>]/g, " ").trim(); return t.length > max ? `${t.slice(0, max - 1)}…` : t; };
const count = (value) => (Number.isFinite(Number(value)) && Number(value) >= 0 ? Math.min(Math.floor(Number(value)), 1_000_000) : 0);
const defanged = (value) => clip(value, 120).replace(/(?<!\[)\.(?!\])/g, "[.]");

/**
 * @param {{
 *   settings: ReturnType<typeof import("./db.mjs").createSettingsStore>,
 *   secretBox: ReturnType<typeof import("./secrets.mjs").createSecretBox>,
 *   audit: ReturnType<typeof import("./audit.mjs").createAuditLog>,
 *   fetchImpl?: typeof fetch,
 *   now?: () => Date,
 * }} deps
 */
export function createSites({ settings, secretBox, audit, fetchImpl = fetch, now = () => new Date() }) {
  const list = () => /** @type {any[]} */ (settings.get("sites") ?? []);
  const snapshots = () => /** @type {Record<string, any>} */ (settings.get("sites_snapshots") ?? {});

  /** @returns {Promise<any>} */
  async function read(site, path) {
    const response = await fetchImpl(`${site.url}${path}`, { headers: { authorization: `Bearer ${secretBox.open(site.tokenSealed) ?? ""}`, accept: "application/json" }, signal: AbortSignal.timeout(20_000) });
    if (response.status === 401) throw new Error("the site refused the token; create a new one there (Briefing → API and MCP)");
    if (!response.ok) throw new Error(`the site answered ${response.status}`);
    return response.json();
  }

  const api = {
    /** The sites and what each said last, newest reading first. */
    overview() {
      const snaps = snapshots();
      return list().map((s) => ({ id: s.id, name: s.name, url: s.url, ...(snaps[s.id] ?? { at: null }) }));
    },

    /** @param {{ name?: string, url?: string, token?: string }} input @param {string} actor */
    add(input, actor) {
      const name = clip(input.name, 40);
      if (!name) throw Object.assign(new Error("Give the site a name, e.g. Cabin"), { status: 400 });
      let u;
      try { u = new URL(String(input.url)); } catch { u = null; }
      if (!u || !["http:", "https:"].includes(u.protocol) || u.username || u.password) throw Object.assign(new Error("The site's address must look like https://cabin.example.ts.net:8797"), { status: 400 });
      if (!/^tsy_[A-Za-z0-9_-]{16,}$/.test(String(input.token ?? ""))) throw Object.assign(new Error("Paste an API token from that TheySpy (Briefing → API and MCP); it starts with tsy_"), { status: 400 });
      const site = { id: randomBytes(6).toString("hex"), name, url: u.origin, tokenSealed: secretBox.seal(String(input.token)) };
      settings.set("sites", [...list(), site]);
      audit.record(actor, "sites.added", name, { url: site.url });
      return { id: site.id, name, url: site.url };
    },

    /** @param {string} id @param {string} actor */
    remove(id, actor) {
      const site = list().find((s) => s.id === id);
      if (!site) throw Object.assign(new Error("No such site"), { status: 404 });
      settings.set("sites", list().filter((s) => s.id !== id));
      const snaps = snapshots(); delete snaps[id]; settings.set("sites_snapshots", snaps);
      audit.record(actor, "sites.removed", site.name, {});
    },

    /** Reads every site; a site that cannot be read keeps its last reading, marked with the error. */
    async refresh() {
      const snaps = snapshots();
      for (const site of list()) {
        const at = now().toISOString();
        try {
          const [status, lookups, exploited, devices] = await Promise.all([
            read(site, "/api/v1/status"), read(site, "/api/v1/indicator-lookups?days=7"), read(site, "/api/v1/exploited-on-devices"), read(site, "/api/v1/devices?online=1"),
          ]);
          const rows = (Array.isArray(lookups.lookups) ? lookups.lookups : []).slice(0, 200).map((l) => ({
            device: clip(l.device, 60), domain: defanged(l.domain), indicator: defanged(l.indicator), lookups: count(l.lookups), blocked: count(l.blocked), lastSeen: typeof l.lastSeen === "string" ? l.lastSeen.slice(0, 30) : null,
          }));
          const gotThrough = rows.filter((l) => l.blocked < l.lookups);
          // An alert for each (device, indicator) that got through and was not there at the last reading.
          const before = new Set((snaps[site.id]?.gotThrough ?? []).map((l) => `${l.device}|${l.indicator}`));
          const fresh = gotThrough.filter((l) => !before.has(`${l.device}|${l.indicator}`));
          if (fresh.length) audit.record("system", "sites.indicator_lookups", site.name, { site: site.name, lookups: fresh.slice(0, 20) });
          snaps[site.id] = {
            at, error: null,
            version: clip(status.version ?? status.theyspy ?? "", 20) || null,
            sections: (Array.isArray(status.sections) ? status.sections : []).slice(0, 6).map((s) => ({ title: clip(s.title, 40), tone: ["good", "warn", "bad"].includes(s.tone) ? s.tone : "unknown", lines: (Array.isArray(s.lines) ? s.lines : []).slice(0, 4).map((x) => clip(x, 240)) })),
            lookups: rows.length, gotThrough: gotThrough.slice(0, 20),
            exploited: (Array.isArray(exploited.cves) ? exploited.cves : []).length,
            online: (Array.isArray(devices.devices) ? devices.devices : []).length,
          };
        } catch (error) {
          // fetch's own message is just "fetch failed"; the reason (ECONNREFUSED, a timeout) is inside.
          const reason = error.cause?.code ?? error.cause?.errors?.[0]?.code ?? error.cause?.message ?? error.message;
          snaps[site.id] = { ...(snaps[site.id] ?? {}), at: snaps[site.id]?.at ?? null, error: clip(reason === "ECONNREFUSED" ? "nothing answers at that address (connection refused)" : reason, 200), errorAt: at };
        }
      }
      settings.set("sites_snapshots", snaps);
      return api.overview();
    },

    /** Hosts the outbound allowlist must let through. */
    hosts: () => list().map((s) => new URL(s.url).hostname),
  };
  return api;
}
