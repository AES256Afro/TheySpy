import { productVersion } from "../shared.mjs";
import { isRandomisedMac, normaliseMac } from "./addresses.mjs";

// MAC vendors from the IEEE registry (MA-L, the 24-bit prefixes), for devices Pi-hole does not name.
// Fetched on request and then monthly; a randomised (private) MAC has no vendor to look up.

export const ouiUrl = "https://standards-oui.ieee.org/oui/oui.csv";

/** The registry's CSV → prefix ("a4c138") → organisation name. */
export function parseOuiCsv(text) {
  const out = new Map();
  for (const line of text.split(/\r?\n/).slice(1)) {
    const m = /^MA-L,([0-9A-F]{6}),("(?:[^"]|"")*"|[^,]*)/i.exec(line);
    if (!m) continue;
    const name = m[2].startsWith('"') ? m[2].slice(1, -1).replace(/""/g, '"') : m[2];
    if (name.trim()) out.set(m[1].toLowerCase(), name.trim());
  }
  return out;
}

/**
 * @param {{
 *   db: import("node:sqlite").DatabaseSync,
 *   settings: ReturnType<typeof import("../db.mjs").createSettingsStore>,
 *   fetchImpl?: typeof fetch,
 *   now?: () => Date,
 * }} deps
 */
export function createOui({ db, settings, fetchImpl = fetch, now = () => new Date() }) {
  const q = {
    get: db.prepare("SELECT vendor FROM oui WHERE prefix = ?"),
    count: db.prepare("SELECT COUNT(*) AS n FROM oui"),
    clear: db.prepare("DELETE FROM oui"),
    put: db.prepare("INSERT INTO oui (prefix, vendor) VALUES (?, ?)"),
    unnamed: db.prepare("SELECT id, mac FROM devices WHERE vendor IS NULL AND mac IS NOT NULL"),
    name: db.prepare("UPDATE devices SET vendor = ? WHERE id = ?"),
  };
  const oui = {
    /** The vendor for a MAC, or null (unknown, or a randomised MAC). */
    vendorOf(mac) {
      const m = normaliseMac(mac);
      if (!m || isRandomisedMac(m)) return null;
      return /** @type {any} */ (q.get.get(m.replaceAll(":", "").slice(0, 6)))?.vendor ?? null;
    },
    status: () => ({ prefixes: Number(/** @type {any} */ (q.count.get()).n), ...(settings.get("oui_last_update") ?? {}) }),

    /** Downloads the registry (unless unchanged since last time) and names devices that had no vendor. */
    async update() {
      const last = settings.get("oui_last_update");
      const response = await fetchImpl(ouiUrl, { headers: { "user-agent": `TheySpy/${productVersion}`, ...(last?.etag && oui.status().prefixes ? { "if-none-match": last.etag } : {}) }, redirect: "follow", signal: AbortSignal.timeout(120_000) });
      let changed = false;
      if (response.status !== 304) {
        if (!response.ok) throw new Error(`The IEEE registry answered ${response.status}`);
        const prefixes = parseOuiCsv(await response.text());
        if (prefixes.size < 10_000) throw new Error(`The IEEE registry looked wrong (${prefixes.size} prefixes); keeping the current one`);
        db.exec("BEGIN");
        try {
          q.clear.run();
          for (const [prefix, vendor] of prefixes) q.put.run(prefix, vendor);
          db.exec("COMMIT");
        } catch (error) {
          db.exec("ROLLBACK");
          throw error;
        }
        changed = true;
      }
      let named = 0;
      for (const raw of q.unnamed.all()) {
        const d = /** @type {any} */ (raw);
        const vendor = oui.vendorOf(d.mac);
        if (vendor) { q.name.run(vendor, d.id); named += 1; }
      }
      const result = { at: now().toISOString(), etag: response.headers.get("etag") ?? last?.etag ?? null, prefixes: oui.status().prefixes, changed, named };
      settings.set("oui_last_update", result);
      return result;
    },
  };
  return oui;
}

/** @param {ReturnType<typeof createOui>} oui */
export function ouiJobKinds(oui) {
  return {
    "fleet.oui": {
      title: "Update MAC vendor names (IEEE)",
      direct: true,
      async run({ log }) {
        const r = await oui.update();
        log(`${r.changed ? `Loaded ${r.prefixes.toLocaleString()} vendor prefixes` : "The IEEE registry has not changed"}; named ${r.named} device${r.named === 1 ? "" : "s"}.`);
        return r;
      },
    },
  };
}
