import { productVersion } from "./shared.mjs";

// Alerts (docs/PLAN.md M9): the few things worth telling the owner about without being asked, sent
// to ntfy and listed in TheySpy. Each comes from an audit entry, and each has a key so it is sent
// once: a restart or a second poll does not send it again, and the same device looking up the same
// indicator again sends one alert a day, not one per lookup. Undelivered alerts are retried for a day.

const day = 86_400_000;
const priorities = { urgent: "5", high: "4", default: "3", low: "2" };

/**
 * @param {{
 *   db: import("node:sqlite").DatabaseSync,
 *   settings: ReturnType<typeof import("./db.mjs").createSettingsStore>,
 *   audit: ReturnType<typeof import("./audit.mjs").createAuditLog>,
 *   secretBox: ReturnType<typeof import("./secrets.mjs").createSecretBox>,
 *   env?: { url?: string, topic?: string, token?: string },
 *   names?: () => Record<string, { name: string }>,
 *   kevMatches?: (cveIds: string[]) => { cveId: string, devices: string[] }[],
 *   fetchImpl?: typeof fetch,
 *   now?: () => Date,
 * }} deps
 */
export function createAlerts({ db, settings, audit, secretBox, env = {}, names = () => ({}), kevMatches = () => [], fetchImpl = fetch, now = () => new Date() }) {
  const q = {
    add: db.prepare("INSERT OR IGNORE INTO alerts (key, at, kind, priority, title, message, link) VALUES (?, ?, ?, ?, ?, ?, ?)"),
    get: db.prepare("SELECT * FROM alerts WHERE key = ?"),
    recent: db.prepare("SELECT * FROM alerts ORDER BY at DESC LIMIT ?"),
    pending: db.prepare("SELECT * FROM alerts WHERE delivered_at IS NULL AND at >= ? ORDER BY at"),
    delivered: db.prepare("UPDATE alerts SET delivered_at = ?, error = NULL, attempts = attempts + 1 WHERE key = ?"),
    failed: db.prepare("UPDATE alerts SET error = ?, attempts = attempts + 1 WHERE key = ?"),
    since: db.prepare("SELECT * FROM alerts WHERE at >= ? ORDER BY at"),
  };

  /** Where alerts go: ntfy's server, topic and an optional access token (TS_NTFY_* override the screen). */
  function target() {
    const stored = settings.get("alerts_ntfy") ?? {};
    let token = env.token ?? null;
    if (!token && stored.tokenSealed) { try { token = secretBox.open(stored.tokenSealed); } catch { token = null; } }
    const url = (env.url ?? stored.url ?? "").replace(/\/+$/, "");
    const topic = env.topic ?? stored.topic ?? "";
    return url && topic ? { url, topic, token } : null;
  }

  const who = (ip) => (names()[ip]?.name && names()[ip].name !== ip ? `${names()[ip].name} (${ip})` : ip);
  const link = (path) => (settings.get("lists_base_url") ? `${settings.get("lists_base_url")}${path}` : null);

  /** Audit entry → alert, or null for the ones that are not worth a notification. */
  function fromAudit({ at, action, target: subject, detail }) {
    const d = /** @type {any} */ (detail ?? {});
    const date = at.slice(0, 10);
    switch (action) {
      case "fleet.new_device":
        return { key: `new-device:${subject}`, kind: "new_device", priority: "default", title: "New device on your network",
          message: `${d.hostname ?? d.vendor ?? "A device"} at ${d.ip}${d.mac ? ` (MAC ${d.mac})` : ""}, found by ${d.source === "sweep" ? "a network sweep" : "Pi-hole"}. If you do not know it, look at it in Fleet.`, link: link("/fleet") };
      case "pihole.indicator_lookups": {
        const clients = [...(d.clients ?? [])].sort();
        const indicators = [...(d.indicators ?? [])].sort();
        return { key: `indicator:${clients.join(",")}:${indicators.join(",")}:${date}`, kind: "indicator_lookup", priority: d.allowed ? "urgent" : "high",
          title: d.allowed ? "A device reached a spyware/ADINT address" : "A device asked for a spyware/ADINT address (blocked)",
          message: `${clients.map(who).join(", ")} looked up ${indicators.join(", ").replaceAll(".", "[.]")}: ${d.lookups} lookup${d.lookups === 1 ? "" : "s"}, ${d.allowed ? `${d.allowed} not blocked` : "all blocked"}. A DNS lookup does not prove infection; see Pi-hole Sentinel for what to do next.`, link: link("/pihole") };
      }
      case "cves.zero_day_reported":
      case "cves.kev_added": {
        const matches = kevMatches(d.cves ?? []);
        if (!matches.length) return null; // only exploited bugs in software you run
        const who = action === "cves.kev_added" ? "CISA lists it" : `${(d.sources ?? []).join(", ") || "The vendor"} reports it`;
        return { key: `exploited:${matches.map((m) => m.cveId).sort().join(",")}`, kind: "kev_match", priority: "high",
          title: "Exploited vulnerability in software you run",
          message: matches.map((m) => `${m.cveId} (on ${m.devices.join(", ")})`).join("; ") + `. ${who} as exploited in the wild; update those devices.`, link: link("/intel") };
      }
      case "agent.indicator_found":
        return { key: `agent-hit:${subject}:${[...(d.indicators ?? [])].sort().join(",")}`, kind: "indicator_lookup", priority: "urgent",
          title: d.source === "mvt" ? "MVT found spyware indicators on a phone" : "The agent found a spyware/ADINT indicator on a device",
          message: `${d.device ?? "A device"}: ${(d.indicators ?? []).map((i) => String(i).replaceAll(".", "[.]")).join(", ")}. This is evidence on the device itself; see the Evidence locker for where it was found and what to do.`, link: link("/evidence") };
      case "pihole.unreachable":
        return { key: `pihole-down:${date}:${at.slice(11, 13)}`, kind: "pihole_down", priority: "high", title: "TheySpy cannot reach Pi-hole",
          message: `The live watch failed: ${d.error}. Until it is back, new indicator lookups are not seen.`, link: link("/pihole") };
      case "blocklists.update_quarantined":
        return { key: `quarantine:${subject}:${date}`, kind: "blocklist_held", priority: "low", title: `Blocklist update held: ${d.name}`,
          message: `${(d.reasons ?? []).join("; ")}. The previous version stays in use until you decide.`, link: link("/blocklists") };
      default:
        return null;
    }
  }

  async function deliver(row) {
    const t = target();
    if (!t) return false;
    try {
      const response = await fetchImpl(`${t.url}/${encodeURIComponent(t.topic)}`, {
        method: "POST",
        headers: {
          "user-agent": `TheySpy/${productVersion}`, Title: row.title, Priority: priorities[row.priority] ?? "3",
          Tags: { new_device: "computer", indicator_lookup: "rotating_light", kev_match: "warning", pihole_down: "x", blocklist_held: "hourglass", digest: "newspaper" }[row.kind] ?? "bell",
          ...(row.link ? { Click: row.link } : {}), ...(t.token ? { Authorization: `Bearer ${t.token}` } : {}),
        },
        body: row.message,
        signal: AbortSignal.timeout(15_000),
      });
      if (!response.ok) throw new Error(`ntfy answered ${response.status}`);
      q.delivered.run(now().toISOString(), row.key);
      return true;
    } catch (error) {
      q.failed.run(error.message, row.key);
      return false;
    }
  }

  const alerts = {
    /** Records an alert (once per key) and sends it. Returns false when the key was already used. */
    async raise({ key, kind, priority = "default", title, message, link: url = null }) {
      const inserted = Number(q.add.run(key, now().toISOString(), kind, priority, title, message, url).changes) > 0;
      if (inserted) await deliver(/** @type {any} */ (q.get.get(key)));
      return inserted;
    },

    /** Sends what has not been delivered yet (for a day after it was raised). */
    async retry() {
      let sent = 0;
      for (const row of q.pending.all(new Date(now().getTime() - day).toISOString())) if (await deliver(row)) sent += 1;
      return sent;
    },

    recent: (limit = 30) => q.recent.all(limit).map((raw) => {
      const r = /** @type {any} */ (raw);
      return { key: r.key, at: r.at, kind: r.kind, priority: r.priority, title: r.title, message: r.message, link: r.link, delivered: Boolean(r.delivered_at), error: r.error };
    }),
    since: (iso) => q.since.all(iso),

    config() {
      const stored = settings.get("alerts_ntfy") ?? {};
      return { url: env.url ?? stored.url ?? "", topic: env.topic ?? stored.topic ?? "", hasToken: Boolean(env.token ?? stored.tokenSealed), fromEnv: { url: Boolean(env.url), topic: Boolean(env.topic), token: Boolean(env.token) }, ready: Boolean(target()) };
    },
    /** @param {{ url?: string, topic?: string, token?: string }} input @param {string} actor */
    configure(input, actor) {
      const next = { ...(settings.get("alerts_ntfy") ?? {}) };
      if (input.url !== undefined) {
        if (input.url === "") delete next.url;
        else {
          let u;
          try { u = new URL(String(input.url)); } catch { u = null; }
          if (!u || !["http:", "https:"].includes(u.protocol) || u.username || u.password) throw Object.assign(new Error("The ntfy address must look like https://ntfy.sh or http://192.168.1.5:8093"), { status: 400 });
          next.url = `${u.origin}${u.pathname}`.replace(/\/+$/, "");
        }
      }
      if (input.topic !== undefined) {
        if (input.topic !== "" && !/^[A-Za-z0-9_-]{1,64}$/.test(String(input.topic))) throw Object.assign(new Error("The topic may use letters, digits, - and _ (up to 64)"), { status: 400 });
        next.topic = String(input.topic) || undefined;
      }
      if (input.token !== undefined) next.tokenSealed = input.token ? secretBox.seal(String(input.token)) : undefined;
      settings.set("alerts_ntfy", next);
      audit.record(actor, "alerts.configured", null, { url: next.url ?? null, topic: next.topic ?? null, token: input.token === undefined ? undefined : "(changed)" });
      return alerts.config();
    },
    /** A test notification, sent now whatever the keys say. */
    async test() {
      const key = `test:${now().toISOString()}`;
      await alerts.raise({ key, kind: "test", priority: "low", title: "TheySpy test notification", message: "If you can read this, TheySpy's alerts reach you." });
      const row = /** @type {any} */ (q.get.get(key));
      if (!row.delivered_at) throw Object.assign(new Error(row.error ?? "Set the ntfy address and topic first"), { status: 502 });
      return { delivered: true };
    },
  };

  audit.onRecord((entry) => {
    const alert = fromAudit(entry);
    if (alert) void alerts.raise(alert);
  });
  return alerts;
}
