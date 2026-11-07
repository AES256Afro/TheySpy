import { createHmac } from "node:crypto";
import { productVersion } from "./shared.mjs";

// Alerts (docs/PLAN.md M9): the few things worth telling the owner about without being asked, sent
// to ntfy and listed in TheySpy. Each comes from an audit entry, and each has a key so it is sent
// once: a restart or a second poll does not send it again, and the same device looking up the same
// indicator again sends one alert a day, not one per lookup. Undelivered alerts are retried for a day.

const day = 86_400_000;
const priorities = { urgent: "5", high: "4", default: "3", low: "2" };
const tags = { new_device: "computer", indicator_lookup: "rotating_light", kev_match: "warning", pihole_down: "x", blocklist_held: "hourglass", digest: "newspaper" };

/**
 * @param {{
 *   db: import("node:sqlite").DatabaseSync,
 *   settings: ReturnType<typeof import("./db.mjs").createSettingsStore>,
 *   audit: ReturnType<typeof import("./audit.mjs").createAuditLog>,
 *   secretBox: ReturnType<typeof import("./secrets.mjs").createSecretBox>,
 *   env?: { url?: string, topic?: string, token?: string },
 *   names?: () => Record<string, { id?: number, name: string }>,
 *   kevMatches?: (cveIds: string[]) => { cveId: string, devices: string[] }[],
 *   fetchImpl?: typeof fetch,
 *   now?: () => Date,
 * }} deps
 */
export function createAlerts({ db, settings, audit, secretBox, env = {}, names = () => ({}), kevMatches = () => [], fetchImpl = fetch, now = () => new Date() }) {
  const q = {
    add: db.prepare("INSERT OR IGNORE INTO alerts (key, at, kind, priority, title, message, link, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
    get: db.prepare("SELECT * FROM alerts WHERE key = ?"),
    recent: db.prepare("SELECT * FROM alerts ORDER BY at DESC LIMIT ?"),
    pending: db.prepare("SELECT * FROM alerts WHERE delivered_at IS NULL AND at >= ? ORDER BY at"),
    delivered: db.prepare("UPDATE alerts SET delivered_at = ?, error = NULL, attempts = attempts + 1 WHERE key = ?"),
    failed: db.prepare("UPDATE alerts SET error = ?, attempts = attempts + 1 WHERE key = ?"),
    reached: db.prepare("UPDATE alerts SET deliveries = ? WHERE key = ?"),
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

  /** The webhook, when the owner set one: a URL, and a secret that signs each body (alerts_webhook). */
  function webhook() {
    const stored = settings.get("alerts_webhook") ?? {};
    if (!stored.url) return null;
    let secret = null;
    if (stored.secretSealed) { try { secret = secretBox.open(stored.secretSealed); } catch { secret = null; } }
    return { url: stored.url, secret };
  }

  /** Every channel that is set up, by name. */
  const channels = () => /** @type {[string, any][]} */ ([["ntfy", target()], ["webhook", webhook()]]).filter(([, t]) => t);

  const who = (ip) => (names()[ip]?.name && names()[ip].name !== ip ? `${names()[ip].name} (${ip})` : ip);
  const link = (path) => (settings.get("lists_base_url") ? `${settings.get("lists_base_url")}${path}` : null);
  /** The device page for an address TheySpy knows a device at, so a tap on the alert lands on the item, not the screen. */
  const deviceLink = (ip) => { const known = ip ? names()[ip] : null; return known?.id ? link(`/fleet/devices/${known.id}`) : null; };

  /** Audit entry → alert, or null for the ones that are not worth a notification. */
  function fromAudit({ at, action, target: subject, detail }) {
    const d = /** @type {any} */ (detail ?? {});
    const date = at.slice(0, 10);
    switch (action) {
      case "fleet.new_device":
        return { key: `new-device:${subject}`, kind: "new_device", priority: "default", title: "New device on your network",
          message: `${d.hostname ?? d.vendor ?? "A device"} at ${d.ip}${d.mac ? ` (MAC ${d.mac})` : ""}, found by ${d.source === "sweep" ? "a network sweep" : d.source === "netalertx" ? "NetAlertX" : "Pi-hole"}. If you do not know it, look at it in Fleet.`, link: deviceLink(d.ip) ?? link("/fleet") };
      case "pihole.indicator_lookups": {
        const clients = [...(d.clients ?? [])].sort();
        const indicators = [...(d.indicators ?? [])].sort();
        return { key: `indicator:${clients.join(",")}:${indicators.join(",")}:${date}`, kind: "indicator_lookup", priority: d.allowed ? "urgent" : "high",
          title: d.allowed ? "A device reached a spyware/ADINT address" : "A device asked for a spyware/ADINT address (blocked)",
          message: `${clients.map(who).join(", ")} looked up ${indicators.join(", ").replaceAll(".", "[.]")}: ${d.lookups} lookup${d.lookups === 1 ? "" : "s"}, ${d.allowed ? `${d.allowed} not blocked` : "all blocked"}. A DNS lookup does not prove infection; see Pi-hole Sentinel for what to do next.`, link: (clients.length === 1 ? deviceLink(clients[0]) : null) ?? link("/pihole") };
      }
      case "cves.zero_day_reported":
      case "cves.kev_added": {
        const matches = kevMatches(d.cves ?? []);
        if (!matches.length) return null; // only exploited bugs in software you run
        const who = action === "cves.kev_added" ? "CISA lists it" : `${(d.sources ?? []).join(", ") || "The vendor"} reports it`;
        return { key: `exploited:${matches.map((m) => m.cveId).sort().join(",")}`, kind: "kev_match", priority: "high", detail: { matches },
          title: "Exploited vulnerability in software you run",
          message: matches.map((m) => `${m.cveId} (on ${m.devices.join(", ")})`).join("; ") + `. ${who} as exploited in the wild; update those devices.`, link: link("/intel") };
      }
      case "agent.indicator_found":
        return { key: `agent-hit:${subject}:${[...(d.indicators ?? [])].sort().join(",")}`, kind: "indicator_lookup", priority: "urgent",
          title: d.source === "mvt" ? "MVT found spyware indicators on a phone" : "The agent found a spyware/ADINT indicator on a device",
          message: `${d.device ?? "A device"}: ${(d.indicators ?? []).map((i) => String(i).replaceAll(".", "[.]")).join(", ")}. This is evidence on the device itself; see the Evidence locker for where it was found and what to do.`, link: link("/evidence") };
      case "sites.indicator_lookups": {
        const lookups = (d.lookups ?? []).slice(0, 5);
        return { key: `site-indicator:${subject}:${lookups.map((l) => `${l.device}|${l.indicator}`).sort().join(",")}`, kind: "indicator_lookup", priority: "urgent",
          title: `At ${d.site}: a device reached a spyware/ADINT address`,
          message: `${lookups.map((l) => `${l.device} looked up ${l.indicator} (${l.lookups - l.blocked} of ${l.lookups} not blocked)`).join("; ")}. Open that site's TheySpy for what to do next.`, link: link("/sites") };
      }
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

  async function sendNtfy(t, row) {
    const response = await fetchImpl(`${t.url}/${encodeURIComponent(t.topic)}`, {
      method: "POST",
      headers: {
        "user-agent": `TheySpy/${productVersion}`, Title: row.title, Priority: Object.hasOwn(priorities, row.priority) ? priorities[row.priority] : "3",
        Tags: Object.hasOwn(tags, row.kind) ? tags[row.kind] : "bell",
        ...(row.link ? { Click: row.link } : {}), ...(t.token ? { Authorization: `Bearer ${t.token}` } : {}),
      },
      body: row.message,
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) throw new Error(`ntfy answered ${response.status}`);
  }

  /**
   * The alert as JSON, POSTed once. With a secret set, X-TheySpy-Signature carries the HMAC-SHA256
   * of the exact body, hex, as "sha256=…", so the receiver can refuse anything else.
   */
  async function sendWebhook(t, row) {
    const body = JSON.stringify({ event: "alert", key: row.key, at: row.at, kind: row.kind, priority: row.priority, title: row.title, message: row.message, link: row.link ?? null, detail: row.detail ? JSON.parse(row.detail) : null });
    const response = await fetchImpl(t.url, {
      method: "POST",
      headers: {
        "content-type": "application/json", "user-agent": `TheySpy/${productVersion}`, "x-theyspy-event": "alert",
        ...(t.secret ? { "x-theyspy-signature": `sha256=${createHmac("sha256", t.secret).update(body).digest("hex")}` } : {}),
      },
      body,
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) throw new Error(`the webhook answered ${response.status}`);
  }

  const senders = { ntfy: sendNtfy, webhook: sendWebhook };

  /** Sends to every channel the alert has not reached yet; delivered once every channel has it. */
  async function deliver(row) {
    const configured = channels();
    if (configured.length === 0) return false;
    const reached = row.deliveries ? JSON.parse(row.deliveries) : {};
    const errors = [];
    for (const [name, t] of configured) {
      if (reached[name]) continue;
      try { await senders[name](t, row); reached[name] = now().toISOString(); } catch (error) { errors.push(configured.length > 1 ? `${name}: ${error.message}` : error.message); }
    }
    q.reached.run(JSON.stringify(reached), row.key);
    if (errors.length === 0) { q.delivered.run(now().toISOString(), row.key); return true; }
    q.failed.run(errors.join("; "), row.key);
    return false;
  }

  const alerts = {
    /** Records an alert (once per key) and sends it. Returns false when the key was already used. */
    async raise({ key, kind, priority = "default", title, message, link: url = null, detail = null }) {
      const inserted = Number(q.add.run(key, now().toISOString(), kind, priority, title, message, url, detail === null ? null : JSON.stringify(detail)).changes) > 0;
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
    since: (iso) => q.since.all(iso).map((raw) => { const r = /** @type {any} */ (raw); return { ...r, detail: r.detail ? JSON.parse(r.detail) : null }; }),

    config() {
      const stored = settings.get("alerts_ntfy") ?? {};
      return { url: env.url ?? stored.url ?? "", topic: env.topic ?? stored.topic ?? "", hasToken: Boolean(env.token ?? stored.tokenSealed), fromEnv: { url: Boolean(env.url), topic: Boolean(env.topic), token: Boolean(env.token) }, ready: Boolean(target()) };
    },
    /** The webhook as the screen shows it: the address, whether a secret is set, and whether it is ready. */
    webhookConfig() {
      const stored = settings.get("alerts_webhook") ?? {};
      return { url: stored.url ?? "", hasSecret: Boolean(stored.secretSealed), ready: Boolean(webhook()) };
    },
    /** @param {{ url?: string, secret?: string }} input @param {string} actor */
    configureWebhook(input, actor) {
      const next = { ...(settings.get("alerts_webhook") ?? {}) };
      if (input.url !== undefined) {
        if (input.url === "") delete next.url;
        else {
          let u;
          try { u = new URL(String(input.url)); } catch { u = null; }
          if (!u || !["http:", "https:"].includes(u.protocol) || u.username || u.password) throw Object.assign(new Error("The webhook address must be an http(s) URL without a user name or password, e.g. https://hooks.example/theyspy"), { status: 400 });
          next.url = u.href;
        }
      }
      if (input.secret !== undefined) next.secretSealed = input.secret ? secretBox.seal(String(input.secret).slice(0, 500)) : undefined;
      settings.set("alerts_webhook", next);
      audit.record(actor, "alerts.webhook_configured", null, { url: next.url ?? null, secret: input.secret === undefined ? undefined : "(changed)" });
      return alerts.webhookConfig();
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
      if (!row.delivered_at) throw Object.assign(new Error(row.error ?? "Set up ntfy or a webhook first"), { status: 502 });
      return { delivered: true, channels: Object.keys(JSON.parse(row.deliveries || "{}")) };
    },
  };

  audit.onRecord((entry) => {
    // raise() is async, so a throw inside it is a rejected promise, which the audit log's own
    // try/catch around listeners cannot see. Neither half may be silent: a lost alert is the one
    // failure this module exists to prevent.
    let alert;
    try { alert = fromAudit(entry); } catch (error) { console.error(`alerts: could not build an alert from ${entry.action}: ${error.message}`); return; }
    if (alert) alerts.raise(alert).catch((error) => console.error(`alerts: could not record ${alert.key}: ${error.message}`));
  });
  return alerts;
}
