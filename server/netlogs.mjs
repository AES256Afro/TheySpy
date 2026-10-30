import { createMatcher } from "./pihole/match.mjs";

// Network logs from Zeek or Suricata (docs/PLAN.md "Later"): what the owner's sensor saw on the
// wire, imported in the Evidence locker. Every name a device looked up, every TLS server name and
// every HTTP host is checked against the indicator set; a match is a "contacted" finding on that
// device, as from the agent. TLS client fingerprints (JA4) are kept per device: the first import
// is a device's baseline, and a fingerprint it never showed before is flagged afterwards - new
// software speaking TLS, which is what an implant does.
//
// Formats, as the tools write them (checked against real Suricata 8 and Zeek 9 output):
//  - Zeek ASCII logs (#separator, #path dns|ssl|http, #fields ... ts id.orig_h query|server_name|host)
//  - Zeek JSON logs (one object a line, the same field names)
//  - Suricata eve.json (event_type dns with queries[].rrname (v3) or rrname (v1/v2), tls with sni
//    and ja4, http with hostname; requests only, so the device is src_ip)
// Zeek writes ja4 into ssl.log only with FoxIO's JA4 package; it is read when present.

const maxEvents = 2_000_000;

/** @typedef {{ at: string, client: string, kind: "dns" | "tls" | "http", name: string | null, ja4: string | null }} NetEvent */

const zeekTime = (ts) => { const n = Number(ts); return Number.isFinite(n) ? new Date(n * 1000).toISOString() : null; };
const clean = (value) => (value === undefined || value === null || value === "-" || value === "(empty)" ? null : String(value).toLowerCase().replace(/\.$/, ""));
const ja4Pattern = /^[tqd]\d{2}[di]\d{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/i;
const ja4Of = (value) => (typeof value === "string" && ja4Pattern.test(value) ? value.toLowerCase() : null);

/** One Zeek record (TSV row or JSON object) of a known log, as events. @returns {NetEvent[]} */
function fromZeek(path, r) {
  const at = zeekTime(r.ts);
  const client = r["id.orig_h"] ?? r.id?.orig_h;
  if (!at || !client) return [];
  if (path === "dns" && clean(r.query)) return [{ at, client, kind: "dns", name: clean(r.query), ja4: null }];
  if (path === "ssl") return [{ at, client, kind: "tls", name: clean(r.server_name), ja4: ja4Of(r.ja4) }];
  if (path === "http" && clean(r.host)) return [{ at, client, kind: "http", name: clean(r.host)?.replace(/:\d+$/, "") ?? null, ja4: null }];
  return [];
}

/** One Suricata eve.json record, as events. @returns {NetEvent[]} */
function fromEve(e) {
  const at = e.timestamp ? new Date(e.timestamp).toISOString() : null;
  const client = e.src_ip;
  if (!at || !client || Number.isNaN(Date.parse(at))) return [];
  if (e.event_type === "dns" && e.dns) {
    const d = e.dns;
    if (!["request", "query"].includes(d.type)) return [];
    const names = Array.isArray(d.queries) ? d.queries.map((q) => q.rrname) : [d.rrname];
    return names.map(clean).filter(Boolean).map((name) => ({ at, client, kind: "dns", name, ja4: null }));
  }
  if (e.event_type === "tls" && e.tls) return [{ at, client, kind: "tls", name: clean(e.tls.sni), ja4: ja4Of(e.tls.ja4) }];
  if (e.event_type === "http" && e.http?.hostname) return [{ at, client, kind: "http", name: clean(e.http.hostname), ja4: null }];
  return [];
}

/**
 * Reads one log file, whatever its format, as events.
 * @param {string} name @param {string} text
 * @returns {{ tool: "zeek" | "suricata", log: string, events: NetEvent[] }}
 */
export function parseNetworkLog(name, text) {
  const lines = String(text).split(/\r?\n/);
  const events = [];
  if (lines.some((line) => line.startsWith("#fields"))) {
    // Zeek ASCII: the header names the log and its columns.
    const separator = /^#separator (.+)$/m.exec(text)?.[1]?.replace(/\\x([0-9a-f]{2})/gi, (_m, h) => String.fromCharCode(Number.parseInt(h, 16))) ?? "\t";
    const path = /^#path\s+(\S+)/m.exec(text)?.[1] ?? name.replace(/\..*$/, "");
    let fields = [];
    for (const line of lines) {
      if (line.startsWith("#fields")) { fields = line.split(separator).slice(1); continue; }
      if (!line || line.startsWith("#")) continue;
      const values = line.split(separator);
      events.push(...fromZeek(path, Object.fromEntries(fields.map((f, i) => [f, values[i]]))));
      if (events.length > maxEvents) break;
    }
    return { tool: "zeek", log: path, events };
  }
  let tool = null;
  let log = null;
  for (const line of lines) {
    if (!line.trim()) continue;
    let record;
    try { record = JSON.parse(line); } catch { continue; }
    if (!record || typeof record !== "object") continue;
    if (record.event_type) { tool = "suricata"; log = "eve"; events.push(...fromEve(record)); }
    else {
      const path = record.query !== undefined ? "dns" : record.server_name !== undefined || record.ssl_history !== undefined ? "ssl" : record.method !== undefined && record.host !== undefined ? "http" : null;
      if (path) { tool = "zeek"; log = path; events.push(...fromZeek(path, record)); }
    }
    if (events.length > maxEvents) break;
  }
  if (!tool) throw Object.assign(new Error(`${name} is not a Zeek dns, ssl or http log, nor a Suricata eve.json`), { status: 400 });
  return { tool, log, events };
}

/**
 * @param {{
 *   db: import("node:sqlite").DatabaseSync,
 *   fleet: ReturnType<typeof import("./fleet/registry.mjs").createFleet>,
 *   iocStore: ReturnType<typeof import("./iocs/store.mjs").createIocStore>,
 *   audit: ReturnType<typeof import("./audit.mjs").createAuditLog>,
 *   now?: () => Date,
 * }} deps
 */
export function createNetworkLogs({ db, fleet, iocStore, audit, now = () => new Date() }) {
  const q = {
    contactExists: db.prepare("SELECT 1 FROM findings WHERE source = ? AND kind = 'contacted' AND indicator = ? AND location = ? AND COALESCE(device_id, -1) = COALESCE(?, -1) AND status = 'open'"),
    addFinding: db.prepare("INSERT INTO findings (device_id, source, source_ref, kind, indicator, tier, confidence, location, detail, at) VALUES (?, ?, ?, 'contacted', ?, ?, ?, ?, ?, ?)"),
    clientKnown: db.prepare("SELECT 1 FROM ja4_fingerprints WHERE client_ip = ? LIMIT 1"),
    fingerprint: db.prepare("SELECT * FROM ja4_fingerprints WHERE client_ip = ? AND ja4 = ?"),
    addFingerprint: db.prepare("INSERT INTO ja4_fingerprints (client_ip, ja4, first_seen, last_seen, count, sni, source, is_new) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
    seeFingerprint: db.prepare("UPDATE ja4_fingerprints SET first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?), count = count + ?, sni = COALESCE(sni, ?) WHERE client_ip = ? AND ja4 = ?"),
    fingerprints: db.prepare("SELECT * FROM ja4_fingerprints ORDER BY is_new DESC, last_seen DESC LIMIT 500"),
    acknowledge: db.prepare("UPDATE ja4_fingerprints SET is_new = 0 WHERE client_ip = ? AND ja4 = ?"),
  };
  const deviceOf = () => {
    const byIp = new Map(fleet.list().map((d) => [d.ip, d]));
    return (ip) => byIp.get(ip) ?? null;
  };

  return {
    /**
     * Imports Zeek or Suricata logs: indicator contacts become findings, TLS fingerprints are kept.
     * @param {{ name: string, content: string }[]} files @param {string} actor
     */
    importLogs(files, actor) {
      const set = iocStore.activeSet();
      if (!set) throw Object.assign(new Error("No indicator set is active."), { status: 409 });
      const matcher = createMatcher(set);
      const device = deviceOf();
      const at = now().toISOString();
      let events = 0;
      let added = 0;
      const indicators = new Set();
      const byTool = {};
      // Fingerprints per client in this import, so a client's first import is its baseline as a whole.
      /** @type {Map<string, Map<string, { first: string, last: string, count: number, sni: string | null, tool: string }>>} */
      const seen = new Map();
      for (const file of files.slice(0, 20)) {
        const parsed = parseNetworkLog(String(file.name ?? "log"), String(file.content ?? ""));
        byTool[`${parsed.tool} ${parsed.log}`] = (byTool[`${parsed.tool} ${parsed.log}`] ?? 0) + parsed.events.length;
        events += parsed.events.length;
        for (const e of parsed.events) {
          if (e.ja4) {
            if (!seen.has(e.client)) seen.set(e.client, new Map());
            const f = seen.get(e.client).get(e.ja4) ?? { first: e.at, last: e.at, count: 0, sni: e.name, tool: parsed.tool };
            f.count += 1; if (e.at < f.first) f.first = e.at; if (e.at > f.last) f.last = e.at; f.sni ??= e.name;
            seen.get(e.client).set(e.ja4, f);
          }
          const ind = e.name ? matcher.match(e.name) : null;
          if (!ind) continue;
          const d = device(e.client);
          const location = `${parsed.tool} ${e.kind}`;
          if (q.contactExists.get(parsed.tool, ind.value, location, d?.id ?? null)) continue;
          q.addFinding.run(d?.id ?? null, parsed.tool, `${parsed.tool}:${file.name}`, ind.value, ind.tier ?? null, ind.confidence ?? null, location,
            `${e.client}${d ? ` (${d.name})` : ""} ${e.kind === "dns" ? "looked up" : e.kind === "tls" ? "opened TLS to" : "asked HTTP for"} ${e.name} at ${e.at}${e.ja4 ? `; JA4 ${e.ja4}` : ""}`.slice(0, 300), at);
          added += 1;
          indicators.add(ind.value);
        }
      }
      const fresh = [];
      for (const [client, prints] of seen) {
        const baseline = !q.clientKnown.get(client);
        for (const [ja4, f] of prints) {
          if (q.fingerprint.get(client, ja4)) { q.seeFingerprint.run(f.first, f.last, f.count, f.sni, client, ja4); continue; }
          q.addFingerprint.run(client, ja4, f.first, f.last, f.count, f.sni, f.tool, baseline ? 0 : 1);
          if (!baseline) fresh.push({ client, device: device(client)?.name ?? null, ja4, sni: f.sni });
        }
      }
      audit.record(actor, "evidence.network_logs_imported", null, { files: files.length, events, findings: added, newFingerprints: fresh.length });
      if (added) audit.record("system", "agent.indicator_found", null, { indicators: [...indicators].slice(0, 20), source: "network logs" });
      if (fresh.length) audit.record("system", "evidence.ja4_new", null, { fingerprints: fresh.slice(0, 20) });
      return { events, byTool, findings: added, fingerprints: [...seen.values()].reduce((n, m) => n + m.size, 0), newFingerprints: fresh };
    },

    /** TLS client fingerprints by device, new ones first. */
    fingerprints() {
      const device = deviceOf();
      return q.fingerprints.all().map((raw) => {
        const r = /** @type {any} */ (raw);
        return { client: r.client_ip, device: device(r.client_ip)?.name ?? null, ja4: r.ja4, firstSeen: r.first_seen, lastSeen: r.last_seen, count: r.count, sni: r.sni, source: r.source, isNew: Boolean(r.is_new) };
      });
    },

    /** The owner knows this one (a new browser, an update): it stops being flagged. */
    acknowledge(client, ja4, actor) {
      q.acknowledge.run(String(client), String(ja4));
      audit.record(actor, "evidence.ja4_acknowledged", String(client), { ja4: String(ja4) });
    },
  };
}
