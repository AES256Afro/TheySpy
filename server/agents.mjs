import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { normaliseMac } from "./fleet/addresses.mjs";
import { defang } from "./iocs/parse.mjs";
import { parseChecksums, readPublicKey, verifyDetached } from "./iocs/openpgp.mjs";

// Endpoint agents and evidence (docs/PLAN.md M7).
//  - The agent (agent/theyspy-agent.py) enrolls once with a single-use token and gets its own key.
//  - It downloads zero-breach's scanner from TheySpy, checks its hash, runs it unmodified, adds the
//    OS and browser versions it can read, and posts a report signed with its key.
//  - Hits become "contacted" findings on the device; every check the scanner could not run becomes
//    a "gap", so a device is never shown clean for something nobody checked.
//  - Phones: MVT's results can be imported, and a manual profile records what a phone runs.

const vendored = (path) => readFileSync(new URL(`../third_party/zero-breach/${path}`, import.meta.url));
const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const hashToken = (token) => sha256(String(token));

/** zero-breach's scanner, checked against its signed SHA256SUMS before TheySpy hands it out. */
export function verifiedScanner() {
  const bytes = vendored("scan/zero-breach.py");
  const sums = vendored("release-signatures/v0.1.8/SHA256SUMS.txt");
  const signature = vendored("release-signatures/v0.1.8/SHA256SUMS.txt.asc").toString("utf8");
  const key = readPublicKey(vendored("release-signatures/v0.1.8/archivegenocide-signing-key.asc").toString("utf8"));
  if (!verifyDetached(sums, signature, key)) throw new Error("zero-breach's SHA256SUMS signature does not verify");
  const expected = parseChecksums(sums.toString("utf8")).get("zero-breach.py");
  const actual = sha256(bytes);
  if (expected !== actual) throw new Error(`zero-breach.py does not match its signed hash (${actual} != ${expected})`);
  return { bytes, sha256: actual, version: "0.1.8" };
}

/** Software names the agent and phone profiles report, as NVD's vendor:product. */
export const knownSoftware = Object.freeze({
  chrome: ["google", "chrome", "Google Chrome"], edge: ["microsoft", "edge_chromium", "Microsoft Edge"], firefox: ["mozilla", "firefox", "Firefox"],
  brave: ["brave", "brave", "Brave"], safari: ["apple", "safari", "Safari"], macos: ["apple", "macos", "macOS"], ios: ["apple", "iphone_os", "iOS"],
  ipados: ["apple", "ipados", "iPadOS"], android: ["google", "android", "Android"], windows: ["microsoft", "windows", "Windows"], openssh: ["openbsd", "openssh", "OpenSSH"],
});

/**
 * @param {{
 *   db: import("node:sqlite").DatabaseSync,
 *   fleet: ReturnType<typeof import("./fleet/registry.mjs").createFleet>,
 *   iocStore: ReturnType<typeof import("./iocs/store.mjs").createIocStore>,
 *   audit: ReturnType<typeof import("./audit.mjs").createAuditLog>,
 *   secretBox: ReturnType<typeof import("./secrets.mjs").createSecretBox>,
 *   now?: () => Date,
 * }} deps
 */
export function createAgents({ db, fleet, iocStore, audit, secretBox, now = () => new Date() }) {
  let scanner = null;
  const q = {
    addToken: db.prepare("INSERT INTO agent_tokens (hash, label, created_at, expires_at) VALUES (?, ?, ?, ?)"),
    token: db.prepare("SELECT * FROM agent_tokens WHERE hash = ?"),
    useToken: db.prepare("UPDATE agent_tokens SET used_at = ? WHERE hash = ? AND used_at IS NULL"),
    addAgent: db.prepare("INSERT INTO agents (device_id, name, platform, secret_sealed, enrolled_at) VALUES (?, ?, ?, ?, ?)"),
    agent: db.prepare("SELECT * FROM agents WHERE id = ?"),
    agents: db.prepare("SELECT a.*, d.label, d.hostname, d.ip FROM agents a LEFT JOIN devices d ON d.id = a.device_id ORDER BY a.id DESC"),
    reported: db.prepare("UPDATE agents SET last_report_at = ?, last_verdict = ?, device_id = COALESCE(?, device_id) WHERE id = ?"),
    revoke: db.prepare("UPDATE agents SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL"),
    addReport: db.prepare("INSERT INTO agent_reports (agent_id, at, verdict, report) VALUES (?, ?, ?, ?)"),
    dropGaps: db.prepare("DELETE FROM findings WHERE source_ref = ? AND kind = 'gap'"),
    contactExists: db.prepare("SELECT id FROM findings WHERE device_id IS ? AND source = ? AND kind = 'contacted' AND indicator = ? AND location IS ?"),
    addFinding: db.prepare("INSERT INTO findings (device_id, source, source_ref, kind, indicator, tier, confidence, location, detail, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
    findings: db.prepare("SELECT f.*, d.label, d.hostname, d.ip FROM findings f LEFT JOIN devices d ON d.id = f.device_id ORDER BY f.kind = 'gap', f.at DESC LIMIT 500"),
    finding: db.prepare("SELECT * FROM findings WHERE id = ?"),
    dismiss: db.prepare("UPDATE findings SET status = ?, note = ? WHERE id = ?"),
    dropInventory: db.prepare("DELETE FROM inventory_items WHERE device_id = ? AND source = ?"),
    addInventory: db.prepare(`INSERT INTO inventory_items (device_id, vendor, product, version, label, source, seen_at) VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (device_id, vendor, product, source) DO UPDATE SET version = excluded.version, label = excluded.label, seen_at = excluded.seen_at`),
    inventory: db.prepare("SELECT vendor, product, version, label, source, seen_at FROM inventory_items WHERE device_id = ? ORDER BY source, product"),
    profile: db.prepare("UPDATE devices SET profile = ? WHERE id = ?"),
    deviceProfile: db.prepare("SELECT profile FROM devices WHERE id = ?"),
  };

  const known = (key) => knownSoftware[String(key).toLowerCase()] ?? null;
  const cleanVersion = (v) => (v && /^[0-9][0-9A-Za-z.\-_+]{0,40}$/.test(String(v)) ? String(v) : null);

  /** Replaces what one source says a device runs. */
  function setInventory(deviceId, source, items) {
    const at = now().toISOString();
    q.dropInventory.run(deviceId, source);
    for (const item of items) {
      const k = known(item.software);
      if (!k) continue;
      q.addInventory.run(deviceId, k[0], k[1], cleanVersion(item.version), k[2], source, at);
    }
  }

  /** The device an agent or report belongs to: by MAC, then address; recorded if new. */
  function deviceFor({ macs = [], ip, hostname }) {
    const list = fleet.list();
    for (const m of macs.map(normaliseMac).filter(Boolean)) {
      const d = list.find((x) => x.mac === m);
      if (d) return d.id;
    }
    if (ip) {
      const d = list.find((x) => x.ip === ip);
      if (d) return d.id;
      fleet.observe([{ ip, mac: macs.map(normaliseMac).find(Boolean) ?? null, hostname: hostname ?? null, seenAt: now().toISOString() }], "agent");
      return fleet.list().find((x) => x.ip === ip)?.id ?? null;
    }
    return null;
  }

  const agents = {
    scanner() {
      scanner ??= verifiedScanner();
      return scanner;
    },
    /** The indicator file the scanner reads: TheySpy's active set, byte for byte as checked. */
    indicators() {
      const active = /** @type {any} */ (iocStore.active());
      const raw = active ? /** @type {any} */ (db.prepare("SELECT raw FROM ioc_versions WHERE id = ?").get(active.id))?.raw : null;
      return raw ?? vendored("iocs/adfection_iocs.txt").toString("utf8");
    },

    /** A single-use enrollment token, good for a day. @param {string} label @param {string} actor */
    createEnrollment(label, actor) {
      const token = `tse_${randomBytes(18).toString("base64url")}`;
      const expiresAt = new Date(now().getTime() + 86_400_000).toISOString();
      q.addToken.run(hashToken(token), String(label ?? "").slice(0, 60) || null, now().toISOString(), expiresAt);
      audit.record(actor, "agent.enrollment_created", null, { label });
      return { token, expiresAt };
    },

    /**
     * Swaps a token for an agent id and key. The key is returned once; TheySpy keeps it sealed.
     * @param {{ token: string, hostname?: string, platform?: string, macs?: string[] }} input @param {string | undefined} ip
     */
    enroll({ token, hostname, platform, macs = [] }, ip) {
      const row = /** @type {any} */ (q.token.get(hashToken(token)));
      if (!row || row.used_at || row.expires_at < now().toISOString()) throw Object.assign(new Error("That enrollment token is unknown, used or expired; create a new one in TheySpy"), { status: 403 });
      if (!Number(q.useToken.run(now().toISOString(), row.hash).changes)) throw Object.assign(new Error("That enrollment token was just used"), { status: 403 });
      const secret = randomBytes(32).toString("hex");
      const deviceId = deviceFor({ macs: Array.isArray(macs) ? macs.slice(0, 16) : [], ip, hostname });
      const name = String(hostname ?? row.label ?? "agent").slice(0, 80);
      const id = Number(q.addAgent.run(deviceId, name, String(platform ?? "").slice(0, 40) || null, secretBox.seal(secret), now().toISOString()).lastInsertRowid);
      audit.record("system", "agent.enrolled", String(id), { name, platform, deviceId });
      return { agentId: id, secret };
    },

    /**
     * Checks a report's signature: HMAC-SHA256 of "<timestamp>.<body>" under the agent's key, sent
     * within ten minutes, and newer than the agent's last report (no replays). Returns the agent.
     */
    authenticate(agentId, timestamp, signature, rawBody) {
      const agent = /** @type {any} */ (q.agent.get(Number(agentId)));
      if (!agent || agent.revoked_at) throw Object.assign(new Error("Unknown or revoked agent; enroll it again"), { status: 401 });
      const ts = Date.parse(String(timestamp));
      if (!Number.isFinite(ts) || Math.abs(now().getTime() - ts) > 600_000) throw Object.assign(new Error("The report's timestamp is not within ten minutes of TheySpy's clock"), { status: 401 });
      if (agent.last_report_at && new Date(ts).toISOString() <= agent.last_report_at) throw Object.assign(new Error("That report was already received"), { status: 409 });
      const expected = createHmac("sha256", secretBox.open(agent.secret_sealed)).update(`${timestamp}.`).update(rawBody).digest();
      const given = Buffer.from(String(signature ?? ""), "hex");
      if (given.length !== expected.length || !timingSafeEqual(given, expected)) throw Object.assign(new Error("The report's signature does not match"), { status: 401 });
      return agent;
    },

    /**
     * Takes in one agent report: the device seen, its software, and the scan's hits and gaps.
     * @param {any} agent @param {any} report @param {string} timestamp @param {string | undefined} ip
     */
    ingest(agent, report, timestamp, ip) {
      const at = new Date(Date.parse(timestamp)).toISOString();
      const deviceId = agent.device_id ?? deviceFor({ macs: report.macs ?? [], ip, hostname: report.hostname });
      if (deviceId && ip) {
        const d = fleet.get(deviceId);
        if (d) fleet.observe([{ ip, mac: d.mac ?? null, hostname: report.hostname ?? null, seenAt: at }], "agent");
      }
      if (deviceId) setInventory(deviceId, "agent", Array.isArray(report.inventory) ? report.inventory.slice(0, 100) : []);

      const ref = `agent:${agent.id}`;
      q.dropGaps.run(ref);
      const scan = report.scan ?? {};
      const zb = scan.report && typeof scan.report === "object" ? scan.report : null;
      const added = [];
      for (const [module, result] of Object.entries(zb?.modules ?? {})) {
        for (const hit of /** @type {any} */ (result)?.hits ?? []) {
          const indicator = String(hit.indicator ?? "").toLowerCase();
          if (!indicator) continue;
          if (q.contactExists.get(deviceId, "agent", indicator, hit.location ?? null)) continue;
          q.addFinding.run(deviceId, "agent", ref, "contacted", indicator, hit.tier ?? null, hit.confidence ?? null, hit.location ?? null, `${module}: ${String(hit.detail ?? "").slice(0, 400)}`, at);
          added.push(indicator);
        }
      }
      const gaps = [...(zb?.verdict?.gaps ?? [])];
      if (!zb) gaps.unshift(`The scan could not run${scan.error ? `: ${String(scan.error).slice(0, 300)}` : ""}. Nothing on this device was checked.`);
      for (const gap of gaps.slice(0, 40)) q.addFinding.run(deviceId, "agent", ref, "gap", null, null, null, null, String(gap).slice(0, 500), at);

      const verdict = { status: zb?.verdict?.status ?? "NOT_RUN", hits: zb?.verdict?.hits_total ?? 0, gaps: gaps.length, exitCode: scan.exitCode ?? null, scanner: zb?.tool?.version ?? null, at };
      q.reported.run(at, JSON.stringify(verdict), deviceId, agent.id);
      q.addReport.run(agent.id, at, verdict.status, JSON.stringify(report).slice(0, 500_000));
      audit.record("system", "agent.reported", String(agent.id), { verdict: verdict.status, hits: verdict.hits, gaps: verdict.gaps });
      if (added.length) audit.record("system", "agent.indicator_found", String(agent.id), { device: fleet.get(deviceId)?.name ?? report.hostname ?? null, indicators: [...new Set(added)].slice(0, 20) });
      return { verdict, findings: added.length, gaps: gaps.length, deviceId };
    },

    list: () => q.agents.all().map((raw) => {
      const r = /** @type {any} */ (raw);
      return { id: r.id, name: r.name, platform: r.platform, deviceId: r.device_id, device: r.label ?? r.hostname ?? r.ip ?? null, enrolledAt: r.enrolled_at, lastReportAt: r.last_report_at, verdict: r.last_verdict ? JSON.parse(r.last_verdict) : null, revoked: Boolean(r.revoked_at) };
    }),
    revoke(id, actor) {
      if (!Number(q.revoke.run(now().toISOString(), id).changes)) throw Object.assign(new Error("No such agent"), { status: 404 });
      audit.record(actor, "agent.revoked", String(id));
    },

    /** Findings, newest first, gaps after contacts; indicators defanged. */
    findings() {
      const names = fleet.namesByIp();
      return q.findings.all().map((raw) => {
        const r = /** @type {any} */ (raw);
        return { id: r.id, deviceId: r.device_id, device: (r.ip && names[r.ip]?.name) || r.label || r.hostname || r.ip || null, source: r.source, kind: r.kind, indicator: r.indicator ? defang(r.indicator) : null,
          tier: r.tier, confidence: r.confidence, location: r.location, detail: r.detail ? r.detail.replace(/https?:\/\/\S+/g, (u) => defang(u)) : null, at: r.at, status: r.status, note: r.note };
      });
    },
    setFindingStatus(id, status, note, actor) {
      if (!["open", "dismissed"].includes(status)) throw Object.assign(new Error("status must be open or dismissed"), { status: 400 });
      if (!Number(q.dismiss.run(status, note ? String(note).slice(0, 500) : null, id).changes)) throw Object.assign(new Error("No such finding"), { status: 404 });
      audit.record(actor, "evidence.finding_status", String(id), { status, note });
    },

    /** One finding as a STIX 2.1 bundle: the indicator and a sighting of it on the device. */
    stix(id) {
      const f = /** @type {any} */ (q.finding.get(id));
      if (!f || f.kind !== "contacted") throw Object.assign(new Error("No such finding"), { status: 404 });
      const stamp = new Date(f.at).toISOString();
      const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(f.indicator);
      const uuid = (seed) => { const h = sha256(seed); return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${((parseInt(h[16], 16) & 3) | 8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`; };
      const indicator = { type: "indicator", spec_version: "2.1", id: `indicator--${uuid(`indicator:${f.indicator}`)}`, created: stamp, modified: stamp, name: f.indicator,
        // STIX string literals escape \ and ' (a crafted MVT file must not widen the pattern).
        pattern: `[${isIp ? "ipv4-addr" : "domain-name"}:value = '${String(f.indicator).replace(/[\\']/g, "\\$&")}']`, pattern_type: "stix", valid_from: stamp, labels: ["malicious-activity"] };
      const sighting = { type: "sighting", spec_version: "2.1", id: `sighting--${uuid(`sighting:${f.id}`)}`, created: stamp, modified: stamp, first_seen: stamp, last_seen: stamp, count: 1,
        sighting_of_ref: indicator.id, description: `${{ mvt: "MVT", zeek: "Zeek", suricata: "Suricata" }[f.source] ?? "TheySpy agent"}: ${f.location ?? ""} ${f.detail ?? ""}`.trim() };
      return { type: "bundle", id: `bundle--${uuid(`bundle:${f.id}`)}`, objects: [indicator, sighting] };
    },

    /**
     * Takes MVT's results (its *_detected.json files) for a device: each matched indicator becomes
     * a "contacted" finding.
     * @param {number} deviceId @param {{ name: string, content: string }[]} files @param {string} actor
     */
    importMvt(deviceId, files, actor) {
      if (!fleet.get(deviceId)) throw Object.assign(new Error("No such device"), { status: 404 });
      const at = now().toISOString();
      let added = 0;
      const values = new Set();
      for (const file of files.slice(0, 50)) {
        let items;
        try { items = JSON.parse(String(file.content)); } catch { throw Object.assign(new Error(`${file.name} is not JSON`), { status: 400 }); }
        const module = String(file.name).replace(/\.json$/i, "").replace(/_detected$/i, "");
        for (const item of Array.isArray(items) ? items : []) {
          const matched = item?.matched_indicator;
          const value = String(matched?.value ?? matched ?? "").toLowerCase().replace(/\[\.\]/g, ".").slice(0, 253);
          if (!value) continue;
          if (q.contactExists.get(deviceId, "mvt", value, module)) continue;
          const detail = String(item.url ?? item.domain ?? item.name ?? item.path ?? "").slice(0, 300);
          q.addFinding.run(deviceId, "mvt", `mvt:${module}`, "contacted", value, null, null, module, detail || null, at);
          added += 1;
          values.add(value);
        }
      }
      audit.record(actor, "evidence.mvt_imported", String(deviceId), { files: files.length, findings: added });
      if (added) audit.record("system", "agent.indicator_found", String(deviceId), { device: fleet.get(deviceId)?.name ?? null, indicators: [...values].slice(0, 20), source: "mvt" });
      return { findings: added };
    },

    /**
     * A phone's (or any device's) manual profile: what it runs and whether its advertising ID is off.
     * @param {number} deviceId @param {{ os?: string, osVersion?: string, browser?: string, browserVersion?: string, adId?: string }} input @param {string} actor
     */
    setProfile(deviceId, input, actor) {
      if (!fleet.get(deviceId)) throw Object.assign(new Error("No such device"), { status: 404 });
      const profile = {
        os: known(input.os) ? String(input.os).toLowerCase() : null, osVersion: cleanVersion(input.osVersion),
        browser: known(input.browser) ? String(input.browser).toLowerCase() : null, browserVersion: cleanVersion(input.browserVersion),
        adId: ["off", "on", "unknown"].includes(String(input.adId)) ? String(input.adId) : "unknown",
        at: now().toISOString(),
      };
      q.profile.run(JSON.stringify({ ...profile, observed: agents.profile(deviceId).observed }), deviceId);
      setInventory(deviceId, "manual", [profile.os && { software: profile.os, version: profile.osVersion }, profile.browser && { software: profile.browser, version: profile.browserVersion }].filter(Boolean));
      audit.record(actor, "evidence.profile_set", String(deviceId), profile);
      return profile;
    },
    profile: (deviceId) => JSON.parse(/** @type {any} */ (q.deviceProfile.get(deviceId))?.profile ?? "{}"),
    /** What This device last saw on a device (GPC, ad blocking, DNS through Pi-hole), kept beside its profile. */
    observe(deviceId, observed) {
      const profile = agents.profile(deviceId);
      q.profile.run(JSON.stringify({ ...profile, observed }), deviceId);
    },
    /** The agent's last report time and verdict for a device, if it has one. */
    agentFor(deviceId) {
      return agents.list().filter((a) => a.deviceId === deviceId && !a.revoked).sort((a, b) => String(b.lastReportAt).localeCompare(String(a.lastReportAt)))[0] ?? null;
    },
    /** Open contacted findings per device. */
    contactsFor(deviceId) {
      return agents.findings().filter((f) => f.deviceId === deviceId && f.kind === "contacted" && f.status === "open");
    },
    inventory: (deviceId) => q.inventory.all(deviceId).map((r) => ({ .../** @type {any} */ (r) })),
  };
  return agents;
}
