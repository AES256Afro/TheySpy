import { inCidr, isRandomisedMac, normaliseMac } from "./addresses.mjs";
import { bestName, guessKind, networkOf } from "./explain.mjs";

// The device registry (docs/PLAN.md M4). Every source reports observations (an address seen at a
// time, with a MAC, name or vendor when it knows one); the registry merges them into devices by MAC.
// A device without a known MAC is keyed by its IP until a MAC for that IP turns up, then merged.

const onlineMinutes = 15;
const editable = ["label", "owner", "kind", "notes"];

/**
 * @typedef {{ ip: string, mac?: string | null, hostname?: string | null, vendor?: string | null, seenAt: string }} Observation
 */

/**
 * @param {{
 *   db: import("node:sqlite").DatabaseSync,
 *   audit: ReturnType<typeof import("../audit.mjs").createAuditLog>,
 *   now?: () => Date,
 *   vendorOf?: (mac: string | null) => string | null,
 *   gateway?: () => string | null,
 * }} deps
 */
export function createFleet({ db, audit, now = () => new Date(), vendorOf = () => null, gateway = () => null }) {
  const q = {
    count: db.prepare("SELECT COUNT(*) AS n FROM devices"),
    byId: db.prepare("SELECT * FROM devices WHERE id = ?"),
    byMac: db.prepare("SELECT * FROM devices WHERE mac = ?"),
    ipOnly: db.prepare("SELECT * FROM devices WHERE mac IS NULL AND ip = ?"),
    atIp: db.prepare("SELECT * FROM devices WHERE ip = ? ORDER BY last_seen DESC LIMIT 1"),
    all: db.prepare("SELECT d.*, (SELECT COUNT(*) FROM device_addresses a WHERE a.device_id = d.id) AS addresses FROM devices d ORDER BY d.last_seen DESC"),
    insert: db.prepare("INSERT INTO devices (mac, ip, hostname, vendor, acknowledged, sources, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
    update: db.prepare("UPDATE devices SET mac = ?, ip = ?, hostname = ?, vendor = ?, sources = ?, first_seen = ?, last_seen = ? WHERE id = ?"),
    address: db.prepare(`INSERT INTO device_addresses (device_id, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)
      ON CONFLICT (device_id, ip) DO UPDATE SET first_seen = MIN(first_seen, excluded.first_seen), last_seen = MAX(last_seen, excluded.last_seen)`),
    addresses: db.prepare("SELECT ip, first_seen, last_seen FROM device_addresses WHERE device_id = ? ORDER BY last_seen DESC"),
    moveAddresses: db.prepare(`INSERT INTO device_addresses (device_id, ip, first_seen, last_seen) SELECT ?, ip, first_seen, last_seen FROM device_addresses WHERE device_id = ?
      ON CONFLICT (device_id, ip) DO UPDATE SET first_seen = MIN(first_seen, excluded.first_seen), last_seen = MAX(last_seen, excluded.last_seen)`),
    moveEvents: db.prepare("UPDATE device_events SET device_id = ? WHERE device_id = ?"),
    remove: db.prepare("DELETE FROM devices WHERE id = ?"),
    event: db.prepare("INSERT INTO device_events (device_id, at, kind, detail) VALUES (?, ?, ?, ?)"),
    events: db.prepare("SELECT id, at, kind, detail FROM device_events WHERE device_id = ? ORDER BY at DESC, id DESC LIMIT ?"),
    recentEvents: db.prepare("SELECT e.id, e.device_id, e.at, e.kind, e.detail, d.label, d.hostname, d.ip, d.mac FROM device_events e JOIN devices d ON d.id = e.device_id ORDER BY e.at DESC, e.id DESC LIMIT ?"),
    edit: db.prepare("UPDATE devices SET label = ?, owner = ?, kind = ?, notes = ?, tags = ?, trusted = ?, acknowledged = ? WHERE id = ?"),
    names: db.prepare("UPDATE devices SET names = ? WHERE id = ?"),
    sources: db.prepare("UPDATE devices SET sources = ? WHERE id = ?"),
    trust: db.prepare("UPDATE devices SET trusted = 1 WHERE id = ?"),
    // A device seen before at this address (a phone's Tailscale address, after a merge).
    byAddress: db.prepare("SELECT d.* FROM device_addresses a JOIN devices d ON d.id = a.device_id WHERE a.ip = ? ORDER BY a.last_seen DESC LIMIT 1"),
    allAddresses: db.prepare("SELECT device_id, ip, last_seen FROM device_addresses ORDER BY last_seen DESC"),
  };

  const event = (deviceId, kind, detail = {}) => q.event.run(deviceId, now().toISOString(), kind, JSON.stringify(detail));
  const later = (a, b) => (a > b ? a : b);
  const earlier = (a, b) => (a < b ? a : b);

  /** The device's best name and where it came from, its network, and what it probably is. */
  function describe(r) {
    const names = JSON.parse(r.names ?? "{}");
    const best = bestName({ label: r.label, names, hostname: r.hostname, vendor: r.vendor, mac: r.mac, ip: r.ip });
    const guess = guessKind({ names: [r.label, names.pihole, names.router, names.tailscale, r.hostname], vendor: r.vendor, mac: r.mac });
    return { name: best.name, nameFrom: best.from, names, network: networkOf(r.ip, gateway(), r.mac), guess, inPihole: names.piholeClient === "listed" };
  }

  function present(row) {
    const r = /** @type {any} */ (row);
    const lastSeen = String(r.last_seen);
    return {
      id: Number(r.id), mac: r.mac, ip: r.ip, hostname: r.hostname, vendor: r.vendor,
      label: r.label, owner: r.owner, kind: r.kind, notes: r.notes, tags: JSON.parse(r.tags), trusted: Boolean(r.trusted),
      firstSeen: r.first_seen, lastSeen, sources: JSON.parse(r.sources), addresses: r.addresses === undefined ? undefined : Number(r.addresses),
      randomisedMac: isRandomisedMac(r.mac),
      online: now().getTime() - Date.parse(lastSeen) <= onlineMinutes * 60_000,
      isNew: !r.acknowledged,
      ...describe(r),
    };
  }

  /** Folds one device into another: addresses, events and anything the owner set. */
  function merge(from, into) {
    q.moveAddresses.run(into.id, from.id);
    q.moveEvents.run(into.id, from.id);
    const keep = (field) => into[field] ?? from[field];
    q.edit.run(keep("label"), keep("owner"), keep("kind"), keep("notes"), into.tags !== "[]" ? into.tags : from.tags, Math.max(into.trusted, from.trusted), Math.max(into.acknowledged, from.acknowledged), into.id);
    // What each source called it, and when each saw it: the device being kept wins on a clash.
    q.names.run(JSON.stringify({ ...JSON.parse(from.names ?? "{}"), ...JSON.parse(into.names ?? "{}") }), into.id);
    const sources = JSON.parse(into.sources ?? "{}");
    for (const [k, v] of Object.entries(JSON.parse(from.sources ?? "{}"))) sources[k] = later(sources[k] ?? "", v);
    q.sources.run(JSON.stringify(sources), into.id);
    q.remove.run(from.id);
    event(into.id, "merged", { ip: from.ip, firstSeen: from.first_seen });
    return /** @type {any} */ (q.byId.get(into.id));
  }

  const isTailnet = (ip) => Boolean(ip) && inCidr(ip, "100.64.0.0/10");
  const shortOf = (name) => (typeof name === "string" && name ? name.toLowerCase().replace(/\.$/, "").split(".")[0] : null);
  /** Names a device answers to, for telling two records of one device apart. */
  const namesOf = (r) => {
    const n = JSON.parse(r.names ?? "{}");
    return { tailscale: typeof n.tailscale === "string" ? n.tailscale.toLowerCase().replace(/\.$/, "") : null, given: [r.label, n.pihole, n.netalertx, shortOf(n.router), r.hostname && r.hostname !== "pi.hole" ? shortOf(r.hostname) : null].filter(Boolean).map((x) => String(x).toLowerCase()) };
  };
  // "iPhone 15", "ipad173", "Chris's iPad" → "iphone", "ipad", "chrissipad": close enough to ask, never to merge alone.
  const loose = (name) => String(name).toLowerCase().replace(/\.[a-z0-9-]+\.ts\.net$/, "").replace(/[^a-z]/g, "");
  const notSame = () => new Set((/** @type {string[]} */ (JSON.parse(/** @type {any} */ (db.prepare("SELECT value FROM settings WHERE key = 'fleet_not_same'").get())?.value ?? "[]"))));

  const fleet = {
    /** Whether nothing has been recorded yet: the next observations make the first inventory. */
    isEmpty: () => Number(/** @type {any} */ (q.count.get()).n) === 0,

    /**
     * Records what a source saw. Returns the devices it created. The first inventory (into an
     * empty registry, or as the caller says for a run that spans several sources) is not announced
     * device by device.
     * @param {Observation[]} observations @param {string} source @param {{ inventory?: boolean }} [options]
     */
    observe(observations, source, { inventory } = {}) {
      const initial = inventory ?? fleet.isEmpty();
      const created = [];
      db.exec("BEGIN");
      try {
        for (const o of observations) {
          if (!o.ip) continue;
          const mac = normaliseMac(o.mac);
          const seenAt = o.seenAt;
          let device = mac ? /** @type {any} */ (q.byMac.get(mac)) : null;
          const ipOnly = /** @type {any} */ (q.ipOnly.get(o.ip));
          if (mac && device && ipOnly && ipOnly.id !== device.id) device = merge(ipOnly, device);
          else if (mac && !device && ipOnly) device = ipOnly; // the IP-only device turns out to be this MAC
          else if (!mac && !device) device = ipOnly ?? /** @type {any} */ (q.atIp.get(o.ip)) ?? /** @type {any} */ (q.byAddress.get(o.ip)) ?? null;

          if (!device) {
            const info = q.insert.run(mac, o.ip, o.hostname || null, o.vendor || vendorOf(mac), initial ? 1 : 0, JSON.stringify({ [source]: seenAt }), seenAt, seenAt);
            const id = Number(info.lastInsertRowid);
            q.address.run(id, o.ip, seenAt, seenAt);
            event(id, initial ? "inventoried" : "new", { ip: o.ip, mac, source });
            created.push(id);
            continue;
          }
          const isLatest = seenAt >= device.last_seen;
          const hostname = o.hostname && o.hostname !== o.ip ? o.hostname : null;
          if (isLatest && device.mac && device.ip && device.ip !== o.ip && !(isTailnet(o.ip) && !isTailnet(device.ip))) event(device.id, "ip_changed", { from: device.ip, to: o.ip, source });
          if (isLatest && hostname && device.hostname && device.hostname !== hostname) event(device.id, "name_changed", { from: device.hostname, to: hostname, source });
          const sources = JSON.parse(device.sources);
          sources[source] = later(sources[source] ?? "", seenAt);
          // A device at home that is also reached over Tailscale keeps its home address as the main one.
          const keepHome = isTailnet(o.ip) && device.ip && !isTailnet(device.ip);
          q.update.run(device.mac ?? mac, isLatest && !keepHome ? o.ip : device.ip, (isLatest && hostname) || device.hostname || hostname, device.vendor || o.vendor || vendorOf(device.mac ?? mac),
            JSON.stringify(sources), earlier(device.first_seen, seenAt), later(device.last_seen, seenAt), device.id);
          q.address.run(device.id, o.ip, seenAt, seenAt);
        }
        db.exec("COMMIT");
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
      if (initial && created.length) audit.record("system", "fleet.inventoried", null, { devices: created.length, source });
      else for (const id of created) {
        const d = present(q.byId.get(id));
        audit.record("system", "fleet.new_device", d.mac ?? d.ip, { ip: d.ip, mac: d.mac, vendor: d.vendor, hostname: d.hostname, source });
      }
      return created;
    },

    list: () => {
      // Each device's addresses by network, so one device shows its home and its Tailscale address.
      const byDevice = new Map();
      for (const raw of q.allAddresses.all()) {
        const a = /** @type {any} */ (raw);
        if (!byDevice.has(a.device_id)) byDevice.set(a.device_id, []);
        byDevice.get(a.device_id).push(a.ip);
      }
      return q.all.all().map((row) => {
        const d = present(row);
        const ips = byDevice.get(d.id) ?? [];
        return { ...d, tailscaleIp: ips.find(isTailnet) ?? null, homeIp: d.ip && !isTailnet(d.ip) ? d.ip : ips.find((ip) => !isTailnet(ip)) ?? null };
      });
    },

    /**
     * Folds records of one device together where the names prove it: a Tailscale-only record whose
     * Tailscale name is another record's, or matches the name you gave it in Pi-hole, TheySpy,
     * NetAlertX or the router. Then marks devices in your tailnet or your Pi-hole client list as
     * yours, unless you said otherwise. Returns what it merged.
     * @param {string} actor
     */
    consolidate(actor = "system") {
      const merged = [];
      for (;;) {
        const rows = /** @type {any[]} */ (q.all.all());
        let pair = null;
        for (const t of rows.filter((r) => isTailnet(r.ip))) {
          const tn = namesOf(t);
          const tailShort = shortOf(tn.tailscale);
          const homes = rows.filter((r) => r.id !== t.id && r.ip && !isTailnet(r.ip));
          let match = tn.tailscale ? homes.filter((r) => namesOf(r).tailscale === tn.tailscale) : [];
          if (!match.length && tailShort) match = homes.filter((r) => namesOf(r).given.includes(tailShort));
          if (match.length === 1) { pair = [t, match[0]]; break; }
        }
        if (!pair) break;
        const [from, into] = pair;
        merge(from, into);
        merged.push({ from: from.ip, into: into.ip, name: shortOf(namesOf(from).tailscale) });
      }
      if (merged.length) audit.record(actor, "fleet.devices_merged", null, { merged });
      const trusted = [];
      const untrustedByOwner = new Set(JSON.parse(/** @type {any} */ (db.prepare("SELECT value FROM settings WHERE key = 'fleet_untrusted_by_owner'").get())?.value ?? "[]"));
      const autoTrust = JSON.parse(/** @type {any} */ (db.prepare("SELECT value FROM settings WHERE key = 'fleet_auto_trust'").get())?.value ?? "true");
      if (autoTrust) {
        for (const r of /** @type {any[]} */ (q.all.all())) {
          if (r.trusted || untrustedByOwner.has(r.id)) continue;
          const n = JSON.parse(r.names ?? "{}");
          const yours = n.piholeClient === "listed" || /\.ts\.net\.?$/i.test(String(n.tailscale ?? "")) || isTailnet(r.ip);
          if (yours) { q.trust.run(r.id); trusted.push(r.id); }
        }
        if (trusted.length) audit.record(actor, "fleet.trusted_as_yours", null, { devices: trusted.length });
      }
      return { merged, trusted: trusted.length };
    },

    /** Pairs that look like one device but are not certain: the owner merges or dismisses them. */
    suggestions() {
      const rows = fleet.list().filter((d) => d.network?.kind !== "docker");
      const skip = notSame();
      const out = [];
      // Names someone or something gave the device; never a guess like "Phone, tablet or laptop at …".
      const given = (d) => [d.label, d.hostname, d.names?.pihole, d.names?.netalertx, d.names?.router, d.names?.tailscale].filter((v) => typeof v === "string" && v).map(loose).filter((x) => x.length >= 4);
      for (let i = 0; i < rows.length; i += 1) {
        for (let j = i + 1; j < rows.length; j += 1) {
          const [a, b] = [rows[i], rows[j]];
          if (skip.has([a.id, b.id].sort((x, y) => x - y).join("-"))) continue;
          if (a.mac && b.mac && !a.randomisedMac && !b.randomisedMac) continue; // two real MACs are two devices
          const la = given(a);
          const lb = given(b);
          const close = la.some((x) => lb.some((y) => x === y || x.endsWith(y) || y.endsWith(x)));
          if (!close) continue;
          // Keep the record with a home address and a MAC; fold the other into it.
          const keep = (d) => (d.homeIp && !isTailnet(d.ip) ? 2 : 0) + (d.mac && !d.randomisedMac ? 1 : 0);
          const [into, from] = keep(a) >= keep(b) ? [a, b] : [b, a];
          out.push({ into: { id: into.id, name: into.name, ip: into.ip }, from: { id: from.id, name: from.name, ip: from.ip }, why: `${from.name} and ${into.name} have nearly the same name` });
        }
      }
      return out;
    },

    /** The owner says two records are one device. @param {number} fromId @param {number} intoId @param {string} actor */
    mergeDevices(fromId, intoId, actor) {
      const from = /** @type {any} */ (q.byId.get(fromId));
      const into = /** @type {any} */ (q.byId.get(intoId));
      if (!from || !into || fromId === intoId) throw Object.assign(new Error("Choose two different devices"), { status: 400 });
      db.exec("BEGIN");
      try { merge(from, into); db.exec("COMMIT"); } catch (error) { db.exec("ROLLBACK"); throw error; }
      audit.record(actor, "fleet.devices_merged", into.mac ?? into.ip, { merged: [{ from: from.ip, into: into.ip }], by: "owner" });
      return fleet.get(intoId);
    },

    /** The owner says two records that look alike are two devices; they are not suggested again. */
    notSame(aId, bId, actor) {
      const set = notSame();
      set.add([Number(aId), Number(bId)].sort((x, y) => x - y).join("-"));
      db.prepare("INSERT INTO settings (key, value, updated_at) VALUES ('fleet_not_same', ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").run(JSON.stringify([...set]), now().toISOString());
      audit.record(actor, "fleet.not_same", null, { devices: [Number(aId), Number(bId)] });
    },

    /**
     * Records names a source knows the device by ({ pihole: "iPhone" }); null removes one.
     * @param {number} id @param {Record<string, string | null>} patch
     */
    setNames(id, patch) {
      const row = /** @type {any} */ (q.byId.get(id));
      if (!row) return;
      const names = JSON.parse(row.names ?? "{}");
      for (const [k, v] of Object.entries(patch)) { if (v) names[k] = v; else delete names[k]; }
      q.names.run(JSON.stringify(names), id);
    },

    /** Address → best name, for every screen that shows addresses. */
    namesByIp() {
      const out = {};
      for (const d of fleet.list()) if (d.ip) out[d.ip] = { id: d.id, name: d.name, from: d.nameFrom, network: d.network?.label ?? null };
      return out;
    },
    get(id) {
      const row = q.byId.get(id);
      if (!row) return null;
      const history = q.addresses.all(id).map((a) => ({ ip: /** @type {any} */ (a).ip, firstSeen: /** @type {any} */ (a).first_seen, lastSeen: /** @type {any} */ (a).last_seen }));
      const d = present(row);
      return { ...d, tailscaleIp: history.find((a) => isTailnet(a.ip))?.ip ?? null, homeIp: d.ip && !isTailnet(d.ip) ? d.ip : history.find((a) => !isTailnet(a.ip))?.ip ?? null, addressHistory: history, events: fleet.events(id) };
    },
    events: (id, limit = 50) => q.events.all(id, limit).map((e) => ({ ...(/** @type {any} */ (e)), detail: JSON.parse(/** @type {any} */ (e).detail) })),
    recentEvents: (limit = 30) => q.recentEvents.all(limit).map((e) => {
      const r = /** @type {any} */ (e);
      return { id: r.id, deviceId: r.device_id, at: r.at, kind: r.kind, detail: JSON.parse(r.detail), device: r.label || r.hostname || r.ip || r.mac };
    }),

    /**
     * The owner's details for a device: label, owner, kind, notes, tags, trusted. Editing a new
     * device acknowledges it.
     * @param {number} id @param {Record<string, unknown>} input @param {string} actor
     */
    edit(id, input, actor) {
      const row = /** @type {any} */ (q.byId.get(id));
      if (!row) throw Object.assign(new Error("No such device"), { status: 404 });
      const next = { label: row.label, owner: row.owner, kind: row.kind, notes: row.notes };
      for (const field of editable) {
        if (input[field] === undefined) continue;
        const value = input[field] === null ? null : String(input[field]).trim().slice(0, field === "notes" ? 2000 : 80) || null;
        next[field] = value;
      }
      let tags = JSON.parse(row.tags);
      if (input.tags !== undefined) {
        if (!Array.isArray(input.tags)) throw Object.assign(new Error("tags must be a list"), { status: 400 });
        tags = [...new Set(input.tags.map((t) => String(t).trim().toLowerCase().slice(0, 30)).filter(Boolean))].slice(0, 12);
      }
      const trusted = input.trusted === undefined ? row.trusted : input.trusted ? 1 : 0;
      if (input.trusted !== undefined) {
        // An owner who says "not mine" is not overruled by the automatic trust of tailnet and Pi-hole devices.
        const was = new Set(JSON.parse(/** @type {any} */ (db.prepare("SELECT value FROM settings WHERE key = 'fleet_untrusted_by_owner'").get())?.value ?? "[]"));
        if (trusted) was.delete(id); else was.add(id);
        db.prepare("INSERT INTO settings (key, value, updated_at) VALUES ('fleet_untrusted_by_owner', ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").run(JSON.stringify([...was]), now().toISOString());
      }
      q.edit.run(next.label, next.owner, next.kind, next.notes, JSON.stringify(tags), trusted, 1, id);
      audit.record(actor, "fleet.device_edited", row.mac ?? row.ip, { id, ...input });
      return fleet.get(id);
    },

    /**
     * Fills a device's owner and kind from another tool (NetAlertX) where TheySpy has none. Unlike
     * an edit it neither overwrites nor acknowledges: a new device stays new until the owner looks.
     * @param {number} id @param {{ owner?: string | null, kind?: string | null }} values @param {string} source
     */
    fillEmpty(id, values, source) {
      const row = /** @type {any} */ (q.byId.get(id));
      if (!row) return false;
      const clean = (v) => (v ? String(v).trim().slice(0, 80) || null : null);
      const owner = row.owner ?? clean(values.owner);
      const kind = row.kind ?? clean(values.kind);
      if (owner === row.owner && kind === row.kind) return false;
      q.edit.run(row.label, owner, kind, row.notes, row.tags, row.trusted, row.acknowledged, id);
      audit.record(source, "fleet.device_filled", row.mac ?? row.ip, { id, owner: owner !== row.owner ? owner : undefined, kind: kind !== row.kind ? kind : undefined });
      return true;
    },

    /**
     * Trusts every device you already listed as a client in Pi-hole that is not trusted yet.
     * @param {string} actor
     */
    trustPiholeClients(actor) {
      const ids = fleet.list().filter((d) => d.inPihole && !d.trusted).map((d) => d.id);
      for (const id of ids) {
        const row = /** @type {any} */ (q.byId.get(id));
        q.edit.run(row.label, row.owner, row.kind, row.notes, row.tags, 1, 1, id);
      }
      if (ids.length) audit.record(actor, "fleet.trusted_pihole_clients", null, { count: ids.length, ids });
      return ids.length;
    },

    /** Forgets a device and its history (it reappears as new if it is seen again). */
    forget(id, actor) {
      const row = /** @type {any} */ (q.byId.get(id));
      if (!row) throw Object.assign(new Error("No such device"), { status: 404 });
      q.remove.run(id);
      audit.record(actor, "fleet.device_forgotten", row.mac ?? row.ip, { id });
    },
  };
  return fleet;
}
