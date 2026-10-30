import { isRandomisedMac, normaliseMac } from "./addresses.mjs";
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
    q.remove.run(from.id);
    event(into.id, "merged", { ip: from.ip, firstSeen: from.first_seen });
    return /** @type {any} */ (q.byId.get(into.id));
  }

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
          else if (!mac && !device) device = ipOnly ?? /** @type {any} */ (q.atIp.get(o.ip)) ?? null;

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
          if (isLatest && device.mac && device.ip && device.ip !== o.ip) event(device.id, "ip_changed", { from: device.ip, to: o.ip, source });
          if (isLatest && hostname && device.hostname && device.hostname !== hostname) event(device.id, "name_changed", { from: device.hostname, to: hostname, source });
          const sources = JSON.parse(device.sources);
          sources[source] = later(sources[source] ?? "", seenAt);
          q.update.run(device.mac ?? mac, isLatest ? o.ip : device.ip, (isLatest && hostname) || device.hostname || hostname, device.vendor || o.vendor || vendorOf(device.mac ?? mac),
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

    list: () => q.all.all().map(present),

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
      return { ...present(row), addressHistory: q.addresses.all(id).map((a) => ({ ip: /** @type {any} */ (a).ip, firstSeen: /** @type {any} */ (a).first_seen, lastSeen: /** @type {any} */ (a).last_seen })), events: fleet.events(id) };
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
