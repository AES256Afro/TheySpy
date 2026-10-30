// NetAlertX, both ways (docs/PLAN.md "Later"). NetAlertX keeps its own list of the network's devices,
// often with names, owners and types the owner typed there.
//  - From NetAlertX: its devices join the Fleet by MAC; its names become a name source (after your
//    Pi-hole labels), and its owner and type fill TheySpy's when those are empty.
//  - To NetAlertX: only fields that are empty there and that TheySpy knows (your label, owner, kind).
//    Never one the owner filled in NetAlertX. Nothing is written until the owner allows it, each run
//    is previewed first, and each write is one field through `update-column`: NetAlertX's
//    `POST /device/<mac>` replaces every field and resets the ones it is not given.

const unknownName = /^\s*$|^\((unknown|name not found)\)$/i;
const macPattern = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/;
const mac = (value) => String(value ?? "").trim().toLowerCase().replace(/-/g, ":");

/**
 * @param {{
 *   settings: ReturnType<typeof import("../db.mjs").createSettingsStore>,
 *   secretBox: ReturnType<typeof import("../secrets.mjs").createSecretBox>,
 *   fleet: ReturnType<typeof import("./registry.mjs").createFleet>,
 *   audit: ReturnType<typeof import("../audit.mjs").createAuditLog>,
 *   fetchImpl?: typeof fetch,
 *   now?: () => Date,
 * }} deps
 */
export function createNetAlertX({ settings, secretBox, fleet, audit, fetchImpl = fetch, now = () => new Date() }) {
  const stored = () => settings.get("netalertx") ?? {};
  const token = () => (stored().tokenSealed ? secretBox.open(stored().tokenSealed) : null);

  async function call(path, init = {}) {
    const s = stored();
    if (!s.url) throw Object.assign(new Error("NetAlertX is not connected yet."), { status: 409 });
    let response;
    try {
      response = await fetchImpl(`${s.url}${path}`, { ...init, headers: { authorization: `Bearer ${token() ?? ""}`, accept: "application/json", ...(init.body ? { "content-type": "application/json" } : {}) }, signal: AbortSignal.timeout(30_000) });
    } catch (error) {
      throw Object.assign(new Error(`Could not reach NetAlertX at ${s.url}: ${error.cause?.code ?? error.message}`), { status: 502 });
    }
    if (response.status === 403 || response.status === 401) throw Object.assign(new Error("NetAlertX refused the API token (Settings → API → API_TOKEN)."), { status: 502 });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || body.success === false) throw Object.assign(new Error(`NetAlertX: ${body.error ?? body.message ?? response.status}`), { status: 502 });
    return body;
  }
  const devices = async () => (await call("/devices")).devices ?? [];

  /** What TheySpy would fill in NetAlertX: empty there, known here. */
  function planFor(remote) {
    const byMac = new Map(fleet.list().filter((d) => d.mac).map((d) => [mac(d.mac), d]));
    const changes = [];
    for (const r of remote) {
      const local = byMac.get(mac(r.devMac));
      if (!local) continue;
      const fill = (column, current, value) => { if (value && (column === "devName" ? unknownName.test(current ?? "") : !String(current ?? "").trim())) changes.push({ mac: mac(r.devMac), device: local.name, column, from: current ?? "", to: value }); };
      fill("devName", r.devName, local.label);
      fill("devOwner", r.devOwner, local.owner);
      fill("devType", r.devType, local.kind);
    }
    return changes;
  }

  const api = {
    config() {
      const s = stored();
      return { configured: Boolean(s.url), url: s.url ?? null, hasToken: Boolean(s.tokenSealed), write: Boolean(s.write), lastSync: settings.get("netalertx_last_sync") ?? null };
    },
    /** @param {{ url?: string, token?: string, write?: boolean }} input @param {string} actor */
    configure(input, actor) {
      const next = { ...stored() };
      if (input.url !== undefined) {
        if (input.url === "") delete next.url;
        else {
          let u;
          try { u = new URL(String(input.url)); } catch { u = null; }
          if (!u || !["http:", "https:"].includes(u.protocol) || u.username || u.password) throw Object.assign(new Error("NetAlertX's API address must look like http://192.168.1.5:20212"), { status: 400 });
          next.url = u.origin;
        }
      }
      if (input.token !== undefined) next.tokenSealed = input.token ? secretBox.seal(String(input.token).slice(0, 500)) : undefined;
      if (input.write !== undefined) next.write = input.write === true;
      settings.set("netalertx", next);
      audit.record(actor, "netalertx.configured", null, { url: next.url ?? null, token: input.token === undefined ? undefined : "(changed)", write: next.write ?? false });
      return api.config();
    },
    async test() {
      return { devices: (await devices()).length };
    },

    /**
     * Brings NetAlertX's devices into the Fleet: new ones by MAC and address, names as a source,
     * owner and type where TheySpy has none. The first sync is an inventory (no new-device alerts).
     * @param {string} actor
     */
    async pull(actor = "system") {
      const remote = (await devices()).filter((r) => macPattern.test(mac(r.devMac)));
      const first = !settings.get("netalertx_last_sync");
      const seenAt = now().toISOString();
      const observed = remote.filter((r) => r.devLastIP || r.devPrimaryIPv4).map((r) => ({ ip: String(r.devPrimaryIPv4 || r.devLastIP), mac: mac(r.devMac), hostname: null, seenAt }));
      const created = observed.length ? fleet.observe(observed, "netalertx", first ? { inventory: true } : {}) : [];
      const byMac = new Map(fleet.list().filter((d) => d.mac).map((d) => [mac(d.mac), d]));
      let named = 0;
      let filled = 0;
      for (const r of remote) {
        const local = byMac.get(mac(r.devMac));
        if (!local) continue;
        const name = unknownName.test(r.devName ?? "") ? null : String(r.devName).trim().slice(0, 80);
        fleet.setNames(local.id, { netalertx: name });
        if (name) named += 1;
        if (fleet.fillEmpty(local.id, { owner: r.devOwner, kind: r.devType }, "netalertx")) filled += 1;
      }
      const result = { at: seenAt, devices: remote.length, added: created.length, named, filled, toFill: planFor(remote).length };
      settings.set("netalertx_last_sync", result);
      audit.record(actor, "netalertx.pulled", null, result);
      return result;
    },

    /** The fields TheySpy would fill in NetAlertX, for the owner to read before allowing it. */
    async preview() {
      return { changes: planFor(await devices()) };
    },

    /** Fills them, one field at a time; only with the owner's permission. @param {string} actor */
    async push(actor) {
      if (!stored().write) throw Object.assign(new Error("Writing to NetAlertX is turned off. Allow it first."), { status: 403 });
      const changes = planFor(await devices());
      const done = [];
      for (const c of changes) {
        await call(`/device/${encodeURIComponent(c.mac)}/update-column`, { method: "POST", body: JSON.stringify({ columnName: c.column, columnValue: c.to }) });
        done.push(c);
      }
      audit.record(actor, "netalertx.pushed", null, { fields: done.length, changes: done.slice(0, 50) });
      return { filled: done.length, changes: done };
    },
  };
  return api;
}
