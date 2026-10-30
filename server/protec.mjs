// Protec (the owner's endpoint inventory, docs/PLAN.md "Later"): each enrolled machine's installed
// packages - dpkg on Linux, Homebrew on macOS - feed TheySpy's per-device CVE matching. TheySpy reads
// with a Protec viewer credential (Access → issue credential, role viewer, at most 720 hours), so it
// can see the inventory and change nothing in Protec.
//
// Protec reports a hostname, not an address or MAC, so its machines are matched to Fleet devices by
// name; one it cannot match is listed for the owner to link by hand.
//
// Debian and Ubuntu fix security bugs without changing the upstream version (openssh 9.2p1 stays
// 9.2p1 after a patched build), so a CVE matched from a dpkg version may already be fixed there; the
// screen says so. Homebrew installs upstream versions, so those matches are exact.

/** Package names (dpkg and Homebrew) → TheySpy's software keys (agents.mjs knownSoftware). */
const packageSoftware = {
  "openssh-client": "openssh", "openssh-server": "openssh", openssh: "openssh",
  openssl: "openssl", libssl3: "openssl", "openssl@3": "openssl",
  curl: "curl", libcurl4: "curl", sudo: "sudo", bash: "bash", libc6: "glibc",
  firefox: "firefox", "firefox-esr": "firefox", "xz-utils": "xz", xz: "xz", git: "git",
  nodejs: "nodejs", node: "nodejs", samba: "samba", exim4: "exim", "exim4-base": "exim",
  "postgresql-15": "postgresql", "postgresql-16": "postgresql", "postgresql-17": "postgresql", postgresql: "postgresql", "postgresql@16": "postgresql", "postgresql@17": "postgresql",
};

/**
 * The upstream version in a package version: Debian's epoch ("1:"), revision ("-2+deb12u10") and
 * repack suffixes ("+dfsg", "~"), or Homebrew's rebuild ("_1"), taken off.
 * @param {string} version @param {string} manager
 */
export function upstreamVersion(version, manager) {
  let v = String(version ?? "").trim();
  if (manager === "dpkg") {
    v = v.replace(/^\d+:/, "");
    const dash = v.lastIndexOf("-");
    if (dash > 0) v = v.slice(0, dash);
    v = v.replace(/[+~].*$/, "");
  } else {
    v = v.replace(/_\d+$/, "");
  }
  return /^[0-9][0-9A-Za-z.]{0,30}$/.test(v) ? v : null;
}

/**
 * A machine's packages as TheySpy inventory items, the ones it can match to NVD.
 * @param {{ manager?: string, items?: { name: string, version: string }[] }} packages
 */
export function inventoryFrom(packages) {
  const manager = String(packages?.manager ?? "");
  const out = new Map();
  for (const p of Array.isArray(packages?.items) ? packages.items : []) {
    // Multi-arch libraries carry their architecture: "libc6:arm64", "libssl3:amd64".
    const name = String(p?.name ?? "").toLowerCase().replace(/:[a-z0-9]+$/, "");
    // python3.11 and the like: the version is in the package and in its version.
    const software = packageSoftware[name] ?? (/^python3\.\d+$/.test(name) ? "python" : null);
    const version = software ? upstreamVersion(p.version, manager) : null;
    if (software && version && !out.has(software)) out.set(software, { software, version });
  }
  return [...out.values()];
}

const shortName = (name) => String(name ?? "").toLowerCase().replace(/\.$/, "").split(".")[0];

/**
 * @param {{
 *   settings: ReturnType<typeof import("./db.mjs").createSettingsStore>,
 *   secretBox: ReturnType<typeof import("./secrets.mjs").createSecretBox>,
 *   fleet: ReturnType<typeof import("./fleet/registry.mjs").createFleet>,
 *   agents: ReturnType<typeof import("./agents.mjs").createAgents>,
 *   audit: ReturnType<typeof import("./audit.mjs").createAuditLog>,
 *   fetchImpl?: typeof fetch,
 *   now?: () => Date,
 * }} deps
 */
export function createProtec({ settings, secretBox, fleet, agents, audit, fetchImpl = fetch, now = () => new Date() }) {
  const stored = () => settings.get("protec") ?? {};
  const links = () => /** @type {Record<string, number>} */ (stored().links ?? {});

  /** The Fleet device a Protec machine is: linked by the owner, or the one with its hostname. */
  function deviceFor(machine) {
    const linked = links()[machine.id];
    if (linked && fleet.get(linked)) return linked;
    const name = shortName(machine.inventory?.hostname);
    if (!name) return null;
    const matches = fleet.list().filter((d) => [d.hostname, d.label, d.name, ...Object.values(d.names ?? {})].some((n) => typeof n === "string" && shortName(n) === name));
    return matches.length === 1 ? matches[0].id : null;
  }

  const api = {
    config() {
      const s = stored();
      return { configured: Boolean(s.url), url: s.url ?? null, hasToken: Boolean(s.tokenSealed), lastSync: settings.get("protec_last_sync") ?? null };
    },
    /** @param {{ url?: string, token?: string }} input @param {string} actor */
    configure(input, actor) {
      const next = { ...stored() };
      if (input.url !== undefined) {
        if (input.url === "") delete next.url;
        else {
          let u;
          try { u = new URL(String(input.url)); } catch { u = null; }
          if (!u || !["http:", "https:"].includes(u.protocol) || u.username || u.password) throw Object.assign(new Error("Protec's address must look like https://protec.example.ts.net:8765"), { status: 400 });
          next.url = u.origin;
        }
      }
      if (input.token !== undefined) next.tokenSealed = input.token ? secretBox.seal(String(input.token).slice(0, 500)) : undefined;
      settings.set("protec", next);
      audit.record(actor, "protec.configured", null, { url: next.url ?? null, token: input.token === undefined ? undefined : "(changed)" });
      return api.config();
    },
    /** The owner links a Protec machine TheySpy could not match to a Fleet device. */
    link(machineId, deviceId, actor) {
      if (!fleet.get(Number(deviceId))) throw Object.assign(new Error("No such device"), { status: 404 });
      settings.set("protec", { ...stored(), links: { ...links(), [String(machineId)]: Number(deviceId) } });
      audit.record(actor, "protec.linked", String(machineId), { deviceId: Number(deviceId) });
    },

    /** Reads Protec's inventory and gives each matched device its packages. @param {string} actor */
    async sync(actor = "system") {
      const s = stored();
      if (!s.url) throw Object.assign(new Error("Protec is not connected yet."), { status: 409 });
      let response;
      try {
        response = await fetchImpl(`${s.url}/api/dashboard`, { headers: { authorization: `Bearer ${secretBox.open(s.tokenSealed) ?? ""}`, accept: "application/json" }, signal: AbortSignal.timeout(30_000) });
      } catch (error) {
        throw Object.assign(new Error(`Could not reach Protec at ${s.url}: ${error.cause?.code ?? error.cause?.message ?? error.message}`), { status: 502 });
      }
      if (response.status === 401) throw Object.assign(new Error("Protec refused the credential; it may have expired (at most 720 hours). Issue a new viewer credential in Protec → Access."), { status: 502 });
      if (response.status === 403) throw Object.assign(new Error("That Protec credential cannot read the inventory; issue one with the viewer role."), { status: 502 });
      if (!response.ok) throw Object.assign(new Error(`Protec answered ${response.status}`), { status: 502 });
      const body = /** @type {any} */ (await response.json());
      const machines = (Array.isArray(body.devices) ? body.devices : []).filter((m) => !m.revoked);
      const result = { at: now().toISOString(), machines: machines.length, matched: 0, packages: 0, unmatched: /** @type {any[]} */ ([]) };
      for (const m of machines) {
        const deviceId = deviceFor(m);
        const items = inventoryFrom(m.inventory?.packages);
        if (!deviceId) { result.unmatched.push({ id: String(m.id), hostname: String(m.inventory?.hostname ?? "").slice(0, 80), os: String(m.inventory?.os ?? "").slice(0, 40), packages: items.length }); continue; }
        agents.reportInventory(deviceId, m.inventory?.packages?.manager === "dpkg" ? "protec-dpkg" : "protec", items);
        result.matched += 1;
        result.packages += items.length;
      }
      settings.set("protec_last_sync", result);
      audit.record(actor, "protec.synced", null, { machines: result.machines, matched: result.matched, packages: result.packages, unmatched: result.unmatched.length });
      return result;
    },
  };
  return api;
}
