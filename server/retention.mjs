// Retention (docs/PLAN.md M35). The event tables grow for ever and nothing said how big the
// database was. BigBox after nine days: 204 MB, of which 134 MB was the CVE mirror (108,078 CVEs
// back to 1997, kept because an old router has old CVEs) and 32 MB the blocklist versions (which
// keep the last two already); the tables trimmed here held a few hundred rows between them. So the
// policy is for the long run, the card on Activity is for today, and the mirror is said to be bounded.

/** Days kept, by what is kept. The owner changes these on Activity. */
export const defaultPolicy = Object.freeze({
  hits: 365,      // ioc_hit_events: lookups of indicator addresses, the evidence a hunt found
  audit: 90,      // audit_log
  jobs: 90,       // jobs that have finished (a queued or running one is never touched)
  checks: 365,    // targeted checks that have finished
  events: 365,    // device_events and cve_events: what changed, shown on the device and CVE pages
  reports: 90,    // agent_reports, keeping each agent's latest whatever its age
});

export const policyLimits = Object.freeze({ min: 7, max: 3650 });

/** What each kept thing is, for the card. */
export const policyLabels = Object.freeze({
  hits: "Lookups of indicator addresses",
  audit: "The audit log",
  jobs: "Finished jobs",
  checks: "Finished targeted checks",
  events: "Device and CVE events",
  reports: "Agent reports (each agent's latest is kept)",
});

const day = 86_400_000;

/**
 * @param {{ db: import("node:sqlite").DatabaseSync, settings: ReturnType<typeof import("./db.mjs").createSettingsStore>, audit: ReturnType<typeof import("./audit.mjs").createAuditLog>, now?: () => Date }} deps
 */
export function createRetention({ db, settings, audit, now = () => new Date() }) {
  const q = {
    hits: db.prepare("DELETE FROM ioc_hit_events WHERE at < ?"),
    audit: db.prepare("DELETE FROM audit_log WHERE at < ?"),
    jobs: db.prepare("DELETE FROM jobs WHERE created_at < ? AND status IN ('succeeded', 'failed', 'interrupted')"),
    checks: db.prepare("DELETE FROM checks WHERE started_at < ? AND finished_at IS NOT NULL"),
    deviceEvents: db.prepare("DELETE FROM device_events WHERE at < ?"),
    cveEvents: db.prepare("DELETE FROM cve_events WHERE at < ?"),
    reports: db.prepare("DELETE FROM agent_reports WHERE at < ? AND id NOT IN (SELECT MAX(id) FROM agent_reports GROUP BY agent_id)"),
    pages: db.prepare("SELECT page_count * page_size AS bytes, freelist_count * page_size AS free FROM pragma_page_count, pragma_page_size, pragma_freelist_count"),
    tables: db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"),
  };

  function policy() {
    const stored = settings.get("retention");
    const result = { ...defaultPolicy };
    for (const key of Object.keys(defaultPolicy)) {
      const value = stored && typeof stored === "object" ? stored[key] : undefined;
      if (Number.isInteger(value) && value >= policyLimits.min && value <= policyLimits.max) result[key] = value;
    }
    return result;
  }

  /** Bytes per table, when this SQLite was built with the dbstat table (Node's is); rows always. */
  function tables() {
    /** @type {Map<string, number>} */ const bytes = new Map();
    try {
      for (const row of db.prepare("SELECT name, SUM(pgsize) AS bytes FROM dbstat GROUP BY name").all()) bytes.set(String(/** @type {any} */ (row).name), Number(/** @type {any} */ (row).bytes));
    } catch { /* no dbstat in this build: rows only */ }
    return q.tables.all().map((row) => {
      const name = String(/** @type {any} */ (row).name);
      const rows = Number(/** @type {any} */ (db.prepare(`SELECT COUNT(*) AS n FROM "${name.replaceAll('"', '""')}"`).get()).n);
      // A table's indexes are its weight too: dbstat lists them under their own names.
      let size = bytes.has(name) ? /** @type {number} */ (bytes.get(name)) : null;
      if (size !== null) for (const [other, b] of bytes) if (other !== name && (other.startsWith(`${name}_`) || other === `sqlite_autoindex_${name}_1`)) size += b;
      return { name, rows, bytes: size };
    }).sort((a, b) => (b.bytes ?? 0) - (a.bytes ?? 0) || b.rows - a.rows);
  }

  return {
    policy,
    policyLabels,
    policyLimits,
    /**
     * The owner's new policy: whole days between the limits, each named when refused.
     * @param {unknown} input @param {string} actor
     */
    configure(input, actor) {
      const body = input && typeof input === "object" ? /** @type {Record<string, unknown>} */ (input) : {};
      const next = { ...policy() };
      for (const key of Object.keys(defaultPolicy)) {
        if (body[key] === undefined) continue;
        const raw = body[key];
        const value = typeof raw === "string" && /^\d{1,5}$/.test(raw) ? Number(raw) : typeof raw === "number" ? raw : Number.NaN;
        if (!Number.isInteger(value) || value < policyLimits.min || value > policyLimits.max) throw Object.assign(new Error(`${policyLabels[key]}: between ${policyLimits.min} and ${policyLimits.max} days`), { status: 400 });
        next[key] = value;
      }
      settings.set("retention", next);
      audit.record(actor, "retention.saved", null, next);
      return next;
    },
    /** The file's size, what is free inside it, the tables by weight, and the last trim. */
    size() {
      const pages = /** @type {any} */ (q.pages.get());
      return { bytes: Number(pages.bytes), free: Number(pages.free), tables: tables(), lastTrim: settings.get("retention_last") ?? null };
    },
    /**
     * Removes what the policy says has aged out, then compacts the file when a tenth of it is free.
     * Nothing queued, running or unfinished is touched; each agent keeps its latest report.
     * @param {{ log?: (line: string) => void }} [options]
     */
    trim({ log = () => {} } = {}) {
      const current = policy();
      const at = now();
      const cutoff = (days) => new Date(at.getTime() - days * day).toISOString();
      const gone = (statement, days) => Number(statement.run(cutoff(days)).changes);
      const removed = {
        hits: gone(q.hits, current.hits),
        audit: gone(q.audit, current.audit),
        jobs: gone(q.jobs, current.jobs),
        checks: gone(q.checks, current.checks),
        events: gone(q.deviceEvents, current.events) + gone(q.cveEvents, current.events),
        reports: gone(q.reports, current.reports),
      };
      const total = Object.values(removed).reduce((sum, n) => sum + Number(n), 0);
      for (const [key, n] of Object.entries(removed)) if (n) log(`${policyLabels[key]}: ${n} removed, older than ${current[key]} days.`);
      if (!total) log("Nothing has aged out.");
      let compacted = false;
      const pages = /** @type {any} */ (q.pages.get());
      if (Number(pages.free) >= Number(pages.bytes) / 10) {
        db.exec("VACUUM");
        compacted = true;
        log(`Compacted the file: ${Math.round(Number(pages.free) / 1_048_576)} MB was free inside it.`);
      }
      const summary = { at: at.toISOString(), removed, compacted };
      settings.set("retention_last", summary);
      if (total || compacted) audit.record("system", "retention.trimmed", null, summary);
      return summary;
    },
  };
}

/** @param {ReturnType<typeof createRetention>} retention */
export const retentionJobKinds = (retention) => ({
  "retention.trim": {
    title: "Trim old records",
    direct: true,
    async run({ log }) { return retention.trim({ log }); },
  },
});
