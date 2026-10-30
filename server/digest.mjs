// The briefing (docs/PLAN.md M9, mockup 09): the week in plain language. Shown on the Briefing
// screen at any time, and sent once a week through the alerts channel.

const day = 86_400_000;

/** "2026-W44" for a date: the ISO week, so one digest per week whatever the day it is sent. */
export function isoWeek(date) {
  const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7));
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  return `${d.getUTCFullYear()}-W${String(Math.ceil(((d.getTime() - yearStart.getTime()) / day + 1) / 7)).padStart(2, "0")}`;
}

/**
 * @param {{
 *   fleet: ReturnType<typeof import("./fleet/registry.mjs").createFleet>,
 *   sentinel: ReturnType<typeof import("./pihole/sentinel.mjs").createSentinel>,
 *   cves: ReturnType<typeof import("./cves/store.mjs").createCveStore>,
 *   library: ReturnType<typeof import("./blocklists/library.mjs").createBlocklistLibrary>,
 *   alerts: ReturnType<typeof import("./alerts.mjs").createAlerts>,
 *   now?: () => Date,
 * }} deps
 */
export function createDigest({ fleet, sentinel, cves, library, alerts, now = () => new Date() }) {
  const digest = {
    /** The last `days` days, as sections of short sentences, each with the screen to look at. */
    compose(days = 7) {
      const since = new Date(now().getTime() - days * day).toISOString();
      const devices = fleet.list();
      const newDevices = devices.filter((d) => d.firstSeen >= since && d.network?.kind !== "docker");
      const untrusted = devices.filter((d) => !d.trusted && d.network?.kind !== "docker");
      const hits = sentinel.hits().filter((h) => h.lastSeen >= since);
      const raised = alerts.since(since).map((a) => /** @type {any} */ (a));
      const kevMatches = raised.filter((a) => a.kind === "kev_match");
      const stats = cves.stats();
      const coverage = sentinel.lastCoverage();
      const held = library.quarantined();
      const sections = [
        {
          title: "Spyware and ad-intelligence", tone: hits.some((h) => h.blocked < h.lookups) ? "bad" : hits.length ? "warn" : "good", screen: "/pihole",
          lines: [
            hits.length
              ? `${hits.length} lookup${hits.length === 1 ? "" : "s"} of indicator addresses by ${new Set(hits.map((h) => h.clientIp)).size} device(s); ${hits.filter((h) => h.blocked < h.lookups).length} not fully blocked.`
              : "No device looked up a known spyware or ad-intelligence address.",
            coverage ? `Pi-hole blocks ${coverage.blocked} of ${coverage.total} indicator domains${coverage.fullyBlocked !== undefined ? ` (${coverage.fullyBlocked} with their subdomains)` : ""}.` : "Coverage has not been checked yet.",
          ],
        },
        {
          title: "Your devices", tone: newDevices.length ? "warn" : "good", screen: "/fleet",
          lines: [
            (() => { const n = devices.filter((d) => d.network?.kind !== "docker").length; return `${n} device${n === 1 ? "" : "s"} known, ${devices.filter((d) => d.online && d.network?.kind !== "docker").length} online now.`; })(),
            newDevices.length ? `New this week: ${newDevices.map((d) => d.name).join(", ")}.` : "No new devices this week.",
            untrusted.length ? `${untrusted.length} not marked as trusted yet.` : "Every device is trusted.",
          ],
        },
        {
          title: "Vulnerabilities", tone: kevMatches.length ? "bad" : "good", screen: "/intel",
          lines: [
            `${stats.kevThisWeek} CVE${stats.kevThisWeek === 1 ? "" : "s"} added to CISA's known-exploited list this week (${stats.kev} in all).`,
            kevMatches.length ? `In software you run: ${kevMatches.map((a) => a.message.split(".")[0]).join("; ")}.` : "None of them is in software TheySpy has seen on your devices.",
          ],
        },
        {
          title: "Blocklists", tone: held.length ? "warn" : "good", screen: "/blocklists",
          lines: [held.length ? `${held.length} update${held.length === 1 ? "" : "s"} held for review: ${held.map((h) => h.name).join(", ")}.` : "Every list updated cleanly."],
        },
      ];
      return { week: isoWeek(now()), since, until: now().toISOString(), sections, alerts: raised.length };
    },

    /** Sends this week's digest once (Monday morning, or the first chance after). */
    async sendWeekly() {
      const d = digest.compose(7);
      const text = d.sections.map((s) => `${s.title}: ${s.lines.join(" ")}`).join("\n\n");
      return alerts.raise({ key: `digest:${d.week}`, kind: "digest", priority: "low", title: `TheySpy weekly briefing ${d.week}`, message: text });
    },
  };
  return digest;
}
