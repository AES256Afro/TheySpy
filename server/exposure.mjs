import { inCidr } from "./fleet/addresses.mjs";
import { productVersion } from "./shared.mjs";

// Ad exposure (docs/PLAN.md M8, mockup 07): Citizen Lab's defender guidance as live checks. Every
// factor says pass, partial, fail or unknown, with the evidence it was decided on and the fix. A
// device's score counts what is known: unknown factors are listed, never guessed.

const day = 86_400_000;
const weight = { pass: 1, partial: 0.5, fail: 0 };
export const starlinkFeed = "https://geoip.starlinkisp.net/feed.csv";
export const traceUrl = "https://1.1.1.1/cdn-cgi/trace";

/**
 * Score 0–100 from the known factors, and its tone. A score resting on too little (under half the
 * factors that apply, or fewer than two) keeps its number but no colour: one passing check out of
 * seven is not "green".
 */
export function scoreOf(factors) {
  const known = factors.filter((f) => f.state in weight);
  const applicable = factors.filter((f) => f.state !== "na").length;
  if (!known.length) return { score: null, tone: "unknown", known: 0, of: applicable };
  const score = Math.round((100 * known.reduce((n, f) => n + weight[f.state], 0)) / known.length);
  const enough = known.length >= 2 && known.length * 2 >= applicable;
  return { score, tone: !enough ? "unknown" : score >= 75 ? "good" : score >= 50 ? "warn" : "bad", known: known.length, of: applicable };
}

/** Does an address fall in SpaceX's published Starlink prefixes (its geofeed, RFC 8805)? */
export function inStarlink(ip, feedText) {
  return String(feedText).split("\n").some((line) => {
    const prefix = line.split(",")[0]?.trim();
    return prefix && !prefix.includes(":") && inCidr(ip, prefix);
  });
}

/**
 * @param {{
 *   fleet: ReturnType<typeof import("./fleet/registry.mjs").createFleet>,
 *   sentinel: ReturnType<typeof import("./pihole/sentinel.mjs").createSentinel>,
 *   agents: ReturnType<typeof import("./agents.mjs").createAgents>,
 *   read: { exploitedOnDevices: () => any[] },
 *   deviceCves: ReturnType<typeof import("./cves/devices.mjs").createDeviceCves>,
 *   settings: ReturnType<typeof import("./db.mjs").createSettingsStore>,
 *   audit: ReturnType<typeof import("./audit.mjs").createAuditLog>,
 *   fetchImpl?: typeof fetch,
 *   now?: () => Date,
 * }} deps
 */
export function createExposure({ fleet, sentinel, agents, read, deviceCves, settings, audit, fetchImpl = fetch, now = () => new Date() }) {
  const fresh = (iso, days) => Boolean(iso) && now().getTime() - Date.parse(iso) <= days * day;

  /** The seven per-device checks, from what TheySpy has seen of the device. */
  function deviceFactors(d, exploited) {
    const profile = agents.profile(d.id);
    const seen = profile.observed ?? null;
    const agent = agents.agentFor(d.id);
    const contacts = agents.contactsFor(d.id);
    const hits = sentinel.hits().filter((h) => h.clientIp === d.ip);
    const isComputer = Boolean(agent) || ["computer", "laptop", "desktop"].includes(d.kind ?? "") || /computer|mac\b/i.test(d.guess?.label ?? "");
    const isPhone = ["phone", "tablet", "watch"].includes(d.kind ?? d.guess?.kind ?? "") || /iphone|ipad|android|phone/i.test(`${d.guess?.label ?? ""} ${profile.os ?? ""}`);
    const piholeRecent = fresh(d.sources?.pihole, 1);
    const inventory = deviceCves.inventory(d.id);
    const mine = exploited.filter((e) => e.deviceIp === d.ip);
    return [
      { id: "dns", label: "DNS through Pi-hole",
        ...(seen?.dnsThroughPihole === false ? { state: "fail", evidence: `This device’s own check (${new Date(seen.at).toLocaleDateString()}): its lookups skip Pi-hole.` }
          : seen?.dnsThroughPihole ? { state: "pass", evidence: "This device’s own check: a test name reached Pi-hole." }
          : piholeRecent ? { state: "pass", evidence: "Pi-hole answered its lookups in the last day." }
          : sentinel.effective().mode ? { state: "fail", evidence: "Pi-hole has not seen it ask anything in a day: it may use its own DNS." } : { state: "unknown", evidence: "Pi-hole is not connected." }),
        fix: "Turn off Private DNS (Android), iCloud Private Relay or Chrome’s Secure DNS at home, or point them at Pi-hole." },
      { id: "blocker", label: "Ad blocking on the device",
        ...(seen?.adBlocked === true ? { state: "pass", evidence: "This device’s check: Google’s ad script did not load." } : seen?.adBlocked === false ? { state: "fail", evidence: "This device’s check: Google’s ad script loaded." } : { state: "unknown", evidence: "Open This device on it once to check." }),
        fix: "Install uBlock Origin (Firefox, Edge, Chrome) or use Brave; on iPhone, an on-device blocker such as AdGuard." },
      { id: "adid", label: "Advertising ID off",
        ...(!isPhone && !profile.adId ? { state: "na", evidence: "Computers and TVs have no phone advertising ID." }
          : profile.adId === "off" ? { state: "pass", evidence: "Recorded as off in its profile." } : profile.adId === "on" ? { state: "fail", evidence: "Recorded as on in its profile." } : { state: "unknown", evidence: "Not recorded: set it in the Evidence locker’s phone profile." }),
        fix: "Android: Settings → Privacy → Ads → Delete advertising ID. iPhone: Settings → Privacy → Tracking off, and Apple Advertising → Personalised Ads off." },
      { id: "gpc", label: "Global Privacy Control",
        ...(seen?.gpc === true ? { state: "pass", evidence: `Sent by ${seen.browser ?? "its browser"}.` } : seen?.gpc === false ? { state: "fail", evidence: `${seen.browser ?? "Its browser"} does not send it.` } : { state: "unknown", evidence: "Open This device on it once to check." }),
        fix: "Use Firefox, Brave or DuckDuckGo with GPC on, or add a GPC extension to Chrome or Edge." },
      { id: "patched", label: "No exploited bugs in its software",
        ...(mine.length ? { state: "fail", evidence: `${mine.map((m) => m.cveId).slice(0, 4).join(", ")}${mine.length > 4 ? ` and ${mine.length - 4} more` : ""} are known to be exploited.` }
          : seen?.exploited ? { state: "fail", evidence: `This device’s browser had ${seen.exploited} exploited CVE(s) when last checked.` }
          : inventory.some((i) => i.matchable) || (seen?.browserExact && seen.exploited === 0) ? { state: "pass", evidence: "None of the versions TheySpy knows for it is known to be exploited." }
          : { state: "unknown", evidence: "No software versions known: run the agent, a Standard check, or This device on it." }),
        fix: "Update the software named, then restart it (browser updates wait for a restart)." },
      { id: "clean", label: "No contact with indicators",
        ...(contacts.length ? { state: "fail", evidence: `The agent or MVT found ${contacts.length} indicator trace(s) on it.` }
          : hits.some((h) => h.blocked < h.lookups) ? { state: "fail", evidence: "It reached an indicator address that Pi-hole did not block." }
          : hits.length ? { state: "partial", evidence: "It asked for indicator addresses; Pi-hole blocked every one." }
          : sentinel.effective().mode ? { state: "pass", evidence: "No lookups of indicator addresses in Pi-hole’s history." } : { state: "unknown", evidence: "Pi-hole is not connected." }),
        fix: "See Pi-hole Sentinel and the Evidence locker; for a phone, run MVT and consider expert help." },
      { id: "scan", label: "Device scanned in the last 7 days",
        ...(agent?.lastReportAt && fresh(agent.lastReportAt, 7) ? { state: agent.verdict?.gaps ? "partial" : "pass", evidence: `The agent reported ${new Date(agent.lastReportAt).toLocaleDateString()}${agent.verdict?.gaps ? ` with ${agent.verdict.gaps} gap(s)` : ""}.` }
          : agent?.lastReportAt ? { state: "fail", evidence: `The last agent report is from ${new Date(agent.lastReportAt).toLocaleDateString()}.` }
          : isComputer ? { state: "fail", evidence: "No agent on this computer." }
          : { state: "na", evidence: "Phones are checked with MVT; other devices cannot run the agent." }),
        fix: "Install the agent (Evidence locker → Add a computer) and schedule it daily." },
    ];
  }

  const exposure = {
    /** Every device's checklist and score, and the network's pillars. */
    overview() {
      const exploited = read.exploitedOnDevices();
      const devices = fleet.list().filter((d) => d.network?.kind !== "docker" && d.network?.kind !== "router").map((d) => {
        const factors = deviceFactors(d, exploited);
        return { id: d.id, name: d.name, ip: d.ip, kind: d.kind ?? d.guess?.label ?? null, factors, ...scoreOf(factors) };
      });
      const coverage = sentinel.lastCoverage();
      const egress = settings.get("exposure_egress") ?? null;
      const watch = sentinel.watch.status();
      const network = [
        { id: "gateway", label: "Pi-hole blocks indicators",
          ...(!sentinel.effective().mode ? { state: "fail", evidence: "Pi-hole is not connected." }
            : !coverage ? { state: "unknown", evidence: "Run Check coverage on Pi-hole Sentinel." }
            : coverage.fullyBlocked >= coverage.total ? { state: "pass", evidence: `All ${coverage.total} indicator domains blocked with their subdomains.` }
            : { state: coverage.blocked >= coverage.total ? "partial" : "fail", evidence: `${coverage.blocked} of ${coverage.total} blocked (${coverage.fullyBlocked ?? 0} with subdomains).` }),
          fix: "Pi-hole Sentinel → Block what your lists miss, or subscribe Pi-hole to TheySpy’s Recommended list." },
        { id: "watch", label: "Live watch for indicator lookups", ...(watch.enabled && !watch.lastError ? { state: "pass", evidence: "TheySpy checks Pi-hole’s new queries every 30 seconds." } : { state: "fail", evidence: watch.lastError ? `The watch fails: ${watch.lastError}` : "The live watch is off." }), fix: "Turn the live watch on in Pi-hole Sentinel." },
        { id: "egress", label: "Not IP-targetable through Starlink",
          ...(!egress ? { state: "unknown", evidence: "Not checked yet: press Check my connection." } : egress.starlink ? { state: "fail", evidence: `Your public address is in Starlink’s published ranges (checked ${new Date(egress.at).toLocaleDateString()}). Reuters reported an ad-intelligence bidder was the top buyer of Starlink ad traffic.` } : { state: "pass", evidence: `Your public address is not a Starlink address (checked ${new Date(egress.at).toLocaleDateString()}).` }),
          fix: "Browse through a VPN or relay (for example WireGuard to a server you trust) so ad bidders do not see a Starlink address." },
      ];
      const all = devices.filter((d) => d.score !== null && d.tone !== "unknown");
      return { devices, network, networkScore: scoreOf(network), average: all.length ? Math.round(all.reduce((n, d) => n + d.score, 0) / all.length) : null };
    },

    /**
     * Asks Cloudflare for this network's public address and compares it with SpaceX's published
     * Starlink prefixes. Only when the owner presses the button; the address is not stored.
     */
    async checkEgress(actor) {
      const trace = await (await fetchImpl(traceUrl, { headers: { "user-agent": `TheySpy/${productVersion}` }, signal: AbortSignal.timeout(15_000) })).text();
      const ip = /^ip=(.+)$/m.exec(trace)?.[1]?.trim();
      if (!ip) throw Object.assign(new Error("Could not read this network’s public address"), { status: 502 });
      const feed = await (await fetchImpl(starlinkFeed, { headers: { "user-agent": `TheySpy/${productVersion}` }, signal: AbortSignal.timeout(30_000) })).text();
      const result = { at: now().toISOString(), starlink: inStarlink(ip, feed), cgnat: inCidr(ip, "100.64.0.0/10") };
      settings.set("exposure_egress", result);
      audit.record(actor, "exposure.egress_checked", null, { starlink: result.starlink });
      return result;
    },
  };
  return exposure;
}

/** The hardening kits (mockup 07): files and steps that flip the factors above. */
export const kits = Object.freeze({
  apple: {
    filename: "theyspy-no-personalised-ads.mobileconfig", type: "application/x-apple-aspen-config",
    body: () => `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadDisplayName</key><string>TheySpy: no personalised ads</string>
  <key>PayloadDescription</key><string>Turns off Apple's personalised advertising and app tracking requests. From TheySpy's ad-exposure hardening kit (Citizen Lab defender guidance).</string>
  <key>PayloadIdentifier</key><string>org.theyspy.hardening</string>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>7B0C2A4E-6E3F-4C1D-9C5B-3A1E2F4D5C6B</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.applicationaccess</string>
      <key>PayloadIdentifier</key><string>org.theyspy.hardening.restrictions</string>
      <key>PayloadUUID</key><string>2C9D1E3F-4A5B-4C6D-8E7F-9A0B1C2D3E4F</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>allowApplePersonalizedAdvertising</key><false/>
      <key>forceLimitAdTracking</key><true/>
    </dict>
  </array>
</dict>
</plist>
`,
  },
  windows: {
    filename: "theyspy-ads-off.reg", type: "text/plain",
    body: () => `Windows Registry Editor Version 5.00

; TheySpy ad-exposure hardening kit: the advertising ID off, Edge tracking prevention strict,
; Global Privacy Control in Firefox, third-party cookies blocked in Chrome. Import as an administrator.

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo]
"DisabledByGroupPolicy"=dword:00000001

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Edge]
"TrackingPrevention"=dword:00000003
"PersonalizationReportingEnabled"=dword:00000000

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome]
"BlockThirdPartyCookies"=dword:00000001
"AdsSettingForIntrusiveAdsSites"=dword:00000002

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Mozilla\\Firefox\\Preferences\\privacy.globalprivacycontrol.enabled]
"Value"=dword:00000001
"Status"="locked"
`,
  },
  android: {
    filename: "theyspy-android-steps.txt", type: "text/plain",
    body: (pihole) => `TheySpy ad-exposure kit for Android

1. Delete the advertising ID: Settings → Security & privacy → Privacy → Ads → Delete advertising ID.
   (Older Android: Settings → Google → Ads → Delete advertising ID.)
2. At home, let Pi-hole answer DNS: Settings → Network & internet → Private DNS → Off
   (or Automatic). A Private DNS provider skips Pi-hole${pihole ? ` (${pihole})` : ""} entirely.
3. Browser: use Firefox with uBlock Origin, or Brave. In Chrome: Settings → Privacy → Third-party cookies → Block.
4. Check it: open TheySpy's This device page on the phone. DNS, ad blocking and GPC should all pass.
5. If you are at risk of targeted spyware: run Amnesty's MVT with TheySpy's STIX file (Indicators → Export)
   and import the results in the Evidence locker.
`,
  },
  browsers: {
    filename: "theyspy-browser-steps.txt", type: "text/plain",
    body: () => `TheySpy ad-exposure kit for browsers

- Firefox: Settings → Privacy & Security → Tell websites not to sell or share my data (Global Privacy Control);
  Enhanced Tracking Protection: Strict. Add uBlock Origin.
- Brave: GPC and ad blocking are on by default. Shields: Aggressive.
- Edge: Settings → Privacy → Tracking prevention: Strict. Add uBlock Origin.
- Chrome: block third-party cookies, add uBlock Origin Lite and a GPC extension.
- Safari (Mac): Settings → Privacy → Prevent cross-site tracking; Advanced → Advanced Tracking and Fingerprinting Protection: In all browsing.
- Turn off the browser's own DNS (Chrome "Use secure DNS", Firefox DNS over HTTPS) at home, so Pi-hole sees and blocks lookups.
Then open TheySpy's This device page to confirm GPC, ad blocking and DNS pass.
`,
  },
});
