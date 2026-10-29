import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

// Exports of an indicator set, ported from zero-breach's emitters (build/emit_denylist.py,
// emit_stix.py, emit_misp.py, Apache-2.0) so that for the same input file TheySpy writes the same
// bytes. server/iocs/exports.test.mjs compares every format against zero-breach's own dist/.

const thirdParty = new URL("../../third_party/zero-breach/", import.meta.url);
const readJson = (path) => JSON.parse(readFileSync(new URL(path, thirdParty), "utf8"));

// --- citations -------------------------------------------------------------------------------

/** Per-source citation: publisher, report title, publication date, URL. */
export const sources = Object.freeze({
  "citizenlab-adfection-2026": ["The Citizen Lab", "Exposing AdFection: How Discover-Tech Turned Targeted Ads Into a Pipeline for Zero-Click Mercenary Spyware", "2026-10-15", "https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/"],
  "recordedfuture-2025-08": ["Recorded Future (Insikt Group)", "Tracking Candiru's DevilsTongue Spyware in Multiple Countries (CTA-2025-0805)", "2025-08-05", "https://www.recordedfuture.com/research/tracking-candirus-devilstongue-spyware"],
  "citizenlab-candiru-2021": ["The Citizen Lab", "Hooking Candiru", "2021-07-15", "https://citizenlab.ca/research/hooking-candiru-another-mercenary-spyware-vendor-comes-into-focus/"],
  "eset-swc-2021": ["ESET", "Strategic web compromises in the Middle East with a pinch of Candiru", "2021-11-16", "https://www.welivesecurity.com/2021/11/16/strategic-web-compromises-middle-east-pinch-candiru/"],
  "avast-2022": ["Avast / Gen", "The Return of Candiru: Zero-days in the Middle East", "2022-07-21", "https://www.gendigital.com/blog/insights/research/the-return-of-candiru-zero-days-in-the-middle-east"],
  "confiant-adint-2026": ["Confiant", "ADINT: Weaponized Ad Tech for Zero-Click Spyware and Mass Identity Vacuuming", "2026-10-15", "https://blog.confiant.com/p/adint-weaponized-ad-tech-for-zero-click-spyware-and-mass-identity-vacuuming"],
  "microsoft-devilstongue-2021": ["Microsoft", "Protecting customers from a private-sector offensive actor using 0-day exploits and DevilsTongue malware", "2021-07-15", "https://www.microsoft.com/en-us/security/blog/2021/07/15/protecting-customers-from-a-private-sector-offensive-actor-using-0-day-exploits-and-devilstongue-malware/"],
  "citizenlab-catalangate-2022": ["The Citizen Lab", "CatalanGate: Extensive Mercenary Spyware Operation against Catalans Using Pegasus and Candiru", "2022-04-18", "https://citizenlab.ca/research/catalangate-extensive-mercenary-spyware-operation-against-catalans-using-pegasus-candiru/"],
  "google-tag-candiru-2021": ["Google Threat Analysis Group", "How we protect users from 0-day attacks", "2021-07-14", "https://blog.google/threat-analysis-group/how-we-protect-users-0-day-attacks/"],
  "amnesty-candiru-indonesia-2024": ["Amnesty International Security Lab", "A Web of Surveillance: Unravelling a murky network of spyware exports to Indonesia", "2024-05-01", "https://securitylab.amnesty.org/latest/2024/05/a-web-of-surveillance/"],
});

/** Plain-language meaning of each tier; shown in the UI and written into the STIX bundle. */
export const tierDescriptions = Object.freeze({
  cc: "Candiru command-and-control server. A connection to this is the most serious of the indicator classes.",
  validator: "Candiru validator server. Profiled a device and decided per device whether to deliver an exploit.",
  delivery: "Discover-Tech / Controlium ad-delivery infrastructure. An impression from this is NOT proof of infection — not every ad carried a payload.",
  historical: "Infrastructure attributed in older Candiru campaigns. Interpret dated evidence in the cited report's context; current ownership and activity are not established.",
  sample: "SHA-256 of a published Candiru sample. One build only; another victim's binary will not match.",
  candiru: "Candiru-attributed server infrastructure. The source lists eight clusters mixing victim-facing C2 with higher-tier operator infrastructure and does not state which role this domain had, so the role is unspecified. A hit is serious.",
  "candiru-ip": "IP address of Candiru-attributed infrastructure. WEAKER THAN A DOMAIN: these are mostly cloud-hosted addresses from a 2025 report and are very likely reassigned to unrelated tenants by now. Only meaningful if the hit is dated within the reporting period.",
});

/** "Publisher, Title, date" for a source key; an unknown key is shown as-is, never re-attributed. */
export function citation(sourceKey) {
  const cite = sources[sourceKey];
  if (!cite) return sourceKey || "source unspecified";
  return `${cite[0]}, ${cite[1]}, ${cite[2]}`;
}

/** Calendar date for stamping exports: the set's curated as-of date, never the wall clock. */
function stampDate(set, now) {
  return set.asof ?? now().toISOString().slice(0, 10);
}

// --- DNS blocklists --------------------------------------------------------------------------

const sourceNote = "AdFection / Candiru indicators. Curated from public reporting (The Citizen Lab, Confiant, Recorded Future, Microsoft, ESET, Avast, Google TAG, Amnesty Security Lab). Public domain (CC0). Blocking is a stopgap; it is not proof of anything and does not detect infection. https://github.com/interplains/zero-breach";
// Scanner evidence, not live-blocking material: only the named operational subhosts are blocked.
const blocklistExclusions = new Set(["adtimizer.co"]);
// Never turn a shared-hosting parent into a rule.
const sharedHostingParents = new Set(["cloudfront.net", "amazonaws.com", "azure.com", "cloudapp.azure.com", "herokuapp.com"]);

/**
 * Domains that belong in a live blocklist. IPs are left out (mostly reassigned cloud addresses, and a
 * DNS list cannot carry them) and so are hashes.
 * @param {import("./parse.mjs").IocSet} set
 */
export function blocklistDomains(set, { includeHistorical = true } = {}) {
  const out = new Set();
  for (const ind of set.indicators) {
    if (ind.type !== "domain" || blocklistExclusions.has(ind.value) || sharedHostingParents.has(ind.value)) continue;
    if (ind.tier === "historical" && !includeHistorical) continue;
    out.add(ind.value);
  }
  return [...out].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function header(format, comment, domains, includeHistorical, stamp) {
  const scope = includeHistorical ? "reviewed domains, all tiers" : "historical tier excluded";
  return [
    `${comment} adint-scan denylist (${format}) - generated ${stamp}`,
    `${comment} ${sourceNote}`,
    `${comment} ${domains.length} domains; ${scope}. IP addresses are intentionally omitted (see the emitter).`,
    `${comment} Historical attribution does not establish current ownership or activity. Bare adtimizer.co is excluded; named operational hosts remain.`,
    comment,
  ];
}

const joinLines = (lines) => `${lines.join("\n")}\n`;

/** The four blocklist formats, keyed by zero-breach's file names. */
export function blocklists(set, { includeHistorical = true, now = () => new Date() } = {}) {
  const domains = blocklistDomains(set, { includeHistorical });
  const stamp = stampDate(set, now);
  return {
    "adfection.hosts.txt": joinLines([...header("hosts", "#", domains, includeHistorical, stamp), ...domains.map((d) => `0.0.0.0 ${d}`)]),
    "adfection.adblock.txt": joinLines([...header("adblock", "!", domains, includeHistorical, stamp), "! Title: AdFection / Candiru blocklist", ...domains.map((d) => `||${d}^`)]),
    "adfection.dnsmasq.conf": joinLines([...header("dnsmasq", "#", domains, includeHistorical, stamp), ...domains.map((d) => `address=/${d}/0.0.0.0`)]),
    "adfection.domains.txt": joinLines([...header("domains", "#", domains, includeHistorical, stamp), ...domains]),
  };
}

// --- deterministic ids -----------------------------------------------------------------------

const namespace = Buffer.from("6f0b4a2e5d1c4f3b9a7eadf3c70f1001", "hex");

/** RFC 4122 version-5 UUID, as Python's uuid.uuid5. */
export function uuid5(name, ns = namespace) {
  const bytes = createHash("sha1").update(ns).update(Buffer.from(name, "utf8")).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

const stixId = (prefix, key) => `${prefix}--${uuid5(`${prefix}:${key}`)}`;
const jsonFile = (value) => `${JSON.stringify(value, null, 2)}\n`;

// --- STIX 2.1 --------------------------------------------------------------------------------

// Committed timestamps, so a rebuild never changes the bundle (from emit_stix.py).
const exportRevision = "2026-10-18T22:33:48.000Z";
const initialCreated = "2026-10-18T00:00:00.000Z";
const citizenLabUrl = sources["citizenlab-adfection-2026"][3];

/** @returns {Record<string, string>} */
function stixReference(sourceKey) {
  const cite = sources[sourceKey];
  if (!cite) return { source_name: sourceKey || "unspecified" };
  const ref = { source_name: cite[0], description: `${cite[1]} (${cite[2]})` };
  if (cite[3]) ref.url = cite[3];
  return ref;
}

function stixPattern(ind) {
  if (ind.type === "domain") return `[domain-name:value = '${ind.value}']`;
  // zero-breach writes ipv4-addr for every IP; its set has no IPv6, and TheySpy says so correctly.
  if (ind.type === "ip") return ind.value.includes(":") ? `[ipv6-addr:value = '${ind.value}']` : `[ipv4-addr:value = '${ind.value}']`;
  return `[file:hashes.'SHA-256' = '${ind.value}']`;
}

/** The permanent withdrawals feed, published unchanged beside the active bundle. */
export const withdrawalBundle = () => readJson("build/stix-withdrawals.json");

/**
 * The active STIX bundle. Ids are uuid5 over the indicator, so MVT, MISP and SIEMs de-duplicate
 * across updates instead of piling up copies.
 * @param {import("./parse.mjs").IocSet} set
 */
export function stixBundle(set, { now = () => new Date() } = {}) {
  const firstPublished = new Map();
  for (const [timestamp, values] of Object.entries(readJson("build/stix-first-published.json"))) for (const value of values) firstPublished.set(value, timestamp);
  const withdrawn = new Set(withdrawalBundle().objects.filter((o) => o.type === "indicator" && o.revoked).map((o) => o.name));

  const stamp = set.asof ? `${set.asof}T00:00:00.000Z` : `${now().toISOString().slice(0, 19)}.000Z`;
  const modified = stamp > exportRevision ? stamp : exportRevision;
  const sharedCreated = stamp < initialCreated ? stamp : initialCreated;
  const identityId = stixId("identity", "adint-shield");
  const malwareId = stixId("malware", "candiru");
  /** @type {Record<string, unknown>[]} */
  const objects = [
    {
      type: "identity", spec_version: "2.1", id: identityId, created: sharedCreated, modified,
      name: "adint-scan IOC set", identity_class: "system",
      description: "Curated from public reporting. NOT affiliated with, and NOT endorsed by, The Citizen Lab or Confiant.",
    },
    {
      type: "malware", spec_version: "2.1", id: malwareId, created: sharedCreated, modified,
      name: "Candiru", is_family: true,
      description: "Mercenary spyware from the Israeli vendor Candiru (US-blacklisted since 2021), delivered zero-click through Discover-Tech's Controlium ad platform in the AdFection campaign.",
      external_references: [{ source_name: "The Citizen Lab", description: "Exposing AdFection (2026-10-15)", url: citizenLabUrl }],
    },
  ];
  const relationships = [];
  for (const ind of set.indicators) {
    // A legitimate vulnerable driver is a lead, not a detection; a withdrawn id is never reused.
    if (ind.tier === "vuln-driver" || withdrawn.has(ind.value)) continue;
    const id = stixId("indicator", ind.value);
    const published = firstPublished.get(ind.value) ?? stamp;
    const created = published < modified ? published : modified;
    objects.push({
      type: "indicator", spec_version: "2.1", id, created, modified, created_by_ref: identityId,
      name: ind.value,
      description: tierDescriptions[ind.tier] ?? ind.tier,
      indicator_types: ["malicious-activity"],
      pattern: stixPattern(ind),
      pattern_type: "stix",
      valid_from: created,
      labels: [`tier:${ind.tier}`, `confidence:${ind.confidence}`, `source:${ind.source || "unspecified"}`],
      confidence: ind.confidence === "primary" ? 85 : 50,
      external_references: [stixReference(ind.source)],
    });
    relationships.push({
      type: "relationship", spec_version: "2.1", id: stixId("relationship", `indicates:${ind.value}`), created, modified,
      relationship_type: "indicates", source_ref: id, target_ref: malwareId,
    });
  }
  return { type: "bundle", id: stixId("bundle", "adfection"), objects: [...objects, ...relationships] };
}

// --- MISP ------------------------------------------------------------------------------------

const mispType = { domain: "domain", ip: "ip-dst", sha256: "sha256" };
const mispCategory = { cc: "Network activity", validator: "Network activity", delivery: "Network activity", historical: "Network activity", sample: "Payload delivery", "vuln-driver": "Artifacts dropped", candiru: "Network activity", "candiru-ip": "Network activity" };
// Only tiers safe to turn into detection rules: ad impressions, reassigned cloud IPs and a
// legitimately signed driver would bury analysts in false positives.
const toIdsTiers = new Set(["cc", "validator", "sample", "candiru"]);

/** @param {import("./parse.mjs").IocSet} set */
export function mispEvent(set, { now = () => new Date() } = {}) {
  const date = stampDate(set, now);
  const stamp = String(Math.floor(Date.parse(`${date}T00:00:00Z`) / 1000));
  const attributes = set.indicators.map((ind) => ({
    uuid: uuid5(`misp-attr:${ind.value}`),
    type: mispType[ind.type],
    category: mispCategory[ind.tier] ?? "Network activity",
    value: ind.value,
    to_ids: toIdsTiers.has(ind.tier),
    timestamp: stamp,
    comment: `tier=${ind.tier} confidence=${ind.confidence} (${citation(ind.source)})`,
    Tag: [{ name: `adint:tier="${ind.tier}"` }, { name: `adint:confidence="${ind.confidence}"` }, { name: `adint:source="${ind.source || "unspecified"}"` }],
  }));
  const sourcesUsed = [...new Set(set.indicators.map((ind) => ind.source || ""))].sort().map((key) => {
    const entry = { key: key || "unspecified", citation: citation(key) };
    if (sources[key]?.[3]) entry.url = sources[key][3];
    return entry;
  });
  return {
    Event: {
      uuid: uuid5("misp-event:adfection"),
      info: "AdFection / Discover-Tech / Candiru — zero-click spyware delivered through real-time ad bidding",
      date,
      timestamp: stamp,
      analysis: "2",
      threat_level_id: "1",
      published: false,
      Attribute: attributes,
      Tag: [{ name: "type:OSINT" }, { name: 'misp-galaxy:mercenary-spyware="Candiru"' }, { name: 'adint:campaign="AdFection"' }],
      Object: [],
      extra: {
        source: "The Citizen Lab, 'Exposing AdFection' (2026-10-15) and Confiant, 'ADINT' (2026-10-15).",
        source_url: citizenLabUrl,
        sources: sourcesUsed,
        attribution_note: "Neither The Citizen Lab nor Confiant is affiliated with this tool or endorses it. Their report is the source; the tool is not theirs.",
        caveat: "An ad impression from the delivery-tier infrastructure is NOT proof of infection. The validator server decided per device whether to proceed. A hit means investigate.",
      },
    },
  };
}

// --- one entry point for downloads -----------------------------------------------------------

/** Every export TheySpy offers, by format id: file name, media type and builder. */
export const exportFormats = Object.freeze({
  hosts: { file: "adfection.hosts.txt", type: "text/plain", label: "hosts file (0.0.0.0)" },
  adblock: { file: "adfection.adblock.txt", type: "text/plain", label: "Adblock / uBlock / AdGuard" },
  dnsmasq: { file: "adfection.dnsmasq.conf", type: "text/plain", label: "dnsmasq" },
  domains: { file: "adfection.domains.txt", type: "text/plain", label: "Plain domain list" },
  stix: { file: "adfection.stix.json", type: "application/json", label: "STIX 2.1 bundle (MVT, MISP, SIEM)" },
  "stix-withdrawals": { file: "adfection.withdrawals.stix.json", type: "application/json", label: "STIX withdrawals (revocations only)" },
  misp: { file: "adfection.misp.json", type: "application/json", label: "MISP event" },
});

/**
 * @param {keyof typeof exportFormats} format
 * @param {import("./parse.mjs").IocSet} set
 * @returns {string}
 */
export function renderExport(format, set, options = {}) {
  if (format === "stix") return jsonFile(stixBundle(set, options));
  if (format === "stix-withdrawals") return jsonFile(withdrawalBundle());
  if (format === "misp") return jsonFile(mispEvent(set, options));
  const lists = blocklists(set, options);
  const entry = exportFormats[format];
  if (!entry || !(entry.file in lists)) throw Object.assign(new Error(`Unknown export format "${format}"`), { status: 404 });
  return lists[entry.file];
}
