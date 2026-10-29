// TheySpy's blocklist categories (docs/PLAN.md §6.1) and how each directory's own labels map onto
// them. A list can carry several categories; every domain inherits the categories of the lists
// that contain it.

export const categories = Object.freeze([
  { id: "spyware", group: "security", name: "Spyware & ADINT", description: "Mercenary spyware, stalkerware and ad-intelligence infrastructure." },
  { id: "malware", group: "security", name: "Malware & C2", description: "Malware delivery, command-and-control and badware hosting." },
  { id: "phishing", group: "security", name: "Phishing & scams", description: "Credential phishing, scam shops and fraud." },
  { id: "cryptomining", group: "security", name: "Cryptomining", description: "In-browser and drive-by coin miners." },
  { id: "nrd", group: "security", name: "Newly registered & dynamic", description: "Freshly registered domains, dynamic DNS and abused TLDs." },
  { id: "ads", group: "privacy", name: "Ads", description: "Ad servers and ad networks." },
  { id: "trackers", group: "privacy", name: "Trackers & analytics", description: "Tracking, analytics and fingerprinting." },
  { id: "telemetry", group: "privacy", name: "Telemetry", description: "Phone-home from operating systems, TVs and IoT vendors." },
  { id: "bypass", group: "privacy", name: "DoH / VPN bypass", description: "Encrypted-DNS, VPN, Tor and proxy endpoints that route around your DNS filter." },
  { id: "social", group: "content", name: "Social media", description: "Social networks." },
  { id: "adult", group: "content", name: "Adult", description: "Adult content." },
  { id: "gambling", group: "content", name: "Gambling", description: "Betting and casinos." },
  { id: "dating", group: "content", name: "Dating", description: "Dating sites and apps." },
  { id: "piracy", group: "content", name: "Piracy", description: "Piracy and warez." },
  { id: "other", group: "content", name: "Other", description: "Regional, topical or unclassified lists." },
]);
export const categoryIds = Object.freeze(categories.map((c) => c.id));
export const groups = Object.freeze({ security: "Security", privacy: "Privacy", content: "Content" });
export const securityCategories = Object.freeze(categories.filter((c) => c.group === "security").map((c) => c.id));

// FilterLists.com tag ids (https://api.filterlists.com/tags).
const filterListsTags = { 1: ["cryptomining"], 2: ["ads"], 3: ["trackers"], 4: ["social"], 6: ["malware"], 7: ["phishing"], 11: ["adult"], 17: ["gambling"], 24: ["piracy"], 37: ["nrd"] };
// FilterLists syntax ids a DNS filter can use: hosts (IPv4/IPv6, 0), domains, dnsmasq, RPZ, Adblock-style domain rules.
export const dnsSyntaxIds = Object.freeze([1, 2, 14, 16, 20, 25, 28, 36, 37, 47, 48, 54]);
const allowlistTag = 10;

/** Categories for a FilterLists entry, or null when it is an allowlist (never a blocklist). */
export function fromFilterListsTags(tagIds) {
  if (tagIds.includes(allowlistTag)) return null;
  const out = new Set(tagIds.flatMap((id) => filterListsTags[id] ?? []));
  return out.size ? [...out] : ["other"];
}

// AdGuard HostlistsRegistry: the filterKey says more than the group, so known keys are mapped
// directly; the rest fall back to their group (1 general, 2 other, 3 regional, 4 security).
const adguardKeys = {
  staklerware_indicators_list: ["spyware"],
  hagezi_threat_intelligence_feeds: ["malware", "phishing"],
  urlhaus_filter_online: ["malware"],
  dandelion_sprouts_anti_malware_list: ["malware"],
  shadowwhisperers_malware_list: ["malware"],
  the_big_list_of_hacked_malware_web_sites: ["malware"],
  ublock_badware_risks: ["malware"],
  hagezi_badware_hoster_blocklist: ["malware"],
  scam_blocklist_by_durablenapkin: ["phishing"],
  phishing_army: ["phishing"],
  curben_phishing_filter: ["phishing"],
  nocoin_filter_list: ["cryptomining"],
  hagezi_dyndns_blocklist: ["nrd"],
  hagezi_the_worlds_most_abused_tlds: ["nrd"],
  hagezi_encrypted_dns_vpn_tor_proxy_bypass: ["bypass"],
  hagezi_url_shortener_blocklist: ["other"],
  hagezi_dns_rebind_protection: ["other"],
  hagezi_gambling_blocklist: ["gambling"],
  shadowwhisperers_dating_list: ["dating"],
  hagezi_anti_piracy_blocklist: ["piracy"],
  perflyst_dandelion_sprout_smart_tv_blocklist_for_adguard_home: ["telemetry"],
};
const adguardGroups = { 1: ["ads", "trackers"], 2: ["other"], 3: ["other"], 4: ["malware"] };

/** Categories for an AdGuard registry entry, or null for its allowlists. */
export function fromAdguard({ filterKey, groupId, name }) {
  if (/allowlist/i.test(filterKey)) return null;
  if (adguardKeys[filterKey]) return adguardKeys[filterKey];
  if (/tracker/i.test(filterKey) || /tracker/i.test(name)) return ["telemetry"];
  return adguardGroups[groupId] ?? ["other"];
}

/** A best guess from a list's name, for lists no directory labels (custom URLs, Firebog). */
export function fromName(name) {
  const n = name.toLowerCase();
  if (/stalker|spyware|adint/.test(n)) return ["spyware"];
  if (/phish|scam|fraud/.test(n)) return ["phishing"];
  if (/malware|threat|badware|c2|ransom|urlhaus|tif\b/.test(n)) return ["malware"];
  if (/coin|crypto|miner/.test(n)) return ["cryptomining"];
  if (/telemetry|smart.?tv|native|windows|xiaomi|samsung/.test(n)) return ["telemetry"];
  if (/track|privacy|analytics/.test(n)) return ["trackers"];
  if (/porn|adult|nsfw/.test(n)) return ["adult"];
  if (/gambl|casino|betting/.test(n)) return ["gambling"];
  if (/social|facebook|tiktok/.test(n)) return ["social"];
  if (/\bads?\b|advert|adaway|adguard|hosts/.test(n)) return ["ads"];
  return ["other"];
}
