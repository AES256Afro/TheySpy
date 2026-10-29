import { productVersion } from "../shared.mjs";
import { dnsSyntaxIds, fromAdguard, fromFilterListsTags, fromName } from "./taxonomy.mjs";

// Where TheySpy finds blocklists it has not seen before. Each reader returns candidates; nothing
// here enables a list. Shapes are what the directories served on 29 Oct 2026:
//  - AdGuard HostlistsRegistry assets/filters.json: { filters: [{ filterKey, filterId, groupId, name,
//    description, tags, homepage, downloadUrl, deprecated, timeUpdated }], tags, groups }
//  - FilterLists api.filterlists.com/lists: [{ id, name, description, licenseId, syntaxIds, tagIds }];
//    the download URL is only in /lists/{id} (viewUrls), so it is resolved when a list is enabled.
//  - Firebog v.firebog.net/hosts/lists.php?type=tick|nocross|all: one URL per line; "tick" is the
//    curated, low-false-positive tier.

export const directoryHosts = Object.freeze(["adguardteam.github.io", "api.filterlists.com", "v.firebog.net"]);

/** @typedef {{ key: string, directory: string, name: string, description?: string | null, url?: string | null, homepage?: string | null, license?: string | null, syntax?: string | null, categories: string[], curated?: boolean, deprecated?: boolean }} Candidate */

async function getJson(fetchImpl, url, timeoutMs) {
  const response = await fetchImpl(url, { headers: { "user-agent": `TheySpy/${productVersion}`, accept: "application/json" }, redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
  if (!response.ok) throw new Error(`${new URL(url).hostname} answered ${response.status}`);
  return response.json();
}
async function getText(fetchImpl, url, timeoutMs) {
  const response = await fetchImpl(url, { headers: { "user-agent": `TheySpy/${productVersion}` }, redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
  if (!response.ok) throw new Error(`${new URL(url).hostname} answered ${response.status}`);
  return response.text();
}

/** @returns {Promise<Candidate[]>} */
export async function readAdguard(fetchImpl, timeoutMs = 30_000) {
  const data = await getJson(fetchImpl, "https://adguardteam.github.io/HostlistsRegistry/assets/filters.json", timeoutMs);
  const out = [];
  for (const f of data.filters ?? []) {
    const categories = fromAdguard(f);
    if (!categories || typeof f.downloadUrl !== "string") continue;
    out.push({ key: `adguard:${f.filterKey}`, directory: "adguard", name: f.name, description: f.description ?? null, url: f.downloadUrl, homepage: f.homepage ?? null, license: null, syntax: "adblock", categories, curated: false, deprecated: Boolean(f.deprecated) });
  }
  return out;
}

/** @returns {Promise<Candidate[]>} */
export async function readFilterLists(fetchImpl, timeoutMs = 60_000) {
  const [lists, licenses, syntaxes] = await Promise.all([
    getJson(fetchImpl, "https://api.filterlists.com/lists", timeoutMs),
    getJson(fetchImpl, "https://api.filterlists.com/licenses", timeoutMs),
    getJson(fetchImpl, "https://api.filterlists.com/syntaxes", timeoutMs),
  ]);
  const licenseName = new Map(licenses.map((l) => [l.id, l.name]));
  const syntaxName = new Map(syntaxes.map((s) => [s.id, s.name]));
  const out = [];
  for (const l of lists) {
    const dnsSyntax = (l.syntaxIds ?? []).find((id) => dnsSyntaxIds.includes(id));
    if (dnsSyntax === undefined) continue;
    const categories = fromFilterListsTags(l.tagIds ?? []);
    if (!categories) continue;
    out.push({ key: `filterlists:${l.id}`, directory: "filterlists", name: l.name, description: l.description ?? null, url: null, homepage: null, license: licenseName.get(l.licenseId) ?? null, syntax: syntaxName.get(dnsSyntax) ?? null, categories, curated: false, deprecated: false });
  }
  return out;
}

/** The download URL FilterLists gives first for a list (primariness 1, first segment). */
export async function resolveFilterListsUrl(fetchImpl, id, timeoutMs = 30_000) {
  const detail = await getJson(fetchImpl, `https://api.filterlists.com/lists/${encodeURIComponent(id)}`, timeoutMs);
  const urls = (detail.viewUrls ?? []).filter((u) => typeof u.url === "string" && u.url.startsWith("https://")).sort((a, b) => (a.segmentNumber - b.segmentNumber) || (a.primariness - b.primariness));
  return { url: urls[0]?.url ?? null, homepage: detail.homeUrl ?? null };
}

/**
 * A readable name for a list known only by its URL: a GitHub file by owner/repository, Firebog's
 * own lists by their path, anything else by site plus any path that is more than "hosts".
 */
export function listName(url) {
  const { hostname, pathname } = new URL(url);
  const parts = pathname.split("/").filter(Boolean).map(decodeURIComponent).map((p) => p.replace(/\.txt$/i, ""));
  const generic = (p) => /^(hosts?|domains|list|master|main|raw|blacklists?)$/i.test(p);
  if (hostname === "raw.githubusercontent.com" && parts.length >= 3) {
    const file = parts[parts.length - 1];
    return `${parts[0]}/${parts[1]}${generic(file) ? "" : ` (${file})`}`;
  }
  if (hostname === "v.firebog.net") return `Firebog ${parts.filter((p) => !generic(p)).join("/")}`;
  const meaningful = parts.filter((p) => !generic(p));
  return `${hostname.replace(/^www\./, "")}${meaningful.length ? ` ${meaningful.join("/")}` : ""}`;
}

/** @returns {Promise<Candidate[]>} */
export async function readFirebog(fetchImpl, timeoutMs = 30_000) {
  const [tick, all] = await Promise.all([
    getText(fetchImpl, "https://v.firebog.net/hosts/lists.php?type=tick", timeoutMs),
    getText(fetchImpl, "https://v.firebog.net/hosts/lists.php?type=all", timeoutMs),
  ]);
  const ticked = new Set(tick.split(/\s+/).filter((u) => u.startsWith("https://")));
  const out = [];
  for (const url of new Set(all.split(/\s+/).filter((u) => u.startsWith("https://")))) {
    out.push({ key: `firebog:${url}`, directory: "firebog", name: listName(url), description: null, url, homepage: "https://firebog.net", license: null, syntax: null, categories: fromName(`${listName(url)} ${url}`), curated: ticked.has(url), deprecated: false });
  }
  return out;
}
