// What a compiled list is called, in one place. Two things need to agree about it: the route that
// serves `/lists/<token>/<name>.<format>` and the Pi-hole code that decides whether an address is
// one of TheySpy's own and so may be subscribed to. They did not - the subscribe check took only
// `[a-z]+` as a name, which a baseline's address (`baseline-strict--device-…`) is not.

/** The format a compiled list is served in. */
export const listFormatIds = Object.freeze(["txt", "hosts", "adblock", "dnsmasq", "rpz"]);

/**
 * A compiled list's file name: a category or named list ("spyware", "security", "recommended"), or
 * a baseline for a scope ("baseline-strict--network", "baseline-balanced--device-192-168-1-5").
 */
export const listFileName = new RegExp(`^([a-z]+|baseline-([a-z]+)--(network|device-[0-9a-f-]+))\\.(${listFormatIds.join("|")})$`);

/** Whether an address is one of this TheySpy's own compiled lists. @param {string} address */
export function isListAddress(address) {
  let url;
  try { url = new URL(String(address)); } catch { return false; }
  if (!["http:", "https:"].includes(url.protocol)) return false;
  const parts = url.pathname.split("/").filter(Boolean);
  return parts.length === 3 && parts[0] === "lists" && /^[\w-]+$/.test(parts[1]) && listFileName.test(parts[2]);
}
