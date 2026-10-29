import { describe, expect, it } from "vitest";
import { fakeWeb, testClock, testServices } from "../test-helpers.mjs";

const reg = (id) => `https://adguardteam.github.io/HostlistsRegistry/assets/filter_${id}.txt`;
const abp = (...names) => `! Title: test\n${names.map((n) => `||${n}^`).join("\n")}\n`;
// One small file per enabled starter list.
const starterFiles = () => ({
  [reg(31)]: { body: abp("stalker-c2.example"), etag: '"s1"' },
  [reg(44)]: { body: abp("malware-a.example", "phish-a.example"), etag: '"t1"' },
  [reg(11)]: { body: abp("urlhaus-a.example"), etag: '"u1"' },
  [reg(18)]: { body: abp("phish-b.example"), etag: '"p1"' },
  [reg(8)]: { body: abp("coin-a.example", "connectivitycheck.gstatic.com"), etag: '"n1"' },
  [reg(34)]: { body: abp(...Array.from({ length: 200 }, (_, i) => `ads-${i}.example`)), etag: '"h1"' },
});

function library(options = {}) {
  const web = fakeWeb(starterFiles());
  const services = testServices({ webFetch: web.fetchImpl, now: testClock(), ...options });
  return { ...services, web };
}

describe("blocklist library", () => {
  it("starts with the built-in spyware list and six enabled lists, the rest as candidates", () => {
    const { library: lib } = library();
    const sources = lib.sources({ includeCandidates: true });
    expect(sources.filter((s) => s.status === "enabled").map((s) => s.key)).toEqual(expect.arrayContaining(["builtin:zero-breach", "adguard:staklerware_indicators_list", "adguard:hagezi_multinormal"]));
    expect(sources.filter((s) => s.status === "enabled")).toHaveLength(7);
    expect(lib.candidates().map((c) => c.key)).toContain("adguard:hagezi_pro");
    expect(lib.seed()).toBe(false);
  });

  it("fetches enabled lists and compiles categories, leaving out never-block names", async () => {
    const { library: lib } = library();
    const { summary } = await lib.update();
    expect(summary).toMatchObject({ lists: 7, first: 6, failed: 0 });
    const security = lib.compile(["spyware", "malware", "phishing", "cryptomining", "nrd"]).domains;
    expect(security).toEqual(expect.arrayContaining(["stalker-c2.example", "malware-a.example", "coin-a.example", "fearevolve.com"]));
    expect(security).not.toContain("connectivitycheck.gstatic.com");
    expect(security).not.toContain("ads-1.example");
    expect(lib.compile(["ads"]).domains).toHaveLength(200);
  });

  it("asks only for changes (ETag) and reports unchanged lists", async () => {
    const { library: lib, web } = library();
    await lib.update();
    web.state.requests.length = 0;
    expect((await lib.update()).summary).toMatchObject({ unchanged: 6, first: 0, updated: 0 });
  });

  it("holds an update that would newly block a protected name, until it is accepted", async () => {
    const { library: lib, web } = library();
    await lib.update();
    web.state.files[reg(44)] = { body: abp("malware-a.example", "phish-a.example", "malware-b.example", "github.com"), etag: '"t2"' };
    const { results } = await lib.update();
    const held = results.find((r) => r.outcome === "quarantined");
    expect(held.reasons[0]).toMatch(/would newly block 1 protected name: github\.com/);
    expect(lib.compile(["malware"]).domains).not.toContain("malware-b.example");
    const [q] = lib.quarantined();
    expect(q).toMatchObject({ added: 2, sample: { risky: ["github.com"] } });
    lib.decide(q.id, true, "owner");
    expect(lib.compile(["malware"]).domains).toContain("malware-b.example");
    expect(lib.compile(["malware"]).domains).not.toContain("github.com"); // still filtered from the output
    expect(() => lib.decide(q.id, true, "owner")).toThrow(/Only a quarantined/);
  });

  it("holds an update that changes size by more than half, and a rejection keeps the old version", async () => {
    const { library: lib, web } = library();
    await lib.update();
    web.state.files[reg(34)] = { body: abp("ads-1.example"), etag: '"h2"' };
    const { results } = await lib.update();
    expect(results.find((r) => r.outcome === "quarantined").reasons[0]).toMatch(/size changed from 200 to 1/);
    lib.decide(lib.quarantined()[0].id, false, "owner");
    expect(lib.compile(["ads"]).domains).toHaveLength(200);
  });

  it("marks a list dead after three failed fetches, without losing its last good version", async () => {
    const { library: lib, web } = library();
    await lib.update();
    web.state.files[reg(18)] = { status: 500, body: "down" };
    for (let i = 0; i < 3; i += 1) await lib.update();
    const pa = lib.sources().find((s) => s.key === "adguard:phishing_army");
    expect(pa).toMatchObject({ health: "dead", failures: 3, lastError: "the server answered 500" });
    expect(lib.compile(["phishing"]).domains).toContain("phish-b.example");
  });

  it("refuses an empty list rather than replacing a good one", async () => {
    const { library: lib, web } = library();
    await lib.update();
    web.state.files[reg(18)] = { body: "# nothing\n", etag: '"p2"' };
    const { results } = await lib.update();
    expect(results.find((r) => r.id === lib.sources().find((s) => s.key === "adguard:phishing_army").id)).toMatchObject({ outcome: "failed", error: "the list has no usable domain entries" });
  });

  it("keeps the network's most-used sites off every list", async () => {
    const { library: lib } = library({ popular: async () => ["ads-7.example"] });
    await lib.update();
    expect(lib.compile(["ads"]).domains).not.toContain("ads-7.example");
    expect(lib.compile(["ads"]).domains).toHaveLength(199);
  });

  it("discovers lists from the three directories, skipping allowlists and duplicates", async () => {
    const web = fakeWeb({
      "https://adguardteam.github.io/HostlistsRegistry/assets/filters.json": { body: { filters: [
        { filterKey: "hagezi_pro", filterId: 48, groupId: 1, name: "HaGeZi's Pro Blocklist", description: "d", tags: [1], homepage: "h", downloadUrl: reg(48), deprecated: false },
        { filterKey: "new_security_list", filterId: 99, groupId: 4, name: "New Security List", tags: [2], downloadUrl: reg(99), deprecated: false },
        { filterKey: "hagezi_allowlist_referral", filterId: 45, groupId: 2, name: "HaGeZi's Allowlist Referral", tags: [4], downloadUrl: reg(45) },
      ] } },
      "https://api.filterlists.com/lists": { body: [
        { id: 301, name: "EasyList", syntaxIds: [3], tagIds: [2], licenseId: 1 },
        { id: 500, name: "Some Hosts", syntaxIds: [1], tagIds: [6], licenseId: 1 },
        { id: 501, name: "Whitelist", syntaxIds: [2], tagIds: [10], licenseId: 1 },
      ] },
      "https://api.filterlists.com/licenses": { body: [{ id: 1, name: "MIT" }] },
      "https://api.filterlists.com/syntaxes": { body: [{ id: 1, name: "Hosts (localhost IPv4)" }, { id: 2, name: "Domains" }, { id: 3, name: "Adblock Plus" }] },
      "https://api.filterlists.com/lists/500": { body: { id: 500, homeUrl: "https://hosts.example", viewUrls: [{ segmentNumber: 1, primariness: 2, url: "https://mirror.example/hosts" }, { segmentNumber: 1, primariness: 1, url: "https://hosts.example/hosts" }] } },
      "https://v.firebog.net/hosts/lists.php?type=tick": "https://v.firebog.net/hosts/Easyprivacy.txt\n",
      "https://v.firebog.net/hosts/lists.php?type=all": "https://v.firebog.net/hosts/Easyprivacy.txt\nhttps://v.firebog.net/hosts/Prigent-Malware.txt\n",
    });
    const { library: lib } = testServices({ webFetch: web.fetchImpl });
    const first = await lib.discover("owner");
    expect(first).toMatchObject({ added: 4, errors: [] });
    expect(lib.candidates().map((c) => c.key)).toEqual(expect.arrayContaining(["adguard:new_security_list", "filterlists:500", "firebog:https://v.firebog.net/hosts/Easyprivacy.txt"]));
    expect(lib.candidates().some((c) => /allowlist|Whitelist|EasyList/i.test(c.name))).toBe(false); // allowlists, and EasyList is not a DNS syntax
    expect(lib.candidates().find((c) => c.key === "firebog:https://v.firebog.net/hosts/Easyprivacy.txt")).toMatchObject({ curated: true, categories: ["trackers"] });
    expect((await lib.discover("owner")).added).toBe(0);

    const hosts = lib.candidates().find((c) => c.key === "filterlists:500");
    expect(await lib.setStatus(hosts.id, "enabled", "owner")).toMatchObject({ status: "enabled", url: "https://hosts.example/hosts", categories: ["malware"] });
  });

  it("adds custom lists only over HTTPS, and keeps the built-in list on", async () => {
    const { library: lib } = library();
    expect(() => lib.addCustom({ url: "http://lists.example/x.txt" }, "owner")).toThrow(/https/);
    expect(lib.addCustom({ url: "https://lists.example/x.txt", name: "Mine", categories: ["ads", "bogus"] }, "owner")).toMatchObject({ status: "enabled", categories: ["ads"] });
    const builtin = lib.sources().find((s) => s.key === "builtin:zero-breach");
    await expect(lib.setStatus(builtin.id, "disabled", "owner")).rejects.toThrow(/stays on/);
  });
});
