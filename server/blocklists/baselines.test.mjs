import { describe, expect, it } from "vitest";
import { fakePihole, fakeWeb, testClock, testServices } from "../test-helpers.mjs";
import { baselines as levels, siteOf } from "./baselines.mjs";
import { neverBlock } from "./parse.mjs";

const reg = (id) => `https://adguardteam.github.io/HostlistsRegistry/assets/filter_${id}.txt`;
const abp = (...names) => `${names.map((n) => `||${n}^`).join("\n")}\n`;
const t = (iso) => Date.parse(iso) / 1000;
const phone = "192.168.1.42";
const laptop = "192.168.1.20";

function lookups(client, domain, count, status = "FORWARDED", at = "2026-10-28T10:00:00Z") {
  return Array.from({ length: count }, (_, i) => ({ id: 0, time: t(at) + i, type: "A", domain, cname: null, status, client: { ip: client, name: client === phone ? "pixel.lan" : null } }));
}

async function setup({ queries = [], write = true } = {}) {
  const all = queries.map((q, i) => ({ ...q, id: i + 1 }));
  const pihole = fakePihole({ queries: all });
  const web = fakeWeb({
    [reg(44)]: abp("malware-a.example"),
    [reg(34)]: abp("ads-1.example", "tracker.example"),
    [reg(31)]: abp("stalker.example"), [reg(11)]: abp("u.example"), [reg(18)]: abp("p.example"), [reg(8)]: abp("c.example"),
  });
  const services = testServices({ piholeFetch: pihole.fetchImpl, webFetch: web.fetchImpl, now: testClock("2026-10-29T12:00:00.000Z") });
  services.sentinel.configure({ mode: "api", url: "http://192.0.2.5", password: "pihole-pass", write }, "owner");
  await services.library.update();
  return { ...services, pihole };
}

describe("baselines", () => {
  it("groups names by site", () => {
    expect(siteOf("i.ytimg.com")).toBe("ytimg.com");
    expect(siteOf("www.bbc.co.uk")).toBe("bbc.co.uk");
    expect(siteOf("example.com")).toBe("example.com");
  });

  it("suggests Strict for a device that looked up an indicator, Balanced otherwise", async () => {
    const { baselines, sentinel } = await setup({ queries: [...lookups(phone, "fearevolve.com", 2), ...lookups(laptop, "example.org", 5)] });
    await sentinel.hunt();
    const scopes = await baselines.scopes();
    expect(scopes.network.suggested).toBe("balanced");
    expect(scopes.devices.find((d) => d.ip === phone)).toMatchObject({ suggested: "strict", key: "device-192-168-1-42", name: "pixel.lan" });
    expect(scopes.devices.find((d) => d.ip === laptop).suggested).toBe("balanced");
  });

  it("previews each level against a device's real lookups", async () => {
    const { baselines } = await setup({ queries: [
      ...lookups(phone, "fearevolve.com", 12),
      ...lookups(phone, "ads-1.example", 12),
      ...lookups(phone, "cdn.tracker.example", 60),
      ...lookups(phone, "malware-a.example", 1, "GRAVITY"),
      ...lookups(phone, "example.org", 30),
      ...lookups(laptop, "ads-1.example", 500),
    ] });
    const preview = await baselines.preview({ client: phone, windowDays: 7 });
    expect(preview.totalQueries).toBe(115);
    const essential = preview.levels.find((l) => l.id === "essential");
    const balanced = preview.levels.find((l) => l.id === "balanced");
    expect(essential.details.map((s) => s.site).sort()).toEqual(["fearevolve.com", "malware-a.example"]);
    expect(essential.details.find((s) => s.site === "malware-a.example").today).toBe("blocked");
    expect(balanced.details.map((s) => [s.site, s.risk])).toEqual([["ads-1.example", "high"], ["tracker.example", "low"], ["fearevolve.com", "low"], ["malware-a.example", "low"]]);
    expect(balanced.details.find((s) => s.site === "ads-1.example")).toMatchObject({ queries: 12, categories: ["ads", "trackers"], lists: ["HaGeZi's Normal Blocklist"] });
    expect(balanced.mightBreak).toBe(1);
    // fearevolve.com is looked up directly, but a spyware site is never a breakage risk.
    expect(essential.details.find((x) => x.site === "fearevolve.com").risk).toBe("low");
    expect(preview.levels.find((l) => l.id === "strict").missingLists.length).toBeGreaterThan(0);
  });

  it("matches a brute-force recomputation on a synthetic 7-day log (M3 exit criterion)", async () => {
    // A seeded log of 600 lookups over 10 days: list domains, their subdomains, look-alikes that are
    // not subdomains, a never-block name, and unrelated names; some already blocked by Pi-hole.
    let seed = 42;
    const random = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
    const lists = { [reg(44)]: ["malware-a.example", "evil.test"], [reg(34)]: ["ads-1.example", "tracker.example", "metrics.shop.example", neverBlock[0]], [reg(31)]: ["stalker.example"] };
    const pool = ["malware-a.example", "x.malware-a.example", "notmalware-a.example", "evil.test", "a.b.evil.test", "ads-1.example", "cdn.ads-1.example", "tracker.example", "metrics.shop.example", "www.shop.example",
      "shop.example", "stalker.example", "api.stalker.example", neverBlock[0], "example.org", "www.example.org", "news.example.net"];
    const end = t("2026-10-29T12:00:00Z");
    const queries = Array.from({ length: 600 }, (_, i) => ({ id: i + 1, time: Math.floor(end - random() * 10 * 86400), type: "A", domain: pool[Math.floor(random() * pool.length)], cname: null,
      status: random() < 0.2 ? "GRAVITY" : "FORWARDED", client: { ip: random() < 0.8 ? phone : laptop, name: null } }));
    const pihole = fakePihole({ queries });
    const web = fakeWeb({ ...Object.fromEntries(Object.entries(lists).map(([url, names]) => [url, abp(...names)])), [reg(11)]: abp("u.example"), [reg(18)]: abp("p.example"), [reg(8)]: abp("c.example") });
    const services = testServices({ piholeFetch: pihole.fetchImpl, webFetch: web.fetchImpl, now: testClock("2026-10-29T12:00:00.000Z") });
    services.sentinel.configure({ mode: "api", url: "http://192.0.2.5", password: "pihole-pass", write: true }, "owner");
    await services.library.update();
    const preview = await services.baselines.preview({ client: phone, windowDays: 7 });

    // Brute force: every lookup in the window, every list entry, no indexes.
    const categoriesOf = new Map(services.library.sources().map((src) => [src.url, src.categories]));
    const inWindow = queries.filter((q) => q.client.ip === phone && q.time >= end - 7 * 86400 && q.time <= end);
    expect(preview.totalQueries).toBe(inWindow.length);
    for (const level of levels) {
      const expected = new Map();
      const blockedNames = new Set();
      for (const q of inWindow) {
        const blocks = Object.entries(lists).some(([url, names]) => categoriesOf.get(url).some((c) => level.categories.includes(c))
          && names.some((d) => !neverBlock.includes(d) && !neverBlock.includes(q.domain) && (q.domain === d || q.domain.endsWith(`.${d}`))));
        if (!blocks) continue;
        blockedNames.add(q.domain);
        const e = expected.get(siteOf(q.domain)) ?? { queries: 0, blocked: 0 };
        e.queries += 1;
        if (q.status === "GRAVITY") e.blocked += 1;
        expected.set(siteOf(q.domain), e);
      }
      const got = preview.levels.find((l) => l.id === level.id);
      expect(Object.fromEntries(got.details.map((d) => [d.site, d.queries]))).toEqual(Object.fromEntries([...expected].map(([site, e]) => [site, e.queries])));
      expect(Object.fromEntries(got.details.map((d) => [d.site, d.today]))).toEqual(Object.fromEntries([...expected].map(([site, e]) => [site, e.blocked >= e.queries ? "blocked" : e.blocked ? "partly" : "allowed"])));
      const blockedAfter = inWindow.filter((q) => q.status === "GRAVITY" || blockedNames.has(q.domain)).length;
      expect(got.shareAfter).toBeCloseTo(blockedAfter / inWindow.length, 12);
    }
    expect(preview.levels.find((l) => l.id === "essential").details.map((d) => d.site).sort()).toEqual(["evil.test", "malware-a.example", "stalker.example"]);
  });

  it("keeps an excepted site out of the preview's count and out of the served list", async () => {
    const { baselines } = await setup({ queries: lookups(phone, "ads-1.example", 12) });
    baselines.setException("device-192-168-1-42", "ads-1.example", true, "owner");
    const balanced = (await baselines.preview({ client: phone })).levels.find((l) => l.id === "balanced");
    expect(balanced.details[0]).toMatchObject({ site: "ads-1.example", kept: true });
    expect(balanced.mightBreak).toBe(0);
    expect(baselines.compileFor("balanced", "device-192-168-1-42").domains).not.toContain("ads-1.example");
    expect(baselines.compileFor("balanced", "network").domains).toContain("ads-1.example");
  });

  it("applies a baseline to one device through its own Pi-hole group, and removes it cleanly", async () => {
    const { baselines, pihole } = await setup();
    const before = JSON.stringify({ g: pihole.state.groups, c: pihole.state.clients, l: pihole.state.adlists });
    const a = await baselines.apply({ baselineId: "balanced", client: phone, listsOrigin: "http://192.168.1.5:8797" }, "owner");
    expect(a).toMatchObject({ baseline: "balanced", client: phone, entries: 3, groupName: `TheySpy ${phone}` });
    const group = pihole.state.groups.find((g) => g.name === `TheySpy ${phone}`);
    expect(pihole.state.clients).toEqual([{ client: phone, groups: [0, group.id], comment: "TheySpy: Balanced baseline" }]);
    expect(pihole.state.adlists[0]).toMatchObject({ groups: [group.id], address: expect.stringMatching(/^http:\/\/192\.168\.1\.5:8797\/lists\/[\w-]+\/baseline-balanced--device-192-168-1-42\.adblock$/) });
    await baselines.remove({ client: phone }, "owner");
    expect(JSON.stringify({ g: pihole.state.groups, c: pihole.state.clients, l: pihole.state.adlists })).toBe(before);
    expect(baselines.assignments()).toEqual({});
  });

  it("switches a device from one baseline to another without leaving the first behind", async () => {
    const { baselines, pihole } = await setup();
    await baselines.apply({ baselineId: "balanced", client: phone, listsOrigin: "http://x:8797" }, "owner");
    await baselines.apply({ baselineId: "essential", client: phone, listsOrigin: "http://x:8797" }, "owner");
    expect(pihole.state.adlists.map((l) => l.address)).toEqual([expect.stringMatching(/baseline-essential--device-192-168-1-42\.adblock$/)]);
    expect(pihole.state.groups.filter((g) => g.name.startsWith("TheySpy"))).toHaveLength(1);
    expect(pihole.state.clients).toHaveLength(1);
    expect(baselines.assignments()["device-192-168-1-42"].baseline).toBe("essential");
  });

  it("restores a client entry the owner already had", async () => {
    const { baselines, pihole } = await setup();
    pihole.state.clients.push({ client: phone, groups: [0], comment: "kitchen phone" });
    await baselines.apply({ baselineId: "essential", client: phone, listsOrigin: "http://x:8797" }, "owner");
    expect(pihole.state.clients[0].groups).toHaveLength(2);
    await baselines.remove({ client: phone }, "owner");
    expect(pihole.state.clients).toEqual([{ client: phone, groups: [0], comment: "kitchen phone" }]);
  });

  it("applies to the whole network through the Default group, turning on the lists a level needs", async () => {
    const { baselines, pihole, library } = await setup();
    const a = await baselines.apply({ baselineId: "strict", listsOrigin: "http://x:8797" }, "owner");
    expect(a.client).toBeNull();
    expect(pihole.state.adlists[0].groups).toEqual([0]);
    expect(pihole.state.clients).toEqual([]);
    expect(library.sources().find((s) => s.key === "adguard:hagezi_pro++").status).toBe("enabled");
  });

  it("lets the owner define their own level, always with spyware, and keeps it while in use", async () => {
    const { baselines } = await setup({ queries: [...lookups(phone, "ads-1.example", 3), ...lookups(phone, "fearevolve.com", 1)] });
    expect(() => baselines.setCustom({ categories: ["ads", "astrology"] }, "owner")).toThrow(/categories must be from/);
    const custom = baselines.setCustom({ name: "Kids' tablet", categories: ["social", "ads"] }, "owner");
    expect(custom).toMatchObject({ id: "custom", name: "Kids' tablet", severity: 4, categories: ["spyware", "ads", "social"] });
    expect(baselines.list().map((b) => b.id)).toEqual(["essential", "balanced", "strict", "lockdown", "custom"]);
    const level = (await baselines.preview({ client: phone })).levels.find((l) => l.id === "custom");
    expect(level.details.map((d) => d.site).sort()).toEqual(["ads-1.example", "fearevolve.com"]);
    expect(level.missingCategories).toEqual(["social"]);
    expect(baselines.compileFor("custom", "network").domains).toContain("ads-1.example");
    await baselines.apply({ baselineId: "custom", client: phone, listsOrigin: "http://x:8797" }, "owner");
    expect(() => baselines.deleteCustom("owner")).toThrow(/in use/);
    await baselines.remove({ client: phone }, "owner");
    baselines.deleteCustom("owner");
    expect(baselines.list()).toHaveLength(4);
  });

  it("tries a baseline in shadow: counts the device's new lookups once each, blocks nothing", async () => {
    const { baselines, sentinel, pihole, now } = await setup();
    expect(() => baselines.startShadow({ baselineId: "nope", client: phone }, "owner")).toThrow(/No such baseline/);
    baselines.startShadow({ baselineId: "balanced", client: phone }, "owner");
    const before = JSON.stringify({ g: pihole.state.groups, c: pihole.state.clients, l: pihole.state.adlists });
    const at = "2026-10-29T12:00:05Z";
    const fresh = [...lookups(phone, "ads-1.example", 4, "FORWARDED", at), ...lookups(phone, "cdn.tracker.example", 2, "GRAVITY", at), ...lookups(phone, "example.org", 5, "FORWARDED", at), ...lookups(laptop, "ads-1.example", 9, "FORWARDED", at)];
    pihole.state.queries.push(...fresh.map((x, i) => ({ ...x, id: 1000 + i })));
    now.advance(30_000);
    await sentinel.watch.poll();
    await sentinel.watch.poll(); // overlapping polls read the same queries again
    const report = baselines.shadowReport(phone);
    expect(report).toMatchObject({ baseline: "balanced", totalQueries: 11 });
    expect(report.level.details.map((d) => [d.site, d.queries, d.today])).toEqual([["ads-1.example", 4, "allowed"], ["tracker.example", 2, "blocked"]]);
    expect(report.level.shareAfter).toBeCloseTo(6 / 11, 12);
    expect((await baselines.preview({ client: phone })).shadow.baseline).toBe("balanced");
    expect(JSON.stringify({ g: pihole.state.groups, c: pihole.state.clients, l: pihole.state.adlists })).toBe(before);

    // Applying for real replaces the shadow; trying another in shadow on top of a real one is refused.
    await baselines.apply({ baselineId: "balanced", client: phone, listsOrigin: "http://x:8797" }, "owner");
    expect(baselines.shadowReport(phone)).toBeNull();
    expect(() => baselines.startShadow({ baselineId: "strict", client: phone }, "owner")).toThrow(/is applied here/);
  });

  it("stops a shadow without touching Pi-hole", async () => {
    const { baselines, pihole } = await setup();
    baselines.startShadow({ baselineId: "strict" }, "owner");
    const requests = pihole.state.requests.length;
    expect(await baselines.remove({}, "owner")).toEqual({ removed: true, shadow: true });
    expect(pihole.state.requests.length).toBe(requests);
    expect(baselines.assignments()).toEqual({});
  });

  it("refuses to change Pi-hole when writes are off", async () => {
    const { baselines } = await setup({ write: false });
    await expect(baselines.apply({ baselineId: "balanced", client: phone, listsOrigin: "http://x" }, "owner")).rejects.toThrow(/turned off/);
  });
});
