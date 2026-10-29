import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import { fakePihole, testClock, testServices } from "../test-helpers.mjs";
import { wildcardRegex } from "./client.mjs";

const t = (iso) => Date.parse(iso) / 1000;
// Two real indicator domains from the bundled zero-breach set.
const ioc = "fearevolve.com";
const other = "jobmarcher.com";
const history = [
  { id: 1, time: t("2026-10-20T08:00:00Z"), type: "A", domain: ioc, cname: null, status: "FORWARDED", client: { ip: "192.168.1.42", name: "pixel.lan" } },
  { id: 2, time: t("2026-10-20T08:00:00Z"), type: "AAAA", domain: ioc, cname: null, status: "FORWARDED", client: { ip: "192.168.1.42", name: "pixel.lan" } },
  { id: 3, time: t("2026-10-25T21:14:02Z"), type: "A", domain: `cdn.${ioc}`, cname: null, status: "GRAVITY", client: { ip: "192.168.1.61", name: null } },
  { id: 4, time: t("2026-10-26T10:00:00Z"), type: "A", domain: `not${ioc}`, cname: null, status: "FORWARDED", client: { ip: "192.168.1.42", name: "pixel.lan" } },
  { id: 5, time: t("2026-10-26T10:00:01Z"), type: "A", domain: "example.org", cname: null, status: "CACHE", client: { ip: "192.168.1.5", name: null } },
  // Still only in Pi-hole's memory: the long-term database has not caught up yet.
  { id: 6, time: t("2026-10-29T11:59:30Z"), type: "A", domain: other, cname: null, status: "FORWARDED", client: { ip: "192.168.1.20", name: "mac.lan" }, onDisk: false },
  // Long ago, only on disk.
  { id: 7, time: t("2026-08-15T09:00:00Z"), type: "A", domain: other, cname: null, status: "FORWARDED", client: { ip: "192.168.1.20", name: "mac.lan" }, inMemory: false },
];

function connected(options = {}) {
  const pihole = fakePihole({ queries: history, ...options });
  const services = testServices({ piholeFetch: pihole.fetchImpl, now: testClock("2026-10-29T12:00:00.000Z") });
  services.sentinel.configure({ mode: "api", url: "http://192.0.2.5", password: "pihole-pass", write: true }, "owner");
  return { ...services, pihole };
}

describe("Pi-hole Sentinel", () => {
  it("keeps the password encrypted and never returns it", () => {
    const { sentinel, settings } = connected();
    expect(sentinel.publicConfig()).toMatchObject({ configured: true, mode: "api", url: "http://192.0.2.5", hasPassword: true, write: true });
    expect(JSON.stringify(sentinel.publicConfig())).not.toContain("pihole-pass");
    expect(JSON.stringify(settings.get("pihole"))).not.toContain("pihole-pass");
    expect(sentinel.effective().password).toBe("pihole-pass");
  });

  it("tests the connection and signs out afterwards", async () => {
    const { sentinel, pihole } = connected();
    expect(await sentinel.test()).toMatchObject({ mode: "api", ftl: "v6.7" });
    expect(pihole.state.logins).toBe(pihole.state.logouts);
  });

  it("finds every lookup with its client and time, merging memory and disk, and counts nothing twice", async () => {
    const { sentinel, pihole } = connected();
    const first = await sentinel.hunt();
    expect(first).toMatchObject({ hits: 5, newHits: 5 });
    const hits = sentinel.hits();
    expect(hits.map((h) => [h.indicator, h.domain, h.clientIp, h.lookups, h.blocked])).toEqual([
      [other, other, "192.168.1.20", 2, 0],
      [ioc, `cdn.${ioc}`, "192.168.1.61", 1, 1],
      [ioc, ioc, "192.168.1.42", 2, 0],
    ]);
    expect(hits.find((h) => h.clientIp === "192.168.1.42")).toMatchObject({ clientName: "pixel.lan", firstSeen: "2026-10-20T08:00:00.000Z", tier: "cc" });
    expect(hits.some((h) => h.domain === `not${ioc}`)).toBe(false);
    expect((await sentinel.hunt()).newHits).toBe(0);
    expect(pihole.state.logins).toBe(pihole.state.logouts);
  });

  it("looks only as far back as the window", async () => {
    const { sentinel } = connected();
    await sentinel.hunt({ windowDays: 30 });
    expect(sentinel.hits().find((h) => h.indicator === other).lookups).toBe(1);
  });

  it("picks up new lookups on the live watch", async () => {
    const { sentinel, pihole } = connected();
    await sentinel.watch.poll();
    expect(sentinel.watch.status().newHits).toBe(1); // only the lookup from the last few minutes
    pihole.state.queries.push({ id: 8, time: t("2026-10-29T11:59:50Z"), type: "A", domain: `www.${ioc}`, cname: null, status: "FORWARDED", client: { ip: "192.168.1.44", name: null } });
    await sentinel.watch.poll();
    expect(sentinel.watch.status()).toMatchObject({ newHits: 2, lastError: null });
  });

  it("reports which indicator domains Pi-hole blocks, and their subdomains", async () => {
    const { sentinel, pihole } = connected({ gravity: { [ioc]: "https://lists.example/tif.txt" } });
    const coverage = await sentinel.coverage();
    expect(coverage.total).toBe(291);
    expect(coverage.results.find((r) => r.domain === ioc)).toEqual({ domain: ioc, blocked: true, subdomainsBlocked: false, allowlisted: false, by: ["https://lists.example/tif.txt"] });
    expect(coverage.blocked).toBe(1);
    expect(sentinel.pushPreview().domains).toHaveLength(291);
    expect(pihole.state.logins).toBe(pihole.state.logouts);
  });

  it("pushes wildcard deny entries, and a rollback leaves Pi-hole exactly as it was", async () => {
    const { sentinel, pihole } = connected();
    pihole.state.domains.push({ id: 900, domain: "(\\.|^)tracker\\.example$", type: "deny", kind: "regex", comment: "mine", enabled: true, groups: [0] });
    const before = JSON.stringify(pihole.state.domains);
    const pushed = await sentinel.push([ioc, other], "owner");
    expect(pushed).toMatchObject({ added: 2 });
    expect(pihole.state.domains.filter((d) => d.comment?.startsWith("TheySpy:")).map((d) => d.domain)).toEqual([wildcardRegex(ioc), wildcardRegex(other)]);

    await sentinel.coverage();
    expect(sentinel.lastCoverage().results.find((r) => r.domain === ioc)).toMatchObject({ blocked: true, subdomainsBlocked: true, by: ["TheySpy regex"] });
    expect(sentinel.pushPreview().domains).not.toContain(ioc);
    expect((await sentinel.push([ioc], "owner")).added).toBe(0);

    expect(await sentinel.rollback(pushed.pushId, "owner")).toEqual({ removed: 2, skipped: 0 });
    expect(sentinel.lastCoverage().stale).toBe(true);
    expect(sentinel.pushPreview()).toBeNull();
    expect(JSON.stringify(pihole.state.domains)).toBe(before);
    expect(sentinel.pushes()[0]).toMatchObject({ status: "rolled_back", entries: 2 });
    await expect(sentinel.rollback(pushed.pushId, "owner")).rejects.toThrow(/Only an active push/);
  });

  it("leaves an entry alone that the owner re-commented after the push", async () => {
    const { sentinel, pihole } = connected();
    const { pushId } = await sentinel.push([ioc, other], "owner");
    pihole.state.domains.find((d) => d.domain === wildcardRegex(ioc)).comment = "keeping this one";
    expect(await sentinel.rollback(pushId, "owner")).toEqual({ removed: 1, skipped: 1 });
    expect(pihole.state.domains.map((d) => d.domain)).toEqual([wildcardRegex(ioc)]);
  });

  it("refuses to push when writes are off, or anything that is not an indicator", async () => {
    const { sentinel } = connected();
    await expect(sentinel.push(["example.com"], "owner")).rejects.toThrow(/Only indicator domains/);
    sentinel.configure({ write: false }, "owner");
    await expect(sentinel.push([ioc], "owner")).rejects.toThrow(/turned off/);
  });

  it("explains a refused password", async () => {
    const { sentinel } = connected();
    sentinel.configure({ password: "wrong" }, "owner");
    await expect(sentinel.test()).rejects.toThrow(/refused the password/);
  });

  it("lets the environment override the screen's settings", () => {
    const services = testServices({ piholeEnv: { url: "http://pihole.lan", password: "from-env", write: false } });
    expect(services.sentinel.publicConfig()).toMatchObject({ mode: "api", url: "http://pihole.lan", hasPassword: true, write: false, fromEnv: { url: true, password: true, write: true } });
  });

  it("validates settings", () => {
    const { sentinel } = connected();
    expect(() => sentinel.configure({ url: "ftp://x", windowDays: 0, mode: "dns" }, "owner")).toThrow(/mode must be.*address must.*window must/);
  });
});

describe("Pi-hole database source", () => {
  it("reads pihole-FTL.db read-only, with client names, CNAME blocks and the window", async () => {
    const file = path.join(mkdtempSync(path.join(tmpdir(), "theyspy-ftl-")), "pihole-FTL.db");
    const ftl = new DatabaseSync(file);
    ftl.exec(`CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp INTEGER, type INTEGER, status INTEGER, domain TEXT, client TEXT, forward TEXT, additional_info TEXT);
              CREATE TABLE client_by_id (id INTEGER PRIMARY KEY, ip TEXT, name TEXT);
              INSERT INTO client_by_id (ip, name) VALUES ('192.168.1.42', 'pixel.lan');
              INSERT INTO queries VALUES (1, ${t("2026-10-28T10:00:00Z")}, 1, 2, 'cdn.${ioc}', '192.168.1.42', NULL, NULL);
              INSERT INTO queries VALUES (2, ${t("2026-10-28T10:00:05Z")}, 1, 11, 'innocent.example', '192.168.1.61', NULL, '${other}');
              INSERT INTO queries VALUES (3, ${t("2025-01-01T00:00:00Z")}, 1, 2, '${ioc}', '192.168.1.42', NULL, NULL);`);
    ftl.close();
    const services = testServices({ now: testClock("2026-10-29T12:00:00.000Z") });
    services.sentinel.configure({ mode: "database", dbPath: file }, "owner");
    expect(await services.sentinel.test()).toMatchObject({ mode: "database", queries: 3 });
    expect(await services.sentinel.hunt({ windowDays: 30 })).toMatchObject({ queriesSeen: 2, hits: 2 });
    expect(services.sentinel.hits().map((h) => [h.indicator, h.via, h.clientName, h.lastStatus])).toEqual([
      [other, "cname", null, "DENYLIST_CNAME"],
      [ioc, "query", "pixel.lan", "FORWARDED"],
    ]);
    await expect(services.sentinel.coverage()).rejects.toThrow(/needs the Pi-hole API/);
  });

  it("counts a working live watch as a passed test, and forgets the result when the address changes", async () => {
    const { sentinel, settings } = testServices();
    sentinel.configure({ mode: "api", url: "http://192.0.2.5", password: "pihole-pass" }, "owner");
    expect(settings.get("pihole_last_test") ?? null).toBeNull();
    await sentinel.watch.poll();
    expect(settings.get("pihole_last_test")).toMatchObject({ ok: true, via: "live watch" });
    sentinel.configure({ password: "wrong" }, "owner");
    expect(settings.get("pihole_last_test") ?? null).toBeNull();
    await sentinel.watch.poll();
    expect(settings.get("pihole_last_test")).toMatchObject({ ok: false, message: expect.stringMatching(/refused the password/) });
  });
});
