import { describe, expect, it } from "vitest";
import { adguardSource, opnsenseSource, technitiumSource } from "./connectors.mjs";
import { createMatcher } from "./match.mjs";

// AdGuard Home and Technitium are also checked against the real servers (scripts/e2e-dns-sources.sh).
// OPNsense cannot run here: its answers below follow its own code, OverviewController::searchQueriesAction
// and scripts/unbound/stats.py (rows of time, client, domain, action, source, rcode).
const matcher = createMatcher({ indicators: [{ type: "domain", value: "fearevolve.com", tier: "delivery" }] });
const now = Math.floor(Date.now() / 1000);

describe("OPNsense (Unbound reporting)", () => {
  function opnsense(rows, enabled = 1) {
    const calls = [];
    const fetchImpl = async (url, init = {}) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith("/isEnabled")) return Response.json({ enabled });
      if (String(url).includes("/totals/")) return Response.json({ top: { "example.com": { total: 9 } }, top_blocked: { "ads.example": { total: 4 } } });
      return Response.json({ total: rows.length, rowCount: rows.length, current: 1, rows });
    };
    return { source: opnsenseSource({ url: "https://fw.lan", username: "key", password: "secret", fetchImpl }), calls };
  }
  const row = (domain, extra = {}) => ({ time: now - 60, client: "192.168.1.20", family: "IPv4", type: "A", domain, action: "Pass", source: "Recursion", rcode: "NOERROR", ...extra });

  it("finds indicator lookups, marks Block and Drop as blocked, and sends the key and secret", async () => {
    const { source, calls } = opnsense([row("cdn.fearevolve.com", { action: "Block" }), row("fearevolve.com", { action: "Drop" }), row("notfearevolve.com"), row("example.com", { source: "Cache" })]);
    const { hits } = await source.recent(matcher, now - 300);
    expect(hits.map((h) => [h.domain, h.blocked])).toEqual([["cdn.fearevolve.com", true], ["fearevolve.com", true]]);
    expect(calls[0].init.headers.authorization).toBe(`Basic ${Buffer.from("key:secret").toString("base64")}`);
    expect(String(calls[0].init.body)).toContain("rowCount=1000");
  });

  it("keeps a hostname OPNsense resolved as the client's name, and counts the network from its totals", async () => {
    const { source } = opnsense([row("fearevolve.com", { client: "kids-ipad.lan" })]);
    const [q] = await source.lookupsOf("fearevolve.com", { from: now - 300, until: now });
    expect(q).toMatchObject({ clientIp: "kids-ipad.lan", clientName: "kids-ipad.lan", status: "FORWARDED" });
    expect((await source.domainCounts({ from: now - 86400, until: now })).rows).toEqual([{ domain: "example.com", queries: 9, blocked: 0 }, { domain: "ads.example", queries: 4, blocked: 4 }]);
  });

  it("says what to turn on when reporting is off", async () => {
    await expect(opnsense([], 0).source.test()).rejects.toThrow(/Statistics/);
  });
});

describe("the same interface for every DNS server", () => {
  it("never claims it can change lists, and has no network table", async () => {
    const none = async () => Response.json({});
    for (const source of [adguardSource({ url: "http://a", username: "u", password: "p", fetchImpl: none }), technitiumSource({ url: "http://t", password: "x", fetchImpl: none }), opnsenseSource({ url: "http://o", username: "k", password: "s", fetchImpl: none })]) {
      expect(source.canWrite).toBe(false);
      expect(await source.networkDevices()).toEqual([]);
    }
  });

  it("explains a refused sign-in in the server's words", async () => {
    const refused = async () => new Response("", { status: 401 });
    await expect(adguardSource({ url: "http://a", username: "u", password: "bad", fetchImpl: refused }).test()).rejects.toThrow(/AdGuard Home refused the sign-in/);
    const badToken = async () => Response.json({ status: "invalid-token" });
    await expect(technitiumSource({ url: "http://t", password: "bad", fetchImpl: badToken }).test()).rejects.toThrow(/API token/);
  });
});
