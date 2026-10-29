import { describe, expect, it } from "vitest";
import { parseIocText } from "../iocs/parse.mjs";
import { wildcardRegex } from "./client.mjs";
import { createMatcher, findHits, fromApi, isBlocked, statusName } from "./match.mjs";

const set = parseIocText([
  "powerium.net\tdelivery\tprimary\tt",
  "noas.powerium.net\tdelivery\tprimary\tt",
  "c2-node.example\tcc\tprimary\tt",
  "203.0.113.5\tcandiru-ip\tsecondary\tt",
].join("\n"));
const matcher = createMatcher(set);
const q = (domain, extra = {}) => ({ queryId: 1, at: "2026-10-29T12:00:00.000Z", domain, cname: null, status: "FORWARDED", clientIp: "192.168.1.42", clientName: null, ...extra });

describe("matching DNS queries to indicators", () => {
  it("matches the name and its subdomains, never a lookalike", () => {
    expect(matcher.match("powerium.net")?.value).toBe("powerium.net");
    expect(matcher.match("cdn.powerium.net.")?.value).toBe("powerium.net");
    expect(matcher.match("notpowerium.net")).toBeNull();
    expect(matcher.match("powerium.network")).toBeNull();
    expect(matcher.match("C2-NODE.EXAMPLE")?.value).toBe("c2-node.example");
  });

  it("credits the most specific indicator", () => {
    expect(matcher.match("x.noas.powerium.net")?.value).toBe("noas.powerium.net");
  });

  it("ignores IP indicators, which a DNS name cannot match", () => {
    expect(matcher.size).toBe(3);
    expect(matcher.match("203.0.113.5")).toBeNull();
  });

  it("counts a lookup blocked by its CNAME target", () => {
    const hits = findHits([q("innocent.example.org", { cname: "noas.powerium.net", status: "DENYLIST_CNAME" }), q("other.example.org", { cname: "noas.powerium.net", status: "FORWARDED" })], matcher);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ indicator: "noas.powerium.net", via: "cname", blocked: true });
  });

  it("tells allowed from blocked", () => {
    expect(isBlocked("GRAVITY")).toBe(true);
    expect(isBlocked("BLACKLIST")).toBe(true);
    expect(isBlocked("FORWARDED")).toBe(false);
    expect(isBlocked("CACHE")).toBe(false);
    expect(statusName(5)).toBe("DENYLIST");
    expect(statusName("cache")).toBe("CACHE");
  });

  it("reads Pi-hole's API rows", () => {
    expect(fromApi({ id: 7, time: 1793300000.5, domain: "Ads.Example.", cname: null, status: "GRAVITY", client: { ip: "192.168.1.9", name: "tv.lan" } }))
      .toEqual({ queryId: 7, at: new Date(1793300000500).toISOString(), domain: "ads.example", cname: null, status: "GRAVITY", clientIp: "192.168.1.9", clientName: "tv.lan" });
  });

  it("writes Pi-hole's own wildcard pattern", () => {
    expect(wildcardRegex("noas.powerium.net")).toBe("(\\.|^)noas\\.powerium\\.net$");
    expect(new RegExp(wildcardRegex("powerium.net")).test("cdn.powerium.net")).toBe(true);
    expect(new RegExp(wildcardRegex("powerium.net")).test("notpowerium.net")).toBe(false);
  });
});
