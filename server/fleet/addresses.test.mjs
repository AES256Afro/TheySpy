import { describe, expect, it } from "vitest";
import { hostsOf, inCidr, isRandomisedMac, normaliseMac, parseCidr, slash24 } from "./addresses.mjs";

describe("addresses", () => {
  it("parses IPv4 ranges and lists a sweep's hosts", () => {
    expect(parseCidr("192.168.1.77/24")).toMatchObject({ cidr: "192.168.1.0/24", prefix: 24, size: 256 });
    expect(parseCidr("10.0.0.5")).toMatchObject({ cidr: "10.0.0.5/32", size: 1 });
    for (const bad of ["192.168.1.0/33", "192.168.1/24", "fd00::/8", "192.168.1.0/24/1", "x", "192.168.1.0/2x"]) expect(parseCidr(bad)).toBeNull();
    expect(hostsOf("192.168.1.0/30")).toEqual(["192.168.1.1", "192.168.1.2"]);
    expect(hostsOf("192.168.1.0/24")).toHaveLength(254);
    expect(inCidr("172.20.3.4", "172.16.0.0/12")).toBe(true);
    expect(inCidr("172.32.0.1", "172.16.0.0/12")).toBe(false);
    expect(slash24("192.168.7.200")).toBe("192.168.7.0/24");
  });

  it("normalises MACs and spots randomised (private) ones", () => {
    expect(normaliseMac("A4-C1-38-0A-0B-19")).toBe("a4:c1:38:0a:0b:19");
    expect(normaliseMac("a4c1.380a.0b19")).toBe("a4:c1:38:0a:0b:19");
    expect(normaliseMac("00:00:00:00:00:00")).toBeNull();
    expect(normaliseMac("ip-192.168.1.4")).toBeNull();
    expect(isRandomisedMac("da:a1:19:00:00:01")).toBe(true);
    expect(isRandomisedMac("a4:c1:38:0a:0b:19")).toBe(false);
  });


  it("refuses to list the addresses of a range too big to sweep, rather than building them", () => {
    expect(() => hostsOf("10.0.0.0/8")).toThrow(/holds 16777216 addresses/);
    expect(() => hostsOf("192.168.0.0/16")).toThrow(/one sweep visits at most 1024/);
    expect(hostsOf("192.168.4.0/22")).toHaveLength(1022);
  });
});

describe("IPv6 (M38)", () => {
  it("spells an address one way: mapped IPv4 as IPv4, IPv6 lower-case and compressed, zones and brackets gone", async () => {
    const { canonicalIp } = await import("./addresses.mjs");
    expect(canonicalIp("::ffff:192.168.1.5")).toBe("192.168.1.5");
    expect(canonicalIp("::FFFF:192.168.1.5")).toBe("192.168.1.5");
    expect(canonicalIp("2001:DB8:0:0:0:0:0:1")).toBe("2001:db8::1");
    expect(canonicalIp("[2001:db8::1]")).toBe("2001:db8::1");
    expect(canonicalIp("fe80::1%eth0")).toBe("fe80::1");
    expect(canonicalIp("192.168.1.5")).toBe("192.168.1.5");
    expect(canonicalIp("phone.local")).toBeNull();
    expect(canonicalIp("")).toBeNull();
    expect(canonicalIp(null)).toBeNull();
  });

  it("knows IPv6 ranges: in the scope guard, never in a sweep", async () => {
    const { parseRange, privateRanges } = await import("./addresses.mjs");
    expect(inCidr("fd7a:115c:a1e0:ab12::1", "fd7a:115c:a1e0::/48")).toBe(true);
    expect(inCidr("fd00::1", "fd7a:115c:a1e0::/48")).toBe(false);
    expect(inCidr("FE80::1", "fe80::/10")).toBe(true);
    expect(inCidr("2001:db8::1", "fc00::/7")).toBe(false);
    expect(inCidr("192.168.1.5", "fc00::/7")).toBe(false);
    expect(inCidr("fd00::1", "192.168.0.0/16")).toBe(false);
    expect(inCidr("::ffff:192.168.1.5", "192.168.0.0/16")).toBe(true);
    expect(parseRange("fd00::/8")).toEqual({ family: 6, cidr: "fd00::/8", address: "fd00::", prefix: 8 });
    expect(parseRange("2001:DB8::1")).toMatchObject({ family: 6, cidr: "2001:db8::1/128" });
    expect(parseRange("fd00::/129")).toBeNull();
    expect(parseRange("fd00::/8/x")).toBeNull();
    expect(parseRange("192.168.1.0/24")).toMatchObject({ family: 4, first: 3232235776 });
    expect(hostsOf("fd00::/64")).toEqual([]);
    expect(privateRanges).toContain("fc00::/7");
  });
});
