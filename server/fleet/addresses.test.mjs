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
});
