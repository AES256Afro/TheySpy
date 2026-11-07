import { describe, expect, it } from "vitest";
import { readConfig } from "./config.mjs";

describe("TS_SCAN_RANGES (M38)", () => {
  it("takes IPv6 ranges beside IPv4 ones, and names what it refuses", () => {
    expect(readConfig({ TS_SCAN_RANGES: "192.168.1.0/24, fd00::/8" }).scanRanges).toEqual(["192.168.1.0/24", "fd00::/8"]);
    expect(readConfig({}).scanRanges).toContain("fe80::/10");
    expect(() => readConfig({ TS_SCAN_RANGES: "192.168.1.0/24,home" })).toThrow('TS_SCAN_RANGES: "home" is not an IPv4 or IPv6 range such as 192.168.1.0/24 or fd00::/8');
  });
});
