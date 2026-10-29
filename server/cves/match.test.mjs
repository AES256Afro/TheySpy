import { describe, expect, it } from "vitest";
import { compareVersions, matchSoftware, parseCpe } from "./match.mjs";

const chrome = (v) => ({ vendor: "google", product: "chrome", version: v });
const kevFix = [{ criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", vee: "141.0.7390.65" }];

describe("version matching", () => {
  it("compares versions part by part, numbers as numbers", () => {
    expect(compareVersions("141.0.7390.54", "141.0.7390.65")).toBeLessThan(0);
    expect(compareVersions("141.0.7390.100", "141.0.7390.65")).toBeGreaterThan(0);
    expect(compareVersions("9.6p1", "9.6")).toBeGreaterThan(0);
    expect(compareVersions("1.0", "1.0.1")).toBeLessThan(0);
    expect(compareVersions("1.0rc1", "1.0")).toBeLessThan(0);
    expect(compareVersions("2.4.58", "2.4.58")).toBe(0);
  });

  it("flags a Chrome one version behind a fix, and not the patched one (M6 exit criterion)", () => {
    expect(matchSoftware(chrome("141.0.7390.54"), kevFix)).toEqual({ confidence: "range", criteria: kevFix[0].criteria, fixed: "141.0.7390.65" });
    expect(matchSoftware(chrome("141.0.7390.65"), kevFix)).toBeNull();
    expect(matchSoftware(chrome(null), kevFix)).toMatchObject({ confidence: "product" });
  });

  it("matches exact CPE versions and inclusive bounds, and never another product", () => {
    const m = [{ criteria: "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*" }, { criteria: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", vsi: "8.5", vei: "9.7" }];
    expect(matchSoftware({ vendor: "openbsd", product: "openssh", version: "9.6" }, m)).toMatchObject({ confidence: "exact" });
    expect(matchSoftware({ vendor: "openbsd", product: "openssh", version: "9.7" }, m)).toMatchObject({ confidence: "range" });
    expect(matchSoftware({ vendor: "openbsd", product: "openssh", version: "9.8" }, m)).toBeNull();
    expect(matchSoftware({ vendor: "openbsd", product: "openssh", version: "8.4" }, m)).toBeNull();
    expect(matchSoftware({ vendor: "f5", product: "nginx", version: "1.24.0" }, m)).toBeNull();
    expect(parseCpe("cpe:2.3:o:apple:iphone_os:18.0:*:*:*:*:*:*:*")).toMatchObject({ part: "o", vendor: "apple", product: "iphone_os", version: "18.0" });
  });
});
