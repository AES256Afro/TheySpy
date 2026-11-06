import { describe, expect, it } from "vitest";
import { intParam, intQuery } from "./params.mjs";

describe("numbers from a request", () => {
  it("takes a whole number, and refuses anything else with a 400 that names it", () => {
    expect(intParam("12", "The job id")).toBe(12);
    expect(intParam(12, "The job id")).toBe(12);
    expect(intParam("0", "The job id")).toBe(0);
    for (const bad of ["abc", "", "1.5", "-3", "0x10", "1e3", " 1", " ", null, undefined, {}, ["1"], NaN, -1, 1.5]) {
      let thrown;
      try { intParam(bad, "The job id"); } catch (error) { thrown = error; }
      expect(thrown, `${JSON.stringify(bad)} should be refused`).toMatchObject({ status: 400, message: "The job id must be a whole number" });
    }
  });

  it("falls back when a query number is absent, clamps it when present, refuses junk", () => {
    expect(intQuery(undefined, { name: "limit", fallback: 100 })).toBe(100);
    expect(intQuery("", { name: "limit", fallback: 100 })).toBe(100);
    expect(intQuery("20", { name: "limit", fallback: 100, min: 1, max: 500 })).toBe(20);
    expect(intQuery("9000", { name: "limit", fallback: 100, min: 1, max: 500 })).toBe(500);
    expect(intQuery("0", { name: "limit", fallback: 100, min: 1, max: 500 })).toBe(1);
    // Repeated query parameters arrive as an array, which is not a number either.
    for (const bad of ["abc", "1.5", ["1", "2"]]) {
      expect(() => intQuery(bad, { name: "limit", fallback: 100 })).toThrow(/limit must be a whole number/);
    }
  });
});
