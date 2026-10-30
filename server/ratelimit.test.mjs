import { describe, expect, it } from "vitest";
import { createRateLimit } from "./ratelimit.mjs";

describe("rate limit", () => {
  it("allows the limit per window, then says how long to wait, per key", () => {
    let t = 0;
    const limit = createRateLimit({ limit: 3, windowMs: 60_000, now: () => t });
    expect([1, 2, 3].map(() => limit.hit("a"))).toEqual([0, 0, 0]);
    expect(limit.hit("a")).toBe(60);
    expect(limit.hit("b")).toBe(0);
    t = 30_000;
    expect(limit.hit("a")).toBe(30);
    t = 60_000;
    expect(limit.hit("a")).toBe(0);
  });
});
