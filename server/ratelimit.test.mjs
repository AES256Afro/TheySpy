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


  it("charges a hit that did several pieces of work for all of them", () => {
    let t = 0;
    const limit = createRateLimit({ limit: 10, windowMs: 60_000, now: () => t });
    expect(limit.hit("a", 8)).toBe(0);
    // Two more is still within ten; the next one is not.
    expect(limit.hit("a", 2)).toBe(0);
    expect(limit.hit("a")).toBe(60);
    // A cost over the whole limit in one go is refused on a fresh window too.
    expect(limit.hit("b", 11)).toBe(60);
  });

  it("drops keys a window at a time instead of sweeping on every hit", () => {
    let t = 0;
    const limit = createRateLimit({ limit: 1, windowMs: 1_000, now: () => t });
    for (let i = 0; i < 500; i += 1) limit.hit(`caller-${i}`);
    expect(limit.size()).toBe(500);
    t = 5_000;
    limit.hit("someone else");
    expect(limit.size()).toBe(1);
  });
});
