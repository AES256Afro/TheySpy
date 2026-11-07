import { describe, expect, it } from "vitest";
import { createQuietRunner } from "./quietly.mjs";
import { testClock, testServices } from "./test-helpers.mjs";

describe("quiet scheduled work (M18, B28)", () => {
  it("records a failure under its name, clears it on the next success, and never runs twice at once", async () => {
    const { settings } = testServices({ now: testClock("2026-11-07T12:00:00Z") });
    const quiet = createQuietRunner({ settings, prefix: "fleet", now: testClock("2026-11-07T12:00:00Z") });
    let fail = true;
    let runs = 0;
    const sync = quiet.wrap("sync", async () => { runs += 1; await new Promise((r) => setTimeout(r, 5)); if (fail) throw new Error("Pi-hole refused the password"); });
    await Promise.all([sync(), sync()]); // the second call finds the first running and does nothing
    expect(runs).toBe(1);
    expect(quiet.errors(["sync", "sweep"])).toEqual({ sync: { at: "2026-11-07T12:00:00.000Z", error: "Pi-hole refused the password" } });
    fail = false;
    await sync();
    expect(quiet.errors(["sync", "sweep"])).toEqual({});
  });
});
