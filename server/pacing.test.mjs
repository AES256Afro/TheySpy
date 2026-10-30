import { describe, expect, it } from "vitest";
import { createPacedFetch, retryAfterMs } from "./pacing.mjs";

function world() {
  let t = Date.parse("2026-10-30T12:00:00.000Z");
  const sent = [];
  const answers = new Map();
  const base = async (input) => { sent.push([String(input), t]); return answers.get(new URL(String(input)).hostname)?.() ?? new Response("ok"); };
  const entries = [];
  const audit = { record: (...args) => entries.push(args) };
  const paced = createPacedFetch(/** @type {any} */ (base), {
    budgets: { "api.github.com": { minIntervalMs: 1_000, perHour: 3 }, "services.nvd.nist.gov": { minIntervalMs: 600, perHour: 100, slowDown: [403], quietMs: 30_000 }, default: { minIntervalMs: 250, perHour: 1_000 } },
    audit, now: () => t, sleep: async (ms) => { t += ms; },
  });
  return { paced, sent, answers, entries, advance: (ms) => { t += ms; }, now: () => t };
}

describe("pacing outside services", () => {
  it("spaces requests to the same host and leaves other hosts alone", async () => {
    const w = world();
    await w.paced.fetch("https://api.github.com/a");
    await w.paced.fetch("https://api.github.com/b");
    await w.paced.fetch("https://www.cisa.gov/kev.json");
    expect(w.sent.map(([url, at]) => [new URL(url).pathname, at - w.sent[0][1]])).toEqual([["/a", 0], ["/b", 1_000], ["/kev.json", 1_000]]);
  });

  it("keeps to an hourly budget: waits when the wait is short, refuses plainly when it is long", async () => {
    const w = world();
    for (const path of ["1", "2", "3"]) await w.paced.fetch(`https://api.github.com/${path}`);
    const refused = await w.paced.fetch("https://api.github.com/4").catch((e) => e);
    expect(refused).toMatchObject({ code: "TS_RATE_LIMITED" });
    expect(refused.message).toMatch(/hourly budget for api\.github\.com \(3 requests\) is used up; trying again after 13:00 UTC/);
    w.advance(3_600_000 - 2_000 - 60_000); // a minute before the first one leaves the hour
    await w.paced.fetch("https://api.github.com/5");
    expect(w.sent).toHaveLength(4);
    expect(w.now()).toBe(Date.parse("2026-10-30T13:00:00.000Z"));
  });

  it("holds back from a host that says slow down, for as long as it asks, and records it once", async () => {
    const w = world();
    w.answers.set("api.github.com", () => new Response("", { status: 429, headers: { "retry-after": "90" } }));
    expect((await w.paced.fetch("https://api.github.com/x")).status).toBe(429);
    w.answers.delete("api.github.com");
    const start = w.now();
    await w.paced.fetch("https://api.github.com/y");
    expect(w.now() - start).toBe(90_000);
    expect(w.entries).toEqual([["system", "egress.rate_limited", "api.github.com", { status: 429, until: "2026-10-30T12:01:30.000Z" }]]);

    w.answers.set("api.github.com", () => new Response("", { status: 429, headers: { "retry-after": "3600" } }));
    await w.paced.fetch("https://api.github.com/z");
    expect(await w.paced.fetch("https://api.github.com/w").catch((e) => e.message)).toMatch(/api\.github\.com asked TheySpy to slow down; trying again after/);
    expect(w.paced.held()).toEqual([{ host: "api.github.com", until: expect.any(String) }]);
    expect(w.entries).toHaveLength(1);
  });

  it("knows NVD's own way of saying too many (403), and reads Retry-After in both forms", async () => {
    const w = world();
    w.answers.set("services.nvd.nist.gov", () => new Response("", { status: 403 }));
    await w.paced.fetch("https://services.nvd.nist.gov/rest/json/cves/2.0");
    w.answers.delete("services.nvd.nist.gov");
    const start = w.now();
    await w.paced.fetch("https://services.nvd.nist.gov/rest/json/cves/2.0");
    expect(w.now() - start).toBe(30_000);
    expect(retryAfterMs("120", 0)).toBe(120_000);
    expect(retryAfterMs("Thu, 30 Oct 2026 12:02:00 GMT", Date.parse("2026-10-30T12:00:00Z"))).toBe(120_000);
    expect(retryAfterMs("soon", 0)).toBeNull();
  });
});
