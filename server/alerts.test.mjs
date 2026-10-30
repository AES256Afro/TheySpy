import { describe, expect, it } from "vitest";
import { openDatabase } from "./db.mjs";
import { fakePihole, testClock, testServices } from "./test-helpers.mjs";

function ntfy() {
  const sent = [];
  const fetchImpl = async (url, init) => { sent.push({ url: String(url), title: init.headers.Title, priority: init.headers.Priority, auth: init.headers.Authorization ?? null, body: String(init.body) }); return new Response("", { status: 200 }); };
  return { sent, fetchImpl };
}

describe("alerts", () => {
  it("sends each alert once, even after a restart on the same database (M9 exit criterion)", async () => {
    const db = openDatabase(":memory:");
    const box = ntfy();
    const now = testClock("2026-10-29T12:00:00.000Z");
    const first = testServices({ db, now, ntfyFetch: box.fetchImpl, ntfyEnv: { url: "https://ntfy.example", topic: "home-alerts", token: "tk_secret" } });
    first.fleet.observe([{ ip: "192.168.8.1", mac: "94:83:c4:e5:70:cc", seenAt: now().toISOString() }], "pihole"); // the first inventory: no alert
    first.fleet.observe([{ ip: "192.168.8.88", mac: "3c:a9:f4:00:00:21", vendor: "Espressif Inc.", seenAt: now().toISOString() }], "sweep");
    await new Promise((r) => setTimeout(r, 0));
    expect(box.sent).toEqual([expect.objectContaining({ url: "https://ntfy.example/home-alerts", title: "New device on your network", auth: "Bearer tk_secret", body: expect.stringContaining("Espressif Inc. at 192.168.8.88") })]);

    // A restart: new services, same database. The same event raises nothing new.
    const again = testServices({ db, now, ntfyFetch: box.fetchImpl, ntfyEnv: { url: "https://ntfy.example", topic: "home-alerts" } });
    again.audit.record("system", "fleet.new_device", "3c:a9:f4:00:00:21", { ip: "192.168.8.88", mac: "3c:a9:f4:00:00:21", vendor: "Espressif Inc.", source: "sweep" });
    await new Promise((r) => setTimeout(r, 0));
    expect(box.sent).toHaveLength(1);
    expect(again.alerts.recent()).toMatchObject([{ kind: "new_device", delivered: true }]);
  });

  it("alerts on indicator lookups once per device and indicator a day, urgently when not blocked", async () => {
    const box = ntfy();
    const now = testClock("2026-10-29T12:00:00.000Z");
    const pihole = fakePihole({ queries: [{ id: 1, time: Date.parse("2026-10-29T11:00:00Z") / 1000, type: "A", domain: "fearevolve.com", cname: null, status: "FORWARDED", client: { ip: "192.168.8.218", name: null } }] });
    const { sentinel, fleet, alerts } = testServices({ now, piholeFetch: pihole.fetchImpl, ntfyFetch: box.fetchImpl, ntfyEnv: { url: "https://ntfy.example", topic: "t" } });
    fleet.observe([{ ip: "192.168.8.218", mac: "c4:5b:ac:88:22:8d", seenAt: now().toISOString() }], "pihole");
    fleet.setNames(fleet.list()[0].id, { pihole: "iPhone" });
    sentinel.configure({ mode: "api", url: "http://192.0.2.5", password: "pihole-pass" }, "owner");
    await sentinel.hunt();
    pihole.state.queries.push({ id: 2, time: Date.parse("2026-10-29T11:30:00Z") / 1000, type: "A", domain: "fearevolve.com", cname: null, status: "FORWARDED", client: { ip: "192.168.8.218", name: null } });
    await sentinel.hunt();
    await new Promise((r) => setTimeout(r, 0));
    expect(box.sent).toHaveLength(1);
    expect(box.sent[0]).toMatchObject({ priority: "5", title: "A device reached a spyware/ADINT address", body: expect.stringContaining("iPhone (192.168.8.218) looked up fearevolve[.]com") });
    expect(alerts.recent()[0].kind).toBe("indicator_lookup");
  });

  it("keeps alerts when ntfy is not set, and retries the undelivered ones", async () => {
    let up = false;
    const sent = [];
    const fetchImpl = async (url, init) => { if (!up) throw new Error("connection refused"); sent.push(init.headers.Title); return new Response("", { status: 200 }); };
    const { alerts } = testServices({ ntfyFetch: fetchImpl, ntfyEnv: { url: "https://ntfy.example", topic: "t" } });
    await alerts.raise({ key: "x", kind: "pihole_down", priority: "high", title: "TheySpy cannot reach Pi-hole", message: "m" });
    expect(alerts.recent()[0]).toMatchObject({ delivered: false, error: "connection refused" });
    up = true;
    expect(await alerts.retry()).toBe(1);
    expect(sent).toEqual(["TheySpy cannot reach Pi-hole"]);
    expect(() => alerts.configure({ url: "ftp://x" }, "owner")).toThrow(/ntfy address/);
  });

  it("composes the weekly briefing and sends it once a week", async () => {
    const box = ntfy();
    const { digest, fleet, now } = testServices({ now: testClock("2026-10-26T09:00:00.000Z"), ntfyFetch: box.fetchImpl, ntfyEnv: { url: "https://n.example", topic: "t" } });
    fleet.observe([{ ip: "192.168.8.10", mac: "aa:bb:cc:00:00:01", seenAt: now().toISOString() }], "pihole");
    const d = digest.compose(7);
    expect(d.week).toBe("2026-W44");
    expect(d.sections.map((s) => s.title)).toEqual(["Spyware and ad-intelligence", "Your devices", "Vulnerabilities", "Blocklists"]);
    expect(await digest.sendWeekly()).toBe(true);
    expect(await digest.sendWeekly()).toBe(false);
    expect(box.sent).toHaveLength(1);
  });
});
