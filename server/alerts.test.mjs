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
    first.fleet.observe([{ ip: "192.168.8.1", mac: "94:83:c4:00:00:cc", seenAt: now().toISOString() }], "pihole"); // the first inventory: no alert
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
    fleet.observe([{ ip: "192.168.8.218", mac: "c4:5b:ac:00:00:8d", seenAt: now().toISOString() }], "pihole");
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

describe("sweep 3 (M14)", () => {
  const at = (iso) => new Date(iso).toISOString();
  const hit = (db, i, when, blocked) => db.prepare("INSERT INTO ioc_hit_events (source, query_id, at, indicator, domain, via, client_ip, client_name, status, blocked, found_by, found_at) VALUES ('pihole', ?, ?, 'adfection-c2.example', 'adfection-c2.example', 'query', '192.168.1.30', 'laptop', ?, ?, 'hunt', ?)").run(i, when, blocked ? "GRAVITY" : "FORWARDED", blocked ? 1 : 0, when);

  it("B18: the briefing counts the week's lookups, not the groups they fall in", () => {
    const { digest, db } = testServices({ now: testClock("2026-11-05T12:00:00Z"), piholeEnv: { url: "http://pihole.lan", password: "x", write: false } });
    // 500 unblocked lookups of one C2 since July, then three this week - all blocked.
    for (let i = 0; i < 500; i += 1) hit(db, i, at(new Date(Date.parse("2026-07-01T00:00:00Z") + i * 2 * 3600_000).toISOString()), false);
    for (let i = 0; i < 3; i += 1) hit(db, 9000 + i, at(`2026-11-0${3 + i}T09:00:00Z`), true);
    const spyware = digest.compose(7).sections[0];
    expect(spyware.lines[0]).toBe("3 lookups of indicator addresses by 1 device; every one blocked.");
    expect(spyware.tone).toBe("warn");
    // Old unblocked history does not make this week "not fully blocked"; an unblocked one this week does.
    hit(db, 9100, at("2026-11-04T10:00:00Z"), false);
    const after = digest.compose(7).sections[0];
    expect(after.tone).toBe("bad");
    expect(after.lines[0]).toBe("4 lookups of indicator addresses by 1 device; 1 not blocked.");
  });

  it("B19: the briefing names every device on an exploited CVE, dots and all", async () => {
    const { digest, alerts, audit } = testServices({ now: testClock("2026-11-05T12:00:00Z") });
    // The matches an alert was raised with travel with it, not inside its prose.
    await alerts.raise({ key: "exploited:CVE-2026-12345", kind: "kev_match", priority: "high", title: "Exploited vulnerability in software you run", message: "CVE-2026-12345 (on laptop.local, nas.lan). CISA lists it as exploited in the wild; update those devices.", detail: { matches: [{ cveId: "CVE-2026-12345", devices: ["laptop.local", "nas.lan"] }] } });
    void audit;
    const vulns = digest.compose(7).sections.find((s) => s.title === "Vulnerabilities");
    expect(vulns.lines[1]).toBe("In software you run: CVE-2026-12345 on laptop.local, nas.lan.");
  });
});

describe("M34, feature 6: an alert lands on the device", () => {
  it("links a new-device alert and a one-device lookup alert to the device page, and the rest to their screens", async () => {
    const now = testClock("2026-11-07T12:00:00.000Z");
    const { fleet, audit, alerts, settings } = testServices({ now, ntfyEnv: { url: "https://ntfy.example", topic: "t" } });
    settings.set("lists_base_url", "https://home.example:8797");
    fleet.observe([{ ip: "192.168.8.1", mac: "94:83:c4:00:00:cc", seenAt: now().toISOString() }], "pihole"); // the inventory
    fleet.observe([{ ip: "192.168.8.88", mac: "3c:a9:f4:00:00:21", vendor: "Espressif Inc.", seenAt: now().toISOString() }], "sweep");
    await new Promise((r) => setTimeout(r, 0));
    const device = fleet.list().find((d) => d.ip === "192.168.8.88");
    expect(alerts.recent().find((a) => a.kind === "new_device")).toMatchObject({ link: `https://home.example:8797/fleet/devices/${device.id}` });
    audit.record("system", "pihole.indicator_lookups", null, { lookups: 2, indicators: ["c2.example"], clients: ["192.168.8.88"], allowed: 1 });
    audit.record("system", "pihole.indicator_lookups", null, { lookups: 2, indicators: ["c2.example"], clients: ["192.168.8.88", "192.168.8.1"], allowed: 1 });
    await new Promise((r) => setTimeout(r, 0));
    const lookups = alerts.recent().filter((a) => a.kind === "indicator_lookup").map((a) => a.link).sort();
    expect(lookups).toEqual([`https://home.example:8797/fleet/devices/${device.id}`, "https://home.example:8797/pihole"]);
  });
});

describe("the webhook channel (M36)", () => {
  function hooks() {
    const sent = { ntfy: [], webhook: [] };
    let failNtfy = false;
    const fetchImpl = async (url, init) => {
      if (String(url).startsWith("https://hooks.example/")) { sent.webhook.push({ headers: init.headers, body: String(init.body) }); return new Response("", { status: 200 }); }
      sent.ntfy.push({ url: String(url) });
      return new Response("", { status: failNtfy ? 503 : 200 });
    };
    return { sent, fetchImpl, breakNtfy() { failNtfy = true; }, mendNtfy() { failNtfy = false; } };
  }

  it("POSTs each alert as signed JSON, and a retry sends only to the channel that has not had it", async () => {
    const { createHmac } = await import("node:crypto");
    const box = hooks();
    const now = testClock("2026-11-07T12:00:00.000Z");
    const { alerts, audit, settings } = testServices({ now, ntfyFetch: box.fetchImpl, ntfyEnv: { url: "https://ntfy.example", topic: "t" } });
    expect(alerts.configureWebhook({ url: "https://hooks.example/theyspy", secret: "hush" }, "owner")).toEqual({ url: "https://hooks.example/theyspy", hasSecret: true, ready: true });
    expect(audit.list(1)[0]).toMatchObject({ action: "alerts.webhook_configured", detail: { url: "https://hooks.example/theyspy", secret: "(changed)" } });
    expect(JSON.stringify(settings.get("alerts_webhook"))).not.toContain("hush");

    box.breakNtfy();
    expect(await alerts.raise({ key: "k1", kind: "new_device", title: "New device on your network", message: "Something at 192.168.8.88", link: "https://ts.example/fleet", detail: { ip: "192.168.8.88" } })).toBe(true);
    expect(box.sent.webhook).toHaveLength(1);
    const [{ headers, body }] = box.sent.webhook;
    expect(JSON.parse(body)).toEqual({ event: "alert", key: "k1", at: "2026-11-07T12:00:00.000Z", kind: "new_device", priority: "default", title: "New device on your network", message: "Something at 192.168.8.88", link: "https://ts.example/fleet", detail: { ip: "192.168.8.88" } });
    expect(headers["x-theyspy-event"]).toBe("alert");
    expect(headers["x-theyspy-signature"]).toBe(`sha256=${createHmac("sha256", "hush").update(body).digest("hex")}`);
    // ntfy failed, so the alert is not delivered yet, and the error names the channel.
    expect(alerts.recent()).toMatchObject([{ key: "k1", delivered: false, error: "ntfy: ntfy answered 503" }]);

    box.mendNtfy();
    expect(await alerts.retry()).toBe(1);
    expect(alerts.recent()).toMatchObject([{ key: "k1", delivered: true, error: null }]);
    expect(box.sent.ntfy).toHaveLength(2); // the failed try and the retry
    expect(box.sent.webhook).toHaveLength(1); // not sent twice
  });

  it("works as the only channel, refuses a bad address, and the test says which channels it reached", async () => {
    const box = hooks();
    const now = testClock("2026-11-07T12:00:00.000Z");
    const { alerts } = testServices({ now, ntfyFetch: box.fetchImpl });
    expect(alerts.config().ready).toBe(false);
    await expect(alerts.test()).rejects.toThrow("Set up ntfy or a webhook first");
    now.advance(1000); // a test notification's key is its time
    expect(() => alerts.configureWebhook({ url: "ftp://hooks.example/x" }, "owner")).toThrow("The webhook address must be an http(s) URL");
    expect(() => alerts.configureWebhook({ url: "https://user:pw@hooks.example/x" }, "owner")).toThrow("The webhook address must be an http(s) URL");
    alerts.configureWebhook({ url: "https://hooks.example/only" }, "owner");
    expect(alerts.webhookConfig()).toEqual({ url: "https://hooks.example/only", hasSecret: false, ready: true });
    expect(await alerts.test()).toEqual({ delivered: true, channels: ["webhook"] });
    expect(box.sent.webhook[0].headers["x-theyspy-signature"]).toBeUndefined();
    expect(box.sent.ntfy).toHaveLength(0);
  });
});
