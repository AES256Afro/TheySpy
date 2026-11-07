import { createHmac } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createApp } from "./app.mjs";
import { readConfig } from "./config.mjs";
import { fakePihole, fakeWeb, testClock, testServices, vendored } from "./test-helpers.mjs";

const servers = [];
afterEach(() => { for (const server of servers.splice(0)) server.close(); });

async function start({ env = {}, staticDirectory, services: options = {} } = {}) {
  const services = testServices(options);
  const config = readConfig({ TS_DATA_DIR: tmpdir(), ...env });
  const app = createApp({ config, ...services, ...(staticDirectory ? { staticDirectory } : { staticDirectory: path.join(tmpdir(), "theyspy-no-dist") }) });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise((resolve) => server.once("listening", resolve));
  const { port } = /** @type {import("node:net").AddressInfo} */ (server.address());
  const base = `http://127.0.0.1:${port}`;
  let cookie = "";
  const request = async (method, url, body, headers = {}) => {
    const response = await fetch(base + url, {
      method,
      headers: { ...(body ? { "content-type": "application/json" } : {}), ...(method === "GET" ? {} : { "x-theyspy": "1" }), ...(cookie ? { cookie } : {}), ...headers },
      body: body ? JSON.stringify(body) : undefined,
    });
    const setCookie = response.headers.get("set-cookie");
    if (setCookie) cookie = setCookie.split(";")[0];
    const type = response.headers.get("content-type") ?? "";
    return { status: response.status, headers: response.headers, body: type.includes("json") ? await response.json() : await response.text() };
  };
  return { ...services, request };
}

describe("HTTP API", () => {
  it("reports health without signing in, with a strict CSP", async () => {
    const { request } = await start();
    const response = await request("GET", "/healthz");
    expect(response).toMatchObject({ status: 200, body: { ok: true } });
    expect(response.headers.get("content-security-policy")).toContain("default-src 'self'");
  });

  it("signs in, runs the no-op job, and shows it in the audit log", async () => {
    const { request, jobs } = await start();
    expect((await request("GET", "/api/jobs")).status).toBe(401);
    expect((await request("POST", "/api/login", { password: "wrong" })).status).toBe(401);
    expect((await request("POST", "/api/login", { password: "correct horse" })).status).toBe(200);
    expect((await request("GET", "/api/session")).body.signedIn).toBe(true);

    const queued = await request("POST", "/api/jobs", { kind: "noop" });
    expect(queued.status).toBe(202);
    await jobs.idle();
    expect((await request("GET", `/api/jobs/${queued.body.job.id}`)).body.job.status).toBe("succeeded");
    const actions = (await request("GET", "/api/audit")).body.entries.map((entry) => entry.action);
    expect(actions).toEqual(expect.arrayContaining(["owner.signed_in", "job.queued", "job.started", "job.succeeded"]));

    expect((await request("POST", "/api/logout")).body.signedIn).toBe(false);
    expect((await request("GET", "/api/jobs")).status).toBe(401);
  });

  it("refuses state changes without the X-TheySpy header", async () => {
    const { request } = await start();
    expect((await request("POST", "/api/login", { password: "correct horse" }, { "x-theyspy": "" })).status).toBe(403);
  });

  it("serves appearance before sign-in and lets only the owner change it", async () => {
    const { request } = await start({ env: { TS_LOOK: "glass", TS_BRAND_NAME: "NetWatch" } });
    const before = await request("GET", "/api/appearance");
    expect(before.body.appearance).toMatchObject({ look: "glass", name: "NetWatch" });
    expect(before.body.options.looks).toContain("paper");
    expect((await request("PUT", "/api/appearance", { look: "paper" })).status).toBe(401);
    await request("POST", "/api/login", { password: "correct horse" });
    expect((await request("PUT", "/api/appearance", { look: "neon" })).status).toBe(400);
    expect((await request("PUT", "/api/appearance", { look: "paper", accent: "#123456" })).body.appearance).toMatchObject({ look: "paper", accent: "#123456", name: "NetWatch" });
    expect((await request("DELETE", "/api/appearance")).body.appearance.look).toBe("glass");
  });

  it("serves indicators, defanged, only to the owner", async () => {
    const { request } = await start();
    expect((await request("GET", "/api/iocs")).status).toBe(401);
    await request("POST", "/api/login", { password: "correct horse" });
    const overview = (await request("GET", "/api/iocs")).body;
    expect(overview).toMatchObject({ active: { count: 405, asof: "2026-10-18", provenance: { track: "bundled" } }, pending: null, track: "release", counts: { total: 405, byType: { domain: 292, ip: 111, sha256: 2 } } });
    const { indicators } = (await request("GET", "/api/iocs/indicators")).body;
    expect(indicators).toHaveLength(405);
    expect(indicators.filter((i) => i.type !== "sha256").every((i) => i.value.includes("[.]"))).toBe(true);
  });

  it("downloads exports that match zero-breach's files", async () => {
    const { request } = await start();
    await request("POST", "/api/login", { password: "correct horse" });
    const hosts = await request("GET", "/api/iocs/export/hosts");
    expect(hosts.headers.get("content-disposition")).toBe('attachment; filename="adfection.hosts.txt"');
    expect(hosts.body).toBe(vendored("dist/adfection.hosts.txt").toString("utf8"));
    expect((await request("GET", "/api/iocs/export/csv")).status).toBe(404);
  });

  it("checks for updates as a job, and only applies pending versions", async () => {
    const { request, jobs } = await start();
    await request("POST", "/api/login", { password: "correct horse" });
    const queued = await request("POST", "/api/iocs/check");
    expect(queued.status).toBe(202);
    await jobs.idle();
    expect((await request("GET", "/api/iocs")).body.lastCheck).toMatchObject({ outcome: "up-to-date" });
    const activeId = (await request("GET", "/api/iocs")).body.active.id;
    expect((await request("POST", `/api/iocs/versions/${activeId}/apply`)).status).toBe(409);
    expect((await request("PUT", "/api/iocs/settings", { track: "nightly" })).status).toBe(400);
    expect((await request("PUT", "/api/iocs/settings", { track: "main" })).body).toEqual({ track: "main" });
  });

  it("starts only direct job kinds from /api/jobs", async () => {
    const { request } = await start();
    await request("POST", "/api/login", { password: "correct horse" });
    expect((await request("POST", "/api/jobs", { kind: "ioc.apply" })).status).toBe(400);
    expect((await request("POST", "/api/jobs", { kind: "ioc.check" })).status).toBe(202);
  });

  it("serves compiled blocklists to Pi-hole at the secret address, in five formats", async () => {
    const { request, library } = await start();
    const token = library.listToken();
    const spyware = await request("GET", `/lists/${token}/spyware.txt`);
    expect(spyware.status).toBe(200);
    expect(spyware.body).toContain("# TheySpy Spyware & ADINT list (txt)");
    expect(spyware.body).toContain("\nfearevolve.com\n");
    expect((await request("GET", `/lists/${token}/spyware.adblock`)).body).toContain("||fearevolve.com^");
    expect((await request("GET", `/lists/${token}/security.rpz`)).body).toContain("*.fearevolve.com CNAME .");
    expect((await request("GET", "/lists/wrong-token/spyware.txt")).status).toBe(404);
    expect((await request("GET", `/lists/${token}/nonsense.txt`)).status).toBe(404);
    const again = await request("GET", `/lists/${token}/spyware.txt`, undefined, { "if-none-match": spyware.headers.get("etag") });
    expect(again.status).toBe(304);
  });

  it("manages blocklists only for the owner", async () => {
    const { request } = await start();
    expect((await request("GET", "/api/blocklists")).status).toBe(401);
    await request("POST", "/api/login", { password: "correct horse" });
    const overview = (await request("GET", "/api/blocklists")).body;
    expect(overview.sources.filter((s) => s.status === "enabled")).toHaveLength(7);
    expect(overview.subscriptions.find((l) => l.id === "spyware").url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/lists\/[\w-]+\/spyware\.adblock$/);
    expect((await request("GET", "/api/blocklists/candidates?category=bypass")).body.candidates.map((c) => c.key)).toEqual(["adguard:hagezi_encrypted_dns_vpn_tor_proxy_bypass"]);
    expect((await request("POST", "/api/blocklists/sources", { url: "ftp://x" })).status).toBe(400);
    expect((await request("PUT", "/api/blocklists/pins", { pins: ["Example.COM", "not a name"] })).body).toEqual({ pins: ["example.com"], ignored: ["not a name"] });
  });

  it("previews baselines with security names defanged, and checks what it is asked to apply", async () => {
    const at = Date.parse("2026-10-28T10:00:00Z") / 1000;
    const queries = [["fearevolve.com", 3], ["example.org", 4]].flatMap(([domain, count], j) => Array.from({ length: count }, (_, i) => ({ id: j * 10 + i + 1, time: at + i, type: "A", domain, cname: null, status: "FORWARDED", client: { ip: "192.168.1.42", name: null } })));
    const { request, sentinel } = await start({ services: { piholeFetch: fakePihole({ queries }).fetchImpl, now: () => new Date("2026-10-29T12:00:00Z") } });
    sentinel.configure({ mode: "api", url: "http://192.0.2.5", password: "pihole-pass", write: true }, "owner");
    await request("POST", "/api/login", { password: "correct horse" });
    const overview = (await request("GET", "/api/blocklists/baselines")).body;
    expect(overview.baselines.map((b) => b.id)).toEqual(["essential", "balanced", "strict", "lockdown"]);
    expect(overview.pihole).toEqual({ connected: true, api: true, write: true });
    const preview = (await request("GET", "/api/blocklists/baselines/preview?client=192.168.1.42&days=7")).body;
    expect(preview.totalQueries).toBe(7);
    expect(preview.levels[0].details.map((s) => s.site)).toEqual(["fearevolve[.]com"]);
    expect((await request("GET", "/api/blocklists/baselines/preview?days=3")).status).toBe(400);
    expect((await request("PUT", "/api/blocklists/baselines/exceptions", { scope: "device-192-168-1-42", site: "fearevolve[.]com" })).body).toEqual({ exceptions: ["fearevolve.com"] });
    expect((await request("POST", "/api/blocklists/baselines/apply", { baselineId: "extreme" })).status).toBe(400);
    expect((await request("POST", "/api/blocklists/baselines/apply", { baselineId: "strict", client: "pixel; rm" })).status).toBe(400);
    expect((await request("PUT", "/api/blocklists/baselines/custom", { categories: ["nope"] })).status).toBe(400);
    expect((await request("PUT", "/api/blocklists/baselines/custom", { name: "Mine", categories: ["ads"] })).body.custom).toMatchObject({ id: "custom", categories: ["spyware", "ads"] });
    expect((await request("DELETE", "/api/blocklists/baselines/shadow", { client: "192.168.1.42" })).status).toBe(404);
    expect((await request("POST", "/api/blocklists/baselines/shadow", { baselineId: "custom", client: "192.168.1.42" })).body.shadow).toMatchObject({ baseline: "custom", mode: "shadow" });
    expect((await request("GET", "/api/blocklists/baselines/preview?client=192.168.1.42")).body.shadow).toMatchObject({ baseline: "custom", totalQueries: 0 });
    expect((await request("DELETE", "/api/blocklists/baselines/custom")).status).toBe(409);
    expect((await request("DELETE", "/api/blocklists/baselines/shadow", { client: "192.168.1.42" })).body).toEqual({ removed: true, shadow: true });
  });

  it("serves the fleet only to the owner, and refuses sweeps outside the scan ranges", async () => {
    const { request, fleet, jobs } = await start();
    expect((await request("GET", "/api/fleet")).status).toBe(401);
    await request("POST", "/api/login", { password: "correct horse" });
    fleet.observe([{ ip: "192.168.1.20", mac: "f0:18:98:00:00:0c", hostname: "macbook", seenAt: "2026-10-29T11:59:00.000Z" }], "pihole");
    const overview = (await request("GET", "/api/fleet")).body;
    expect(overview).toMatchObject({ counts: { total: 1, online: 1, isNew: 0 }, targets: [], suggestions: [{ cidr: "192.168.1.0/24", devices: 1 }] });
    const id = overview.devices[0].id;
    expect((await request("PUT", `/api/fleet/devices/${id}`, { label: "Work laptop", trusted: true })).body.device).toMatchObject({ name: "Work laptop", trusted: true });
    expect((await request("GET", "/api/fleet/devices/999")).status).toBe(404);
    expect((await request("POST", "/api/fleet/sweep")).status).toBe(400);
    expect((await request("POST", "/api/fleet/sweep", { targets: ["8.8.8.0/24"] })).status).toBe(403);
    expect((await request("PUT", "/api/fleet/targets", { targets: ["10.0.0.0/8"] })).status).toBe(400);
    expect((await request("PUT", "/api/fleet/targets", { targets: ["192.168.1.0/24"] })).body).toEqual({ targets: ["192.168.1.0/24"] });
    expect((await request("POST", "/api/fleet/sweep")).status).toBe(202);
    await jobs.idle();
    expect((await request("GET", "/api/fleet")).body.lastSweep).toMatchObject({ networks: ["192.168.1.0/24"], alive: 0 });
  });

  it("serves the CVE list only to the owner, exploited first, and checks its filters", async () => {
    const { request, cves } = await start();
    expect((await request("GET", "/api/cves")).status).toBe(401);
    await request("POST", "/api/login", { password: "correct horse" });
    cves.upsertNvd([{ cveId: "CVE-2026-5000", published: "2026-10-20T00:00:00", modified: "2026-10-28T00:00:00", status: "Analyzed", description: "A bug", cvssScore: 9.8, cvssSeverity: "critical", cvssVector: null, cwes: [], products: ["synology:diskstation_manager"], cpeMatches: [] }], { announce: false });
    cves.applyKev({ version: "1", entries: [{ cveId: "CVE-2026-4127", added: "2026-10-27", due: "2026-11-17", ransomware: false, name: "Chromium V8 type confusion", description: "V8", action: "Update", product: "google:chromium_v8", cwes: [] }] });
    const all = (await request("GET", "/api/cves")).body;
    expect(all.rows.map((r) => r.cveId)).toEqual(["CVE-2026-4127", "CVE-2026-5000"]);
    expect(all.stats).toMatchObject({ total: 2, kev: 1, zeroDays: 1 });
    expect(all.attributions[0]).toMatch(/not endorsed or certified by the NVD/);
    expect((await request("GET", "/api/cves?product=synology")).body.rows.map((r) => r.cveId)).toEqual(["CVE-2026-5000"]);
    expect((await request("GET", "/api/cves?minEpss=7")).status).toBe(400);
    // M26, B37: a page size or offset that is not a number is the caller's mistake, not a 500.
    expect((await request("GET", "/api/cves?limit=abc")).status).toBe(400);
    expect((await request("GET", "/api/cves?offset=1e3")).status).toBe(400);
    expect((await request("GET", "/api/cves/CVE-2026-4127")).body.cve).toMatchObject({ zeroDay: true, kev: { due: "2026-11-17" } });
    expect((await request("GET", "/api/cves/CVE-1999-0001")).status).toBe(404);
    expect((await request("GET", "/api/cves/not-a-cve")).status).toBe(400);
  });

  it("checks this device: a Chrome one version behind a KEV fix is flagged, the patched one is not, and DNS is traced through Pi-hole (M6)", async () => {
    const pihole = fakePihole();
    const webFetch = async (input) => {
      const match = new URL(String(input)).searchParams.get("virtualMatchString");
      const affected = match === "cpe:2.3:a:google:chrome:141.0.7390.54" ? [{ id: "CVE-2026-4127", descriptions: [{ lang: "en", value: "V8 type confusion" }], metrics: {}, configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", versionEndExcluding: "141.0.7390.65" }] }] }] }] : [];
      return Response.json({ totalResults: affected.length, vulnerabilities: affected.map((cve) => ({ cve })) });
    };
    const { request, sentinel, cves } = await start({ services: { piholeFetch: pihole.fetchImpl, webFetch, now: () => new Date() } });
    sentinel.configure({ mode: "api", url: "http://192.0.2.5", password: "pihole-pass" }, "owner");
    cves.applyKev({ version: "1", entries: [{ cveId: "CVE-2026-4127", added: "2026-10-27", due: "2026-11-17", ransomware: false, name: "Chromium V8 type confusion", description: "x", action: "x", product: "google:chromium_v8", cwes: [] }] });
    await request("POST", "/api/login", { password: "correct horse" });
    const chrome = (v) => ({ platform: "macOS", platformVersion: "15.6.1", fullVersionList: [{ brand: "Google Chrome", version: v }] });

    const begun = (await request("POST", "/api/this-device/start")).body;
    expect(begun.dnsName).toMatch(/^ts-[0-9a-f]{12}\.dnscheck\.theyspy\.example$/);
    pihole.state.queries.push({ id: 1, time: Date.now() / 1000, type: "A", domain: begun.dnsName, cname: null, status: "FORWARDED", client: { ip: "192.168.1.20", name: "macbook" } });
    const behind = (await request("POST", "/api/this-device/check", { token: begun.token, uaData: chrome("141.0.7390.54"), gpc: true, adBlocked: true })).body;
    expect(behind).toMatchObject({ browser: { version: "141.0.7390.54", exact: true }, os: "macOS 15.6", gpc: true, adBlocked: true, exploited: 1, dns: { checked: true, throughPihole: true, from: "192.168.1.20" } });
    expect(behind.cves[0]).toMatchObject({ cveId: "CVE-2026-4127", kev: true, kevDue: "2026-11-17", fixed: "141.0.7390.65" });

    const again = (await request("POST", "/api/this-device/start")).body;
    const patched = (await request("POST", "/api/this-device/check", { token: again.token, uaData: chrome("141.0.7390.65") })).body;
    expect(patched).toMatchObject({ exploited: 0, cves: [], dns: { checked: true, throughPihole: false } });
    expect((await request("POST", "/api/this-device/check", { token: again.token })).status).toBe(400); // tokens are single-use
  });

  it("answers an MCP client with a token: devices, indicator lookups and exploited CVEs on devices (M9 exit criterion)", async () => {
    const { request, fleet, cves, checker } = await start({ services: { network: { probeHost: async () => ({ port: 22, answer: "open" }), checkPortsImpl: async () => [{ port: 22, proto: "tcp", service: "ssh", banner: "SSH-2.0-OpenSSH_9.6p1", product: "OpenSSH", version: "9.6p1", tls: null, risk: null }] } } });
    fleet.observe([{ ip: "192.168.8.140", mac: "30:c5:99:5e:fd:3a", seenAt: "2026-10-29T11:59:00.000Z" }], "pihole");
    await checker.run({ query: "192.168.8.140", profile: "standard" }, "owner");
    cves.applyKev({ version: "1", entries: [{ cveId: "CVE-2024-6387", added: "2024-07-01", due: "2024-07-22", ransomware: false, name: "OpenSSH regreSSHion", description: "x", action: "x", product: "openbsd:openssh", cwes: [] }] });

    const mcp = (body, token) => request("POST", "/mcp", body, token ? { authorization: `Bearer ${token}`, "x-theyspy": "" } : { "x-theyspy": "" });
    expect((await mcp({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} })).status).toBe(401);
    await request("POST", "/api/login", { password: "correct horse" });
    const { token } = (await request("POST", "/api/briefing/tokens", { name: "BoxPilot agents" })).body;
    expect(token).toMatch(/^tsy_/);

    const init = (await mcp({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } }, token)).body;
    expect(init.result).toMatchObject({ protocolVersion: "2025-06-18", serverInfo: { name: "theyspy" }, capabilities: { tools: {} } });
    expect((await mcp({ jsonrpc: "2.0", method: "notifications/initialized" }, token)).status).toBe(202);
    const listed = (await mcp({ jsonrpc: "2.0", id: 2, method: "tools/list" }, token)).body.result.tools.map((t) => t.name);
    expect(listed).toEqual(["list_devices", "list_indicator_lookups", "list_exploited_cves_on_devices", "check_domain", "get_status"]);
    const call = async (name, args = {}) => (await mcp({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name, arguments: args } }, token)).body.result.structuredContent;
    expect((await call("list_devices")).devices).toMatchObject([{ ip: "192.168.8.140", network: "Another private network" }]);
    expect((await call("list_indicator_lookups")).lookups).toEqual([]);
    expect((await call("list_exploited_cves_on_devices")).cves).toMatchObject([{ cveId: "CVE-2024-6387", software: "OpenSSH 9.6p1", due: "2024-07-22", confidence: "product" }]);
    expect((await mcp({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "check_domain", arguments: { domain: "a b" } } }, token)).body.error.code).toBe(-32602);

    // The JSON API takes the same token; a revoked token stops working.
    expect((await request("GET", "/api/v1/devices", undefined, { authorization: `Bearer ${token}` })).body.devices).toHaveLength(1);
    const id = (await request("GET", "/api/briefing")).body.tokens[0].id;
    await request("DELETE", `/api/briefing/tokens/${id}`);
    expect((await request("GET", "/api/v1/devices", undefined, { authorization: `Bearer ${token}` })).status).toBe(401);
  });

  it("serves the app shell for client-side routes", async () => {
    const dist = mkdtempSync(path.join(tmpdir(), "theyspy-dist-"));
    writeFileSync(path.join(dist, "index.html"), "<!doctype html><title>shell</title>");
    const { request } = await start({ staticDirectory: dist });
    expect((await request("GET", "/fleet")).body).toContain("shell");
    expect((await request("HEAD", "/")).status).toBe(200);
    expect((await request("GET", "/api/nope")).status).toBe(404);
  });
  it("hands the owner a checked copy of the database", async () => {
    const { request } = await start();
    expect((await request("GET", "/api/backup")).status).toBe(401);
    await request("POST", "/api/login", { password: "correct horse" });
    const response = await request("GET", "/api/backup");
    expect(response.status).toBe(200);
    expect(response.headers.get("content-disposition")).toMatch(/attachment; filename="theyspy-2026-10-29\.db"/);
    expect(response.body.startsWith("SQLite format 3")).toBe(true);
  });

  it("slows down a caller guessing API tokens", async () => {
    const { request } = await start();
    const codes = [];
    for (let i = 0; i < 32; i += 1) codes.push((await request("GET", "/api/v1/status", undefined, { authorization: "Bearer tsy_wrong" })).status);
    expect(codes.slice(0, 31).every((c) => c === 401)).toBe(true);
    expect(codes[31]).toBe(429);
  });

  it("keeps every other setting when one is saved: Pi-hole, alerts and appearance", async () => {
    // The owner's rule (30 Oct 2026): change the address or one switch, and everything else stays.
    const { request, sentinel, alerts } = await start();
    await request("POST", "/api/login", { password: "correct horse" });

    await request("PUT", "/api/pihole/settings", { mode: "api", url: "http://192.168.8.2", password: "app-password-1", write: true });
    await request("PUT", "/api/pihole/settings", { windowDays: 30 });
    await request("PUT", "/api/pihole/settings", { url: "http://100.67.166.48" });
    await request("PUT", "/api/pihole/settings", { watch: false });
    expect(sentinel.effective()).toMatchObject({ mode: "api", url: "http://100.67.166.48", password: "app-password-1", write: true, watch: false, windowDays: 30 });

    await request("PUT", "/api/briefing/ntfy", { url: "https://ntfy.example", topic: "theyspy", token: "tk_secret" });
    await request("PUT", "/api/briefing/ntfy", { url: "https://ntfy.example:8443", topic: "theyspy" }); // the form leaves an empty token out
    const ntfy = (await request("GET", "/api/briefing")).body.ntfy;
    expect(ntfy).toMatchObject({ url: "https://ntfy.example:8443", topic: "theyspy", hasToken: true });
    expect(alerts.config()).toMatchObject({ url: "https://ntfy.example:8443", topic: "theyspy", hasToken: true });

    await request("PUT", "/api/appearance", { name: "Home watch", accent: "#39c6ff" });
    await request("PUT", "/api/appearance", { look: "light" });
    expect((await request("GET", "/api/appearance")).body.appearance).toMatchObject({ name: "Home watch", accent: "#39c6ff", look: "light" });
  });

  it("refuses a long MCP batch, and charges the token's budget for every call in one", async () => {
    const { request } = await start();
    await request("POST", "/api/login", { password: "correct horse" });
    const { token } = (await request("POST", "/api/briefing/tokens", { name: "a client" })).body;
    const mcp = (body) => request("POST", "/mcp", body, { authorization: `Bearer ${token}`, "x-theyspy": "" });
    const ping = (id) => ({ jsonrpc: "2.0", id, method: "ping" });

    // A batch of 20 is answered; 21 is refused before any of it runs.
    const twenty = await mcp(Array.from({ length: 20 }, (_, i) => ping(i)));
    expect(twenty.status).toBe(200);
    expect(twenty.body).toHaveLength(20);
    const long = await mcp(Array.from({ length: 21 }, (_, i) => ping(i)));
    expect(long.status).toBe(400);
    expect(long.body.error).toMatchObject({ code: -32600, message: "A batch may hold at most 20 messages; this one has 21" });

    // The budget is 120 a minute. 20 calls already went; six more batches of 20 pass it, and the
    // token is told to wait — which it was not, when a batch cost one request's worth.
    const statuses = [];
    for (let i = 0; i < 6; i += 1) statuses.push((await mcp(Array.from({ length: 20 }, (_, n) => ping(n)))).status);
    expect(statuses).toContain(429);
    const refused = await mcp([ping(1)]);
    expect(refused.status).toBe(429);
    expect(refused.headers.get("retry-after")).toMatch(/^\d+$/);
  });

  it("answers 400 for a number it cannot read, and 404 for a name no table holds", async () => {
    const { request, library } = await start();
    await request("POST", "/api/login", { password: "correct horse" });

    // These were 500s: NaN bound to a SQL LIMIT, and NaN in new Date().toISOString().
    expect(await request("GET", "/api/audit?limit=abc")).toMatchObject({ status: 400, body: { error: "limit must be a whole number" } });
    expect(await request("GET", "/api/jobs/abc")).toMatchObject({ status: 400, body: { error: "The job id must be a whole number" } });
    expect(await request("GET", "/api/fleet/devices/abc")).toMatchObject({ status: 400, body: { error: "The device id must be a whole number" } });
    expect((await request("GET", "/api/audit?limit=5")).status).toBe(200);
    expect((await request("GET", "/api/jobs/999")).status).toBe(404);

    // An inherited property of a lookup table is not an entry of it.
    expect((await request("GET", "/api/exposure/kits/constructor")).status).toBe(404);
    expect((await request("GET", "/api/exposure/kits/apple")).status).toBe(200);
    const token = library.listToken();
    expect((await request("GET", `/lists/${token}/constructor.txt`)).status).toBe(404);
    expect((await request("GET", `/lists/${token}/toString.txt`)).status).toBe(404);
    expect((await request("GET", `/lists/${token}/security.txt`)).status).toBe(200);
  });

  it("tells the owner when the key to the stored passwords is in the backup, and when the session is in the clear", async () => {
    // No TS_SESSION_SECRET: the key TheySpy generated lives in the database a backup copies.
    const stored = await start({ services: { sessionSecret: null } });
    await stored.request("POST", "/api/login", { password: "correct horse" });
    const ids = (body) => body.notes.map((n) => n.id);
    const notes = (await stored.request("GET", "/api/security")).body;
    expect(ids(notes)).toContain("sealed-key-in-database");
    expect(notes.notes.find((n) => n.id === "sealed-key-in-database").fix).toContain("TS_SESSION_SECRET");
    // The request came from 127.0.0.1, so the cookie never crossed a network.
    expect(ids(notes)).not.toContain("session-over-plain-http");
    // Only the owner may read it.
    const anyone = await start();
    expect((await anyone.request("GET", "/api/security")).status).toBe(401);

    // With the secret in the environment there is nothing to say.
    const env = await start({ services: { sessionSecret: "from-the-environment" } });
    await env.request("POST", "/api/login", { password: "correct horse" });
    expect((await env.request("GET", "/api/security")).body.notes).toEqual([]);
  });

  it("lets a never-block name through by name when a list blocks its parent, in every format that can", async () => {
    // A cryptomining list that also blocks apple.com, lencr.org and gstatic.com - parents of
    // captive.apple.com, Let's Encrypt's OCSP responders and Android's portal check.
    const reg = (id) => `https://adguardteam.github.io/HostlistsRegistry/assets/filter_${id}.txt`;
    const abp = (...names) => `! Title: test\n${names.map((n) => `||${n}^`).join("\n")}\n`;
    const web = fakeWeb({
      [reg(31)]: abp("stalker-c2.example"), [reg(44)]: abp("malware-a.example"), [reg(11)]: abp("urlhaus-a.example"),
      [reg(18)]: abp("phish-b.example"), [reg(34)]: abp("ads-0.example"),
      [reg(8)]: abp("coin-a.example", "apple.com", "lencr.org", "gstatic.com"),
    });
    const { request, library } = await start({ services: { webFetch: web.fetchImpl } });
    await library.update();
    const token = library.listToken();
    const get = async (format) => (await request("GET", `/lists/${token}/cryptomining.${format}`)).body;

    const adblock = await get("adblock");
    expect(adblock).toContain("||apple.com^");          // the parent is still blocked
    expect(adblock).toContain("@@||captive.apple.com^"); // the child is let through
    expect(adblock).toContain("@@||time.apple.com^");
    expect(adblock).toContain("@@||r3.o.lencr.org^");
    expect(adblock).toContain("@@||connectivitycheck.gstatic.com^");
    // The exception must come before the rules, so a reader that stops at the first match is right too.
    expect(adblock.indexOf("@@||captive.apple.com^")).toBeLessThan(adblock.indexOf("||apple.com^\n"));

    const dnsmasq = await get("dnsmasq");
    expect(dnsmasq).toContain("address=/apple.com/0.0.0.0");
    expect(dnsmasq).toContain("server=/captive.apple.com/#");

    const rpz = await get("rpz");
    expect(rpz).toContain("*.apple.com CNAME .");
    expect(rpz).toContain("captive.apple.com CNAME rpz-passthru.");

    // txt and hosts match exactly, so a blocked parent never reaches a child: no exceptions, and
    // the protected name is simply absent.
    const txt = await get("txt");
    expect(txt).toContain("\napple.com\n");
    expect(txt).not.toContain("captive.apple.com");
    expect(txt).toContain("This format matches names exactly");
    expect(await get("hosts")).not.toContain("captive.apple.com");
  });

  it("serves the indicator set and the scanner only to an enrolled agent, and meters the agent download", async () => {
    const clock = testClock();
    const { request, agents } = await start({ services: { now: clock } });
    const sign = (secret, stamp, payload) => createHmac("sha256", secret).update(`${stamp}.`).update(payload).digest("hex");

    // Anything on the network used to be able to read the owner's active indicator set.
    for (const path of ["/api/agent/iocs.txt", "/api/agent/zero-breach.py", "/api/agent/scanner"]) {
      expect((await request("GET", path)).status, path).toBe(401);
    }

    await request("POST", "/api/login", { password: "correct horse" });
    const { token } = agents.createEnrollment("lab", "owner");
    const { agentId, secret } = agents.enroll({ token, hostname: "lab" }, "192.168.8.9");

    const asAgent = (path, { id = agentId, key = secret, stamp = clock().toISOString() } = {}) =>
      request("GET", path, undefined, { "x-theyspy-agent": String(id), "x-theyspy-timestamp": stamp, "x-theyspy-signature": sign(key, stamp, `GET ${path}`) });

    expect((await asAgent("/api/agent/iocs.txt")).status).toBe(200);
    expect((await asAgent("/api/agent/iocs.txt")).body).toContain("fearevolve.com");
    expect((await asAgent("/api/agent/scanner")).body).toMatchObject({ version: "0.1.8" });
    expect((await asAgent("/api/agent/zero-breach.py")).status).toBe(200);

    // A signature for one path does not open another, a wrong key does nothing, and an old
    // timestamp is refused.
    const stamp = clock().toISOString();
    expect((await request("GET", "/api/agent/iocs.txt", undefined, { "x-theyspy-agent": String(agentId), "x-theyspy-timestamp": stamp, "x-theyspy-signature": sign(secret, stamp, "GET /api/agent/scanner") })).status).toBe(401);
    expect((await asAgent("/api/agent/iocs.txt", { key: "wrong" })).status).toBe(401);
    expect((await asAgent("/api/agent/iocs.txt", { stamp: new Date(clock().getTime() - 3_600_000).toISOString() })).status).toBe(401);

    // A revoked agent stops being able to read.
    agents.revoke(agentId, "owner");
    expect((await asAgent("/api/agent/iocs.txt")).status).toBe(401);

    // The agent script itself cannot be signed for - a new machine has no key yet - but it is
    // metered: 60 in ten minutes.
    const statuses = [];
    for (let i = 0; i < 62; i += 1) statuses.push((await request("GET", "/agent/theyspy-agent.py")).status);
    expect(statuses[0]).toBe(200);
    expect(statuses.at(-1)).toBe(429);
  });
});

describe("sweep 3, found by the Stage 2 sweep (M14)", () => {
  it("B21: the Baselines screen loads on a fresh install, before Pi-hole is connected", async () => {
    const { request } = await start();
    await request("POST", "/api/login", { password: "correct horse" });
    const response = await request("GET", "/api/blocklists/baselines");
    expect(response.status).toBe(200);
    expect(response.body.pihole.connected).toBe(false);
    expect(response.body.scopes).toMatchObject({ pihole: false, devices: [], network: { key: "network", suggested: "balanced" } });
    expect(response.body.baselines.map((b) => b.id)).toEqual(["essential", "balanced", "strict", "lockdown"]);
  });
  it("M15: the overview and a device's indicator lookups answer under any address the device has held", async () => {
    const { request, fleet, db } = await start({ services: { piholeEnv: { url: "http://pihole.lan", password: "x", write: false } } });
    await request("POST", "/api/login", { password: "correct horse" });
    fleet.observe([{ ip: "192.168.1.30", mac: "f0:18:98:00:00:aa", hostname: "laptop", seenAt: "2026-11-01T10:00:00.000Z" }], "pihole", { inventory: true });
    db.prepare("INSERT INTO ioc_hit_events (source, query_id, at, indicator, domain, via, client_ip, client_name, status, blocked, found_by, found_at) VALUES ('pihole', 1, '2026-11-06T21:14:00.000Z', 'adfection-c2.example', 'adfection-c2.example', 'query', '192.168.1.30', 'laptop', 'FORWARDED', 0, 'hunt', '2026-11-06T21:15:00.000Z')").run();
    fleet.observe([{ ip: "192.168.1.31", mac: "f0:18:98:00:00:aa", seenAt: "2026-11-07T11:55:00.000Z" }], "pihole");
    const [device] = fleet.list();
    const hits = await request("GET", `/api/fleet/devices/${device.id}/hits`);
    expect(hits.status).toBe(200);
    expect(hits.body.hits).toHaveLength(1);
    expect(hits.body.hits[0]).toMatchObject({ clientIp: "192.168.1.30", lookups: 1, blocked: 0 });
    const overview = await request("GET", "/api/overview");
    expect(overview.status).toBe(200);
    expect(overview.body.questions.contacts.count).toBe(1);
    expect(overview.body.devices[0]).toMatchObject({ name: "laptop", notBlocked: 1 });
    expect((await request("GET", "/api/fleet/devices/999/hits")).status).toBe(404);
  });
  it("M16: one device's exposure and findings come from their own endpoints", async () => {
    const { request, fleet } = await start();
    await request("POST", "/api/login", { password: "correct horse" });
    fleet.observe([{ ip: "192.168.1.30", mac: "f0:18:98:00:00:aa", hostname: "laptop", seenAt: "2026-11-01T10:00:00.000Z" }], "pihole", { inventory: true });
    const [device] = fleet.list();
    const exposure = await request("GET", `/api/fleet/devices/${device.id}/exposure`);
    expect(exposure.status).toBe(200);
    expect(exposure.body).toMatchObject({ id: device.id, name: "laptop" });
    expect(exposure.body.factors.map((f) => f.id)).toContain("clean");
    expect((await request("GET", `/api/fleet/devices/${device.id}/findings`)).body).toEqual({ findings: [] });
    expect((await request("GET", "/api/fleet/devices/999/exposure")).status).toBe(404);
    expect((await request("GET", "/api/fleet/devices/999/findings")).status).toBe(404);
  });

  it("M17 B25: a Pi-hole Sentinel row is named after the device that held its address when it was last seen", async () => {
    const { request, fleet, db } = await start({ services: { piholeEnv: { url: "http://pihole.lan", password: "x", write: false } } });
    await request("POST", "/api/login", { password: "correct horse" });
    fleet.observe([{ ip: "192.168.1.30", mac: "aa:aa:aa:00:00:01", hostname: "old-tablet", seenAt: "2026-01-10T10:00:00.000Z" }], "pihole", { inventory: true });
    db.prepare("INSERT INTO ioc_hit_events (source, query_id, at, indicator, domain, via, client_ip, client_name, status, blocked, found_by, found_at) VALUES ('pihole', 1, '2026-01-12T10:00:00.000Z', 'adfection-c2.example', 'adfection-c2.example', 'query', '192.168.1.30', NULL, 'FORWARDED', 0, 'hunt', '2026-01-12T10:05:00.000Z')").run();
    fleet.observe([{ ip: "192.168.1.30", mac: "bb:bb:bb:00:00:02", hostname: "new-laptop", seenAt: "2026-11-07T11:00:00.000Z" }], "pihole");
    const { body } = await request("GET", "/api/pihole/hits");
    expect(body.hits).toHaveLength(1);
    expect(body.hits[0].device).toBe("old-tablet");
  });

  it("M18 B28: a failing scheduled fleet read is listed on the Fleet overview", async () => {
    const { request, settings } = await start();
    await request("POST", "/api/login", { password: "correct horse" });
    settings.set("fleet_last_sync_error", { at: "2026-11-07T11:55:00.000Z", error: "Pi-hole refused the password" });
    const { body } = await request("GET", "/api/fleet");
    expect(body.errors).toEqual({ sync: { at: "2026-11-07T11:55:00.000Z", error: "Pi-hole refused the password" } });
  });

  it("M19: an export format named through the prototype is 404, and a baseline exception must be a domain", async () => {
    const { request, db } = await start();
    await request("POST", "/api/login", { password: "correct horse" });
    expect((await request("GET", "/api/iocs/export/constructor")).status).toBe(404);
    expect((await request("GET", "/api/iocs/export/__proto__")).status).toBe(404);
    expect((await request("PUT", "/api/blocklists/baselines/exceptions", { scope: "network", site: "not a domain!", keep: true })).status).toBe(400);
    expect((await request("PUT", "/api/blocklists/baselines/exceptions", { scope: "network", site: "Example[.]COM.", keep: true })).body).toEqual({ exceptions: ["example.com"] });
    expect(db.prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'ioc_hit_events_at'").get()).toBeTruthy();
  });
});

describe("M30 B41", () => {
  it("says which never-block names it did not keep", async () => {
    const { request } = await start();
    await request("POST", "/api/login", { password: "correct horse" });
    const r = await request("PUT", "/api/blocklists/pins", { pins: ["keep.example", "not a name!!", "Also.Example."] });
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ pins: ["keep.example", "also.example"], ignored: ["not a name!!"] });
  });
});

describe("M28 B39", () => {
  it("answers 409, not 500, when a baseline preview is asked for before Pi-hole is connected", async () => {
    const { request } = await start();
    await request("POST", "/api/login", { password: "correct horse" });
    const r = await request("GET", "/api/blocklists/baselines/preview");
    expect(r.status).toBe(409);
    expect(r.body.error).toMatch(/Pi-hole is not connected/);
  });
});

describe("M32 O1", () => {
  it("compresses a large answer when the browser accepts gzip, and never the backup", async () => {
    const { request } = await start();
    await request("POST", "/api/login", { password: "correct horse" });
    const gz = await request("GET", "/api/iocs/indicators", undefined, { "accept-encoding": "gzip" });
    expect(gz.headers.get("content-encoding")).toBe("gzip");
    expect(gz.body.indicators.length).toBeGreaterThan(100);
    const plain = await request("GET", "/api/iocs/indicators", undefined, { "accept-encoding": "identity" });
    expect(plain.headers.get("content-encoding")).toBeNull();
  });
});
