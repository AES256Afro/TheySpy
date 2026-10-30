import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createApp } from "./app.mjs";
import { readConfig } from "./config.mjs";
import { fakePihole, testServices, vendored } from "./test-helpers.mjs";

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
    expect((await request("PUT", "/api/blocklists/pins", { pins: ["Example.COM", "not a name"] })).body).toEqual({ pins: ["example.com"] });
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
});
