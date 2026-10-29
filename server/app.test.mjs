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

  it("serves the app shell for client-side routes", async () => {
    const dist = mkdtempSync(path.join(tmpdir(), "theyspy-dist-"));
    writeFileSync(path.join(dist, "index.html"), "<!doctype html><title>shell</title>");
    const { request } = await start({ staticDirectory: dist });
    expect((await request("GET", "/fleet")).body).toContain("shell");
    expect((await request("HEAD", "/")).status).toBe(200);
    expect((await request("GET", "/api/nope")).status).toBe(404);
  });
});
