import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createApp } from "./app.mjs";
import { readConfig } from "./config.mjs";
import { testServices, vendored } from "./test-helpers.mjs";

const servers = [];
afterEach(() => { for (const server of servers.splice(0)) server.close(); });

async function start({ env = {}, staticDirectory } = {}) {
  const services = testServices();
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

  it("serves the app shell for client-side routes", async () => {
    const dist = mkdtempSync(path.join(tmpdir(), "theyspy-dist-"));
    writeFileSync(path.join(dist, "index.html"), "<!doctype html><title>shell</title>");
    const { request } = await start({ staticDirectory: dist });
    expect((await request("GET", "/fleet")).body).toContain("shell");
    expect((await request("HEAD", "/")).status).toBe(200);
    expect((await request("GET", "/api/nope")).status).toBe(404);
  });
});
