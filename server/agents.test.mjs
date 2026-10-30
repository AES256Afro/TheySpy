import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { testClock, testServices } from "./test-helpers.mjs";
import { verifiedScanner } from "./agents.mjs";

const sign = (secret, ts, body) => createHmac("sha256", secret).update(`${ts}.`).update(body).digest("hex");
const zbReport = { tool: { name: "adint-scan", version: "0.1.8 (single-file build)" }, modules: { browser: { status: "HITS", hits: [{ indicator: "fearevolve.com", location: "/home/lab/.config/google-chrome/Default/History", detail: "history: https://cdn.fearevolve.com/ad.js", tier: "cc", confidence: "primary" }] } },
  verdict: { status: "INDICATORS_FOUND", hits_total: 1, gaps: ["hash/file-fingerprints: skipped by --quick", "host/com-persistence: not supported on Linux"] } };

function enrolled() {
  const now = testClock("2026-10-30T03:00:00.000Z");
  const s = testServices({ now });
  const { token } = s.agents.createEnrollment("lab VM", "owner");
  const { agentId, secret } = s.agents.enroll({ token, hostname: "lab-vm", platform: "Linux", macs: ["02:00:00:aa:bb:cc"] }, "192.168.8.77");
  return { ...s, agentId, secret, now };
}

describe("agents and evidence", () => {
  it("hands out zero-breach's scanner only after checking it against the signed release", () => {
    const s = verifiedScanner();
    expect(s.sha256).toBe("74740af20f609f82dc6e50d66f234d0c39a20f516caa35731c2d19c11684ef44");
    expect(s.bytes.length).toBe(281147);
  });

  it("enrolls once per token, and links the agent to the device", () => {
    const { agents, fleet, agentId } = enrolled();
    expect(agentId).toBe(1);
    expect(fleet.list().find((d) => d.ip === "192.168.8.77")).toMatchObject({ mac: "02:00:00:aa:bb:cc" });
    const { token } = agents.createEnrollment("x", "owner");
    agents.enroll({ token, hostname: "a" }, "192.168.8.78");
    expect(() => agents.enroll({ token, hostname: "b" }, "192.168.8.79")).toThrow(/unknown, used or expired/);
  });

  it("takes a signed report: hits become contacted findings, gaps are kept, software feeds CVE matching (M7 exit criterion)", async () => {
    const { agents, agentId, secret, now, deviceCves, fleet } = enrolled();
    const body = Buffer.from(JSON.stringify({ hostname: "lab-vm", inventory: [{ software: "chrome", version: "141.0.7390.54" }, { software: "notepad", version: "1" }], scan: { exitCode: 2, report: zbReport } }));
    const ts = now().toISOString();
    expect(() => agents.authenticate(agentId, ts, "00".repeat(32), body)).toThrow(/signature does not match/);
    const agent = agents.authenticate(agentId, ts, sign(secret, ts, body), body);
    const result = agents.ingest(agent, JSON.parse(body.toString()), ts, "192.168.8.77");
    expect(result).toMatchObject({ findings: 1, gaps: 2, verdict: { status: "INDICATORS_FOUND", hits: 1 } });
    const findings = agents.findings();
    expect(findings.filter((f) => f.kind === "contacted")).toMatchObject([{ indicator: "fearevolve[.]com", tier: "cc", location: expect.stringContaining("History"), device: "lab-vm" }]);
    expect(findings.filter((f) => f.kind === "gap").map((f) => f.detail)).toEqual(zbReport.verdict.gaps);
    const device = fleet.list().find((d) => d.ip === "192.168.8.77");
    expect(deviceCves.inventory(device.id)).toMatchObject([{ product: "Google Chrome", version: "141.0.7390.54", source: "agent", cpes: [["google", "chrome"]] }]);
    // The same report again is a replay; an old timestamp is refused too.
    expect(() => agents.authenticate(agentId, ts, sign(secret, ts, body), body)).toThrow(/already received/);
    const old = new Date(now().getTime() - 3_600_000).toISOString();
    expect(() => agents.authenticate(agentId, old, sign(secret, old, body), body)).toThrow(/ten minutes/);
  });

  it("records a scan that could not run as a gap, never as clean", () => {
    const { agents, agentId, now } = enrolled();
    const agent = { id: agentId, device_id: null };
    const r = agents.ingest(agent, { scan: { exitCode: 1, report: null, error: "python too old" } }, now().toISOString(), "192.168.8.77");
    expect(r.verdict.status).toBe("NOT_RUN");
    expect(agents.findings()).toMatchObject([{ kind: "gap", detail: "The scan could not run: python too old. Nothing on this device was checked." }]);
  });

  it("imports MVT results for a phone, keeps its profile, and exports a finding as STIX", () => {
    const { agents, fleet, deviceCves } = enrolled();
    fleet.observe([{ ip: "192.168.8.218", mac: "c4:5b:ac:88:22:8d", seenAt: "2026-10-30T02:00:00.000Z" }], "pihole");
    const phone = fleet.list().find((d) => d.ip === "192.168.8.218").id;
    const detected = JSON.stringify([{ url: "https://fearevolve.com/x", matched_indicator: { value: "fearevolve.com", type: "domain" } }]);
    expect(agents.importMvt(phone, [{ name: "safari_history_detected.json", content: detected }], "owner")).toEqual({ findings: 1 });
    expect(agents.importMvt(phone, [{ name: "safari_history_detected.json", content: detected }], "owner")).toEqual({ findings: 0 });
    agents.setProfile(phone, { os: "ios", osVersion: "26.7.1", browser: "safari", adId: "off" }, "owner");
    expect(deviceCves.inventory(phone).map((i) => [i.product, i.version, i.source])).toEqual([["iOS", "26.7.1", "manual"], ["Safari", null, "manual"]]);
    const f = agents.findings().find((x) => x.source === "mvt");
    const bundle = agents.stix(f.id);
    expect(bundle.objects.map((o) => o.type)).toEqual(["indicator", "sighting"]);
    expect(bundle.objects[0].pattern).toBe("[domain-name:value = 'fearevolve.com']");
  });
});
