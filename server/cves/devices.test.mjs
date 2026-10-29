import { describe, expect, it } from "vitest";
import { testClock, testServices } from "../test-helpers.mjs";

const ssh = { port: 22, proto: "tcp", service: "ssh", banner: "SSH-2.0-OpenSSH_9.6p1", product: "OpenSSH", version: "9.6p1", tls: null, risk: null };
const nvdCve = (id, vee) => ({ id, descriptions: [{ lang: "en", value: `${id} in OpenSSH` }], metrics: { cvssMetricV31: [{ type: "Primary", cvssData: { baseScore: 8.1, baseSeverity: "HIGH" } }] },
  configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", versionEndExcluding: vee }] }] }] });

function setup() {
  const asked = [];
  const webFetch = async (input) => {
    const url = new URL(String(input));
    asked.push(url.searchParams.get("virtualMatchString"));
    const v = url.searchParams.get("virtualMatchString") === "cpe:2.3:a:openbsd:openssh:9.6p1" ? [nvdCve("CVE-2024-6387", "9.8p1"), nvdCve("CVE-2025-26465", "9.9p2")] : [];
    return Response.json({ totalResults: v.length, vulnerabilities: v.map((cve) => ({ cve })) });
  };
  const now = testClock("2026-10-29T12:00:00.000Z");
  const services = testServices({ webFetch, now, network: { probeHost: async () => ({ port: 22, answer: "open" }), checkPortsImpl: async () => [ssh] } });
  return { ...services, asked, now };
}

describe("CVEs per device", () => {
  it("matches a device's software at its exact version, exploited first, with the fixing version", async () => {
    const { checker, deviceCves, cves, asked } = setup();
    cves.applyKev({ version: "1", entries: [{ cveId: "CVE-2024-6387", added: "2024-07-01", due: "2024-07-22", ransomware: false, name: "regreSSHion", description: "x", action: "x", product: "openbsd:openssh", cwes: [] }] });
    const check = await checker.run({ query: "192.168.1.5", profile: "standard" }, "owner");
    const r = await deviceCves.forDevice(check.device.id);
    expect(r.inventory).toMatchObject([{ product: "OpenSSH", version: "9.6p1", matchable: true }]);
    expect(r.cves.map((c) => [c.cveId, c.kev, c.fixed])).toEqual([["CVE-2024-6387", true, "9.8p1"], ["CVE-2025-26465", false, "9.9p2"]]);
    // A CVE that names OpenSSH only as the platform (not vulnerable itself) does not count.
    expect(r).toMatchObject({ open: 2, exploited: 1 });
    await deviceCves.forDevice(check.device.id);
    expect(asked).toEqual(["cpe:2.3:a:openbsd:openssh:9.6p1"]); // a week's cache
  });

  it("keeps the owner's decisions, and reopens a 'fixed' CVE when a later check finds the same version", async () => {
    const { checker, deviceCves, now } = setup();
    const id = (await checker.run({ query: "192.168.1.5", profile: "standard" }, "owner")).device.id;
    deviceCves.decide(id, "CVE-2025-26465", "accepted", "LAN only", "owner");
    now.advance(60_000);
    deviceCves.decide(id, "CVE-2024-6387", "fixed", null, "owner");
    let r = await deviceCves.forDevice(id);
    expect(r.open).toBe(0);
    expect(r.cves.find((c) => c.cveId === "CVE-2025-26465").decision).toMatchObject({ status: "accepted", note: "LAN only" });
    now.advance(60_000);
    await checker.run({ query: "192.168.1.5", profile: "standard" }, "owner"); // still OpenSSH 9.6p1
    r = await deviceCves.forDevice(id);
    expect(r.cves.find((c) => c.cveId === "CVE-2024-6387").decision).toMatchObject({ status: "fixed", contradicted: true });
    expect(r.open).toBe(1);
    deviceCves.decide(id, "CVE-2025-26465", null, null, "owner");
    expect((await deviceCves.forDevice(id)).open).toBe(2);
    expect(() => deviceCves.decide(id, "CVE-2025-26465", "ignored", null, "owner")).toThrow(/status must be/);
  });
});
