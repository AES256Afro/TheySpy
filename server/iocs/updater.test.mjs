import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { fakeGitHub, testServices, vendored } from "../test-helpers.mjs";

const original = vendored("iocs/adfection_iocs.txt").toString("utf8");
const hash = (text) => createHash("sha256").update(text).digest("hex");
// A newer set as the main branch might publish it: one added, one removed, one retiered.
const newer = original
  .replace("# as-of: 2026-10-18", "# as-of: 2026-11-02")
  .replace(/^fearevolve\.com\tcc\tprimary\tcitizenlab-adfection-2026\n/m, "")
  .replace(/^(jobmarcher\.com)\tcc\t/m, "$1\tcandiru\t")
  + "new-delivery-host.example\tdelivery\tprimary\tcitizenlab-adfection-2026\n";
const mainTrack = (body, sha = hash(body)) => fakeGitHub({
  "https://raw.githubusercontent.com/interplains/zero-breach/main/iocs/adfection_iocs.txt": body,
  "https://raw.githubusercontent.com/interplains/zero-breach/main/iocs/adfection_iocs.txt.sha256": `${sha}  adfection_iocs.txt\n`,
});

async function check(services) {
  const job = services.jobs.enqueue("ioc.check", { actor: "owner" });
  await services.jobs.idle();
  return services.jobs.get(job.id);
}

describe("indicator store and updater", () => {
  it("seeds the bundled set once, checked against the signed manifest", () => {
    const { iocStore, audit } = testServices();
    expect(iocStore.active()).toMatchObject({ status: "active", count: 405, asof: "2026-10-18", provenance: { track: "bundled", signedBy: "C24EC92B12D6670A2516065F9B4D575499AFA53C" } });
    expect(iocStore.seedBundled()).toBeNull();
    expect(audit.list().filter((e) => e.action === "iocs.seeded")).toHaveLength(1);
  });

  it("verifies the signed release and reports up to date when nothing changed", async () => {
    const services = testServices();
    const job = await check(services);
    expect(job.status).toBe("succeeded");
    expect(job.result).toEqual({ upToDate: true });
    expect(job.log).toContain("verified with ArchiveGenocide's pinned Ed25519 key");
    expect(services.settings.get("ioc_last_check")).toMatchObject({ track: "release", outcome: "up-to-date" });
  });

  it("finds an update on main, shows the diff, and applies it only when asked", async () => {
    const services = testServices({ fetchImpl: mainTrack(newer) });
    services.settings.set("ioc_track", "main");
    const job = await check(services);
    const pending = services.iocStore.pending();
    expect(job.result).toEqual({ versionId: pending.id });
    expect(pending.provenance).toMatchObject({ track: "main" });
    expect(pending.diff.added.map((i) => i.value)).toEqual(["new-delivery-host.example"]);
    expect(pending.diff.removed.map((i) => i.value)).toEqual(["fearevolve.com"]);
    expect(pending.diff.changed).toEqual([{ value: "jobmarcher.com", type: "domain", fields: [{ field: "tier", from: "cc", to: "candiru" }] }]);
    expect(pending.diff.asof).toEqual({ from: "2026-10-18", to: "2026-11-02" });
    expect(services.iocStore.active().asof).toBe("2026-10-18");

    services.jobs.enqueue("ioc.apply", { actor: "owner", params: { versionId: pending.id } });
    await services.jobs.idle();
    expect(services.iocStore.active()).toMatchObject({ id: pending.id, asof: "2026-11-02", count: 405 });
    expect(services.iocStore.activeSet().indicators.some((i) => i.value === "new-delivery-host.example")).toBe(true);
    expect(services.iocStore.history().map((v) => v.status)).toEqual(["active", "superseded"]);
    expect(services.audit.list()[0]).toMatchObject({ action: "job.succeeded" });
    expect(services.audit.list().map((e) => e.action)).toContain("iocs.applied");
  });

  it("refuses a download that does not match its published hash", async () => {
    const services = testServices({ fetchImpl: mainTrack(newer, hash(original)) });
    services.settings.set("ioc_track", "main");
    const job = await check(services);
    expect(job.status).toBe("failed");
    expect(job.log).toContain("does not match its published SHA-256");
    expect(services.iocStore.pending()).toBeNull();
    expect(services.settings.get("ioc_last_check")).toMatchObject({ outcome: "failed" });
  });

  it("refuses a release whose indicator file does not match the signed manifest", async () => {
    const services = testServices({ fetchImpl: fakeGitHub({ "https://raw.githubusercontent.com/interplains/zero-breach/v0.1.8/iocs/adfection_iocs.txt": newer }) });
    const job = await check(services);
    expect(job.status).toBe("failed");
    expect(job.log).toContain("does not match the signed manifest");
  });

  it("refuses a release whose manifest signature is not valid", async () => {
    const forged = vendored("release-signatures/v0.1.8/SHA256SUMS.txt").toString("utf8").replace(/^[0-9a-f]{64}(?= {2}adfection_iocs\.txt$)/m, hash(newer));
    const services = testServices({ fetchImpl: fakeGitHub({ "https://raw.githubusercontent.com/interplains/zero-breach/main/release-signatures/v0.1.8/SHA256SUMS.txt": forged }) });
    const job = await check(services);
    expect(job.status).toBe("failed");
    expect(job.log).toContain("signature on SHA256SUMS.txt is not valid");
  });

  it("says when a release is not signed yet", async () => {
    const missing = "https://raw.githubusercontent.com/interplains/zero-breach/main/release-signatures/v0.1.8/SHA256SUMS.txt.asc";
    const services = testServices({ fetchImpl: fakeGitHub({ [missing]: null }) });
    expect((await check(services)).log).toContain("has no signed SHA256SUMS.txt yet");
  });

  it("refuses a malformed file even when its hash matches", async () => {
    const broken = `${original}bad line without tabs\n`;
    const services = testServices({ fetchImpl: mainTrack(broken) });
    services.settings.set("ioc_track", "main");
    const job = await check(services);
    expect(job.status).toBe("failed");
    expect(job.log).toMatch(/expected 3 or 4 tab-separated columns/);
  });

  it("only talks to GitHub, over HTTPS", async () => {
    const fetchImpl = fakeGitHub();
    await check(testServices({ fetchImpl }));
    expect(fetchImpl.requested.length).toBeGreaterThan(0);
    for (const url of fetchImpl.requested) expect(new URL(url).origin).toMatch(/^https:\/\/(api\.github\.com|raw\.githubusercontent\.com)$/);
  });

  it("rejects a pending update and keeps the active set", async () => {
    const services = testServices({ fetchImpl: mainTrack(newer) });
    services.settings.set("ioc_track", "main");
    await check(services);
    const pending = services.iocStore.pending();
    expect(services.iocStore.reject(pending.id, "owner").status).toBe("rejected");
    expect(services.iocStore.active().asof).toBe("2026-10-18");
    expect(() => services.iocStore.apply(pending.id, "owner")).toThrow(/Only a pending update/);
  });
});
