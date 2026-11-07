import { describe, expect, it } from "vitest";
import { testServices } from "./test-helpers.mjs";

// The real two-site check is scripts/e2e-sites.sh; this covers what a site must never do to the hub.
const token = "tsy_abcdefghijklmnopqrstuvwxyz012345";

describe("other sites", () => {
  it("treats a site's answer as untrusted: defanged, bounded, no markup", async () => {
    const fetchImpl = async (input) => {
      const path = new URL(String(input)).pathname;
      if (path === "/api/v1/indicator-lookups") return Response.json({ lookups: [{ device: "<img src=x onerror=alert(1)> " + "x".repeat(300), domain: "evil.example", indicator: "evil.example", lookups: "9e9", blocked: -1, lastSeen: "2026-10-30T12:00:00.000Z" }] });
      if (path === "/api/v1/status") return Response.json({ sections: Array.from({ length: 12 }, () => ({ title: "t", tone: "evil", lines: ["l"] })) });
      return Response.json({ cves: [], devices: [] });
    };
    const s = testServices({ sitesFetch: fetchImpl });
    s.sites.add({ name: "Cabin", url: "http://cabin.lan:8797", token }, "owner");
    const [r] = await s.sites.refresh();
    expect(r.gotThrough[0].indicator).toBe("evil[.]example");
    expect(r.gotThrough[0].device).not.toMatch(/[<>]/);
    expect(r.gotThrough[0].device.length).toBeLessThanOrEqual(60);
    expect(r.sections).toHaveLength(6);
    expect(r.sections[0].tone).toBe("unknown");
    expect(JSON.stringify(s.sites.overview())).not.toContain(token); // the token is never shown back
  });

  it("keeps the last reading when a site cannot be read, and says why", async () => {
    let up = true;
    const fetchImpl = async () => (up ? Response.json({ lookups: [], sections: [], cves: [], devices: [] }) : Response.json({}, { status: 401 }));
    const s = testServices({ sitesFetch: fetchImpl });
    s.sites.add({ name: "Cabin", url: "http://cabin.lan:8797", token }, "owner");
    const [first] = await s.sites.refresh();
    up = false;
    const [second] = await s.sites.refresh();
    expect(second.at).toBe(first.at);
    expect(second.error).toMatch(/refused the token/);
  });

  it("refuses an address with credentials in it, or a token that is not a TheySpy API token", () => {
    const s = testServices();
    expect(() => s.sites.add({ name: "x", url: "http://user:pass@cabin.lan", token }, "owner")).toThrow(/address/);
    expect(() => s.sites.add({ name: "x", url: "http://cabin.lan", token: "hunter2" }, "owner")).toThrow(/tsy_/);
  });
});

describe("M17 B24", () => {
  it("raises a site's got-through lookups once, even when there are more than the twenty it keeps for display", async () => {
    const lookups = Array.from({ length: 25 }, (_, i) => ({ device: `phone-${i}`, domain: `c2-${i}.example`, indicator: `c2-${i}.example`, lookups: 3, blocked: 0, lastSeen: "2026-11-07T10:00:00.000Z" }));
    const sitesFetch = async (url) => {
      const u = String(url);
      if (u.includes("/status")) return Response.json({ version: "1.12.0", sections: [] });
      if (u.includes("/indicator-lookups")) return Response.json({ lookups });
      if (u.includes("/exploited")) return Response.json({ cves: [] });
      return Response.json({ devices: [] });
    };
    const { sites, audit } = testServices({ sitesFetch });
    sites.add({ name: "Cabin", url: "https://cabin.example.ts.net:8797", token: `tsy_${"a".repeat(32)}` }, "owner");
    await sites.refresh(); await sites.refresh(); await sites.refresh();
    expect(audit.list(50).filter((e) => e.action === "sites.indicator_lookups")).toHaveLength(1);
    // A new pair is still news.
    lookups.push({ device: "phone-99", domain: "c2-99.example", indicator: "c2-99.example", lookups: 1, blocked: 0, lastSeen: "2026-11-07T11:00:00.000Z" });
    await sites.refresh();
    expect(audit.list(50).filter((e) => e.action === "sites.indicator_lookups")).toHaveLength(2);
  });
});
