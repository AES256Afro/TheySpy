// @vitest-environment jsdom
import { act, cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { DeviceScreen } from "./Device.tsx";

const realFetch = globalThis.fetch;
afterEach(() => { cleanup(); globalThis.fetch = realFetch; });
const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });

const device = { id: 7, name: "pixel", ip: "192.168.1.61", mac: "3c:a9:f4:00:00:21", hostname: "pixel", vendor: "Google", label: null, owner: null, kind: null, notes: "", tags: [], trusted: false, acknowledged: true, isNew: false, online: true, firstSeen: "2026-10-20T00:00:00.000Z", lastSeen: "2026-10-25T21:14:02.000Z", sources: {}, names: {}, network: { kind: "lan", label: "Your router's network", detail: "" }, guess: null, events: [], addresses: [] };
const hit = {
  indicator: "fearevolve.com", domain: "cdn.fearevolve.com", via: "query", clientIp: "192.168.1.61", firstSeen: "2026-10-25T21:14:02.000Z", lastSeen: "2026-10-25T21:14:02.000Z", lookups: 1, blocked: 1, lastStatus: "GRAVITY", tier: "high",
  lastContext: { at: "2026-10-25T21:14:02.000Z", queries: [
    { at: "2026-10-25T21:13:50.000Z", domain: "example.org", status: "CACHE", blocked: false, hit: false },
    { at: "2026-10-25T21:14:02.000Z", domain: "cdn.fearevolve.com", status: "GRAVITY", blocked: true, hit: true },
    { at: "2026-10-25T21:14:05.000Z", domain: "api.example.net", status: "FORWARDED", blocked: false, hit: false },
  ] },
};

describe("the device page's minute around a hit (M39)", () => {
  it("shows what the device asked before and after, with each lookup's distance from the hit", async () => {
    globalThis.fetch = (async (url: string) => {
      if (url.endsWith("/hits")) return json({ connected: true, hits: [hit] });
      if (url === "/api/fleet/devices/7") return json({ device });
      if (url.endsWith("/exposure")) return json({ factors: [] });
      if (url.endsWith("/findings")) return json({ findings: [] });
      if (url.endsWith("/cves")) return json({ cves: [], open: 0, exploited: 0 });
      if (url.endsWith("/services")) return json({ services: [] });
      return json({ total: 0, rows: [] });
    }) as typeof fetch;
    const screen = render(<DeviceScreen id={7} />);
    await act(async () => { await new Promise((r) => setTimeout(r, 30)); });
    const text = screen.container.textContent ?? "";
    expect(text).toContain("What it asked around then: 2 other lookups within 30 s");
    expect(text).toContain("−12 s");
    expect(text).toContain("+3 s");
    expect(text).toContain("api.example.net");
    expect(screen.container.querySelector("details b")?.textContent).toBe("cdn.fearevolve.com");
  });
});
