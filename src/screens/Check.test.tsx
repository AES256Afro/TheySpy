// @vitest-environment jsdom
import { act, cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CheckScreen } from "./Check.tsx";

// B20: a screen that started a job stops asking about it once the owner has moved on. Sweep 2 added
// the stopping flag to waitForJob; this is the test that the screens actually pass it.
const realFetch = globalThis.fetch;
afterEach(() => { cleanup(); globalThis.fetch = realFetch; vi.useRealTimers(); });

describe("the Check screen", () => {
  it("stops polling a job once it is unmounted", async () => {
    vi.useFakeTimers();
    const calls: string[] = [];
    const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    globalThis.fetch = (async (url: string, init?: RequestInit) => {
      calls.push(`${init?.method ?? "GET"} ${url}`);
      if (String(url).endsWith("/api/fleet/checks")) return json({ checks: [], profiles: [{ id: "quick", label: "Quick", ports: 0 }, { id: "standard", label: "Standard", ports: 67 }], scanRanges: ["192.168.0.0/16"] });
      if (String(url).endsWith("/api/fleet/check")) return json({ job: { id: 7 } });
      if (String(url).endsWith("/api/jobs/7")) return json({ job: { id: 7, kind: "fleet.check", status: "running" } }); // never finishes
      return json({});
    }) as typeof fetch;

    const screen = render(<CheckScreen />);
    await act(async () => { await vi.advanceTimersByTimeAsync(10); });
    const input = screen.getByLabelText("What to check") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "192.168.1.10" } });
    fireEvent.submit(input.closest("form")!);
    await act(async () => { await vi.advanceTimersByTimeAsync(2_000); });
    const polled = calls.filter((c) => c.endsWith("/api/jobs/7")).length;
    expect(polled).toBeGreaterThan(1);

    screen.unmount();
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    // At most one poll already in flight when the screen went; nothing after it.
    expect(calls.filter((c) => c.endsWith("/api/jobs/7")).length).toBeLessThanOrEqual(polled + 1);
  });
});

describe("M25 B36", () => {
  it("shows when an indicator lookup last happened, from the field the server sends", async () => {
    const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    globalThis.fetch = (async (url: string) => {
      if (String(url).endsWith("/api/fleet/checks")) return json({ checks: [{ id: 9, query: "192.168.1.30", kind: "ip", profile: "dns", startedAt: "2026-11-07T12:00:00.000Z", finishedAt: "2026-11-07T12:00:01.000Z" }], profiles: [{ id: "dns", label: "DNS only", ports: 0 }], scanRanges: ["192.168.0.0/16"] });
      if (String(url).endsWith("/api/fleet/checks/9")) return json({ check: { id: 9, query: "192.168.1.30", kind: "device", profile: "dns", durationMs: 1000, ip: "192.168.1.30", up: null, open: null, services: [], device: null,
        dns: { connected: true, totalLookups: 2, topDomains: [], hits: [{ domain: "c2.example", indicator: "c2.example", lookups: 2, blocked: 1, lastSeen: "2026-11-07T09:00:00.000Z", lastStatus: "GRAVITY" }] } } });
      return json({});
    }) as typeof fetch;
    const screen = render(<CheckScreen />);
    await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
    fireEvent.click(screen.getByText("192.168.1.30"));
    await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
    const banner = screen.getByText(/Indicator lookups\./).parentElement!.textContent ?? "";
    expect(banner).not.toContain("Invalid Date");
    expect(banner).toContain(new Date("2026-11-07T09:00:00.000Z").toLocaleString());
    expect(banner).toContain("1 not blocked");
  });
});
