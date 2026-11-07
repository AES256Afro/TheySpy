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
