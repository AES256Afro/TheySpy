// @vitest-environment jsdom
import { act, cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ChecksScreen } from "./Checks.tsx";

const realFetch = globalThis.fetch;
afterEach(() => { cleanup(); globalThis.fetch = realFetch; });
const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
const f = (id: string, label: string, state: string, evidence = "", fix = "do the thing") => ({ id, label, state, evidence, fix });

describe("the Checks screen (M33)", () => {
  it("lists the steps a fresh install has left, and each check with who fails it", async () => {
    globalThis.fetch = (async () => json({
      network: [f("gateway", "Pi-hole blocks indicators", "fail", "Pi-hole is not connected."), f("watch", "Live watch for indicator lookups", "fail", "The live watch is off."), f("egress", "Not IP-targetable through Starlink", "unknown", "Not checked yet")],
      devices: [
        { id: 1, name: "pixel-9", factors: [f("dns", "DNS through Pi-hole", "fail", "skips Pi-hole"), f("blocker", "Ad blocking on the device", "unknown"), f("scan", "Device scanned in the last 7 days", "na")] },
        { id: 2, name: "macbook", factors: [f("dns", "DNS through Pi-hole", "pass"), f("blocker", "Ad blocking on the device", "unknown"), f("scan", "Device scanned in the last 7 days", "fail", "No agent on this computer.")] },
      ],
    })) as typeof fetch;
    const screen = render(<ChecksScreen />);
    await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
    const text = screen.container.textContent ?? "";
    expect(text).toContain("6 checks: 0 passing everywhere, 4 failing somewhere, 2 not yet checked");
    expect(text).toContain("Connect Pi-hole");
    expect(text).toContain("Add the agent to a computer");
    expect(text).toContain("Open This device on each phone and computer once");
    expect(text).toMatch(/DNS through Pi-hole · 1 pass · 1 fail.*Failing: pixel-9/);
    expect(text).toMatch(/Device scanned in the last 7 days · 0 pass · 1 fail · 1 n\/a.*Failing: macbook/);
  });
});
