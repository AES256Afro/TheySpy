// @vitest-environment jsdom
import { act, cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { BriefingScreen } from "./Briefing.tsx";

const realFetch = globalThis.fetch;
afterEach(() => { cleanup(); globalThis.fetch = realFetch; });
const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });

const briefing = {
  digest: { week: "2026-W45", since: "2026-10-31T00:00:00.000Z", until: "2026-11-07T00:00:00.000Z", sections: [], alerts: 0 },
  alerts: [],
  ntfy: { url: "", topic: "", hasToken: false, fromEnv: { url: false, topic: false, token: false }, ready: false },
  webhook: { url: "", hasSecret: false, ready: false },
  tokens: [],
};

describe("the Briefing screen's webhook card (M36)", () => {
  it("saves an address and a secret, and sends the secret only when typed", async () => {
    const calls: { method: string; url: string; body: unknown }[] = [];
    globalThis.fetch = (async (url: string, init?: RequestInit) => {
      calls.push({ method: init?.method ?? "GET", url, body: init?.body ? JSON.parse(String(init.body)) : undefined });
      if (init?.method === "PUT") return json({ webhook: { url: "https://hooks.example/theyspy", hasSecret: true, ready: true } });
      return json(briefing);
    }) as typeof fetch;
    const screen = render(<BriefingScreen />);
    await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
    expect(screen.container.textContent).toContain("Or a webhook");
    fireEvent.change(screen.getByLabelText("Address"), { target: { value: "https://hooks.example/theyspy" } });
    fireEvent.change(screen.getByLabelText("Secret"), { target: { value: "hush" } });
    const saves = screen.getAllByText("Save");
    fireEvent.click(saves[1]); // the ntfy card's Save comes first
    await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
    expect(calls.find((c) => c.method === "PUT")).toEqual({ method: "PUT", url: "/api/briefing/webhook", body: { url: "https://hooks.example/theyspy", secret: "hush" } });
    expect((screen.getByLabelText("Secret") as HTMLInputElement).value).toBe("");
    expect(screen.container.textContent).toContain("Saved.");
  });
});
