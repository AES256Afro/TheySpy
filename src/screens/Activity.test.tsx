// @vitest-environment jsdom
import { act, cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ActivityScreen, sizeText } from "./Activity.tsx";

const realFetch = globalThis.fetch;
afterEach(() => { cleanup(); globalThis.fetch = realFetch; });
const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });

const retention = {
  policy: { hits: 365, audit: 90, jobs: 90, checks: 365, events: 365, reports: 90 },
  labels: { hits: "Lookups of indicator addresses", audit: "The audit log", jobs: "Finished jobs", checks: "Finished targeted checks", events: "Device and CVE events", reports: "Agent reports (each agent's latest is kept)" },
  limits: { min: 7, max: 3650 },
  size: { bytes: 204_689_408, free: 3_145_728, tables: [{ name: "cves", rows: 108_078, bytes: 140_000_000 }, { name: "blocklist_versions", rows: 60, bytes: 33_000_000 }, { name: "audit_log", rows: 471, bytes: 90_000 }], lastTrim: null },
};

describe("the Activity screen's Database card (M35)", () => {
  it("says how big the file is, what fills it, and takes the days to keep", async () => {
    const calls: { method: string; url: string; body: unknown }[] = [];
    globalThis.fetch = (async (url: string, init?: RequestInit) => {
      calls.push({ method: init?.method ?? "GET", url, body: init?.body ? JSON.parse(String(init.body)) : undefined });
      if (url === "/api/jobs") return json({ jobs: [] });
      if (url === "/api/audit") return json({ entries: [] });
      if (url === "/api/security") return json({ notes: [] });
      if (url === "/api/household" && init?.method === "PUT") return json({ set: true });
      if (url === "/api/household") return json({ set: false });
      if (url === "/api/tls") return json({ enabled: true, port: 8798, fingerprint: "AB:CD:EF", notAfter: "2036-11-04T11:59:00.000Z", names: ["theyspy", "bigbox"], addresses: ["192.168.8.5"] });
      if (url === "/api/retention" && init?.method === "PUT") return json({ policy: { ...retention.policy, audit: 30 } });
      if (url === "/api/retention") return json(retention);
      return json({});
    }) as typeof fetch;
    const screen = render(<ActivityScreen />);
    await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
    const text = screen.container.textContent ?? "";
    expect(text).toContain("195 MB on disk, 3.0 MB of it free inside the file");
    expect(text).toContain("port 8798 · TheySpy’s own certificate");
    expect(text).toContain("AB:CD:EF");
    expect(text).toContain("For theyspy, bigbox, 192.168.8.5");
    expect(text).toContain("cves 134 MB (the CVE mirror");
    expect(text).toContain("Not trimmed yet.");
    const audit = screen.getByLabelText("The audit log") as HTMLInputElement;
    expect(audit.value).toBe("90");
    fireEvent.change(audit, { target: { value: "30" } });
    fireEvent.click(screen.getByText("Save"));
    await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
    expect(calls.find((c) => c.method === "PUT")).toEqual({ method: "PUT", url: "/api/retention", body: { audit: 30 } });
  });

  it("sets the household password from its card (M37)", async () => {
    const calls: { method: string; url: string; body: unknown }[] = [];
    globalThis.fetch = (async (url: string, init?: RequestInit) => {
      calls.push({ method: init?.method ?? "GET", url, body: init?.body ? JSON.parse(String(init.body)) : undefined });
      if (url === "/api/household") return json({ set: calls.some((c) => c.method === "PUT") });
      if (url === "/api/retention") return json(retention);
      return json({ jobs: [], entries: [], notes: [] });
    }) as typeof fetch;
    const screen = render(<ActivityScreen />);
    await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
    expect(screen.container.textContent).toContain("no household password");
    const set = screen.getByText("Set") as HTMLButtonElement;
    expect(set.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Household password"), { target: { value: "family-looks" } });
    expect(set.disabled).toBe(false);
    fireEvent.click(set);
    await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
    expect(calls.find((c) => c.method === "PUT")).toEqual({ method: "PUT", url: "/api/household", body: { password: "family-looks" } });
    expect(screen.container.textContent).toContain("a household password is set");
    expect(screen.getByText("Clear")).toBeTruthy();
  });

  it("formats sizes the way a person reads them", () => {
    expect(sizeText(204_689_408)).toBe("195 MB");
    expect(sizeText(12_500_000)).toBe("11.9 MB");
    expect(sizeText(655_360)).toBe("640 KB");
    expect(sizeText(null)).toBe("—");
  });
});
