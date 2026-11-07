// @vitest-environment jsdom
import { act, cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { EvidenceScreen } from "./Evidence.tsx";

const realFetch = globalThis.fetch;
afterEach(() => { cleanup(); globalThis.fetch = realFetch; });
const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
const settle = () => act(async () => { await new Promise((r) => setTimeout(r, 20)); });

describe("the Evidence screen (M23)", () => {
  it("B33: an import says how many findings it made, not just Imported", async () => {
    globalThis.fetch = (async (url: string, init?: RequestInit) => {
      const path = String(url);
      if (path.endsWith("/api/evidence")) return json({ findings: [], agents: [{ id: 1, name: "lab", platform: null, device: null, enrolledAt: "2026-11-07T10:00:00.000Z", lastReportAt: null, verdict: { status: "constructor", hits: 0, gaps: 0, scanner: null }, revoked: false }], scanner: { verified: true, version: "0.1.8" } });
      if (path.endsWith("/api/evidence/fingerprints")) return json({ fingerprints: [] });
      if (path.endsWith("/api/fleet")) return json({ devices: [{ id: 3, name: "pixel", ip: "192.168.1.3", network: null }] });
      if (path.endsWith("/api/evidence/devices/3/profile")) return json({ profile: {} });
      if (path.endsWith("/api/evidence/devices/3/mvt") && init?.method === "POST") return json({ findings: 2 });
      return json({});
    }) as typeof fetch;
    const screen = render(<EvidenceScreen />);
    await settle();
    // C40: a status the agent made up is shown as it is, not as a prototype property.
    expect(screen.getByText("constructor")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Phone"), { target: { value: "3" } });
    await settle();
    const file = new File(["[]"], "sms_detected.json", { type: "application/json" });
    if (typeof file.text !== "function") Object.defineProperty(File.prototype, "text", { value() { return new Promise((resolve) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.readAsText(this); }); } });
    fireEvent.change(screen.getByLabelText(/Import MVT results/), { target: { files: [file] } });
    await settle();
    expect(screen.getByText("2 new finding(s) from MVT.")).toBeTruthy();
    expect(screen.queryByText("Imported.")).toBeNull();
  });
});
