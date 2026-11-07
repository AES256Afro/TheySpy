// @vitest-environment jsdom
import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Console, Verdict } from "./Overview.tsx";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const lookup = (deviceId: number, domain: string, indicator = "c2.example") => ({ device: `device ${deviceId}`, deviceId, clientIp: "192.168.1.30", domain, indicator, via: "query", lookups: 2, blocked: 0, lastSeen: "2026-11-07T11:00:00.000Z" });
const row = (id: number, notBlocked: number) => ({ id, name: `device ${id}`, ip: `192.168.1.${id}`, kind: null, online: true, isNew: false, trusted: true, lastSeen: "2026-11-07T11:00:00.000Z", hits: notBlocked, notBlocked, kev: 0, exposure: null, agentAt: null, attention: notBlocked ? 3 : 0 });
const data = (top: ReturnType<typeof lookup>[], devices: ReturnType<typeof row>[]) => ({
  at: "2026-11-07T12:00:00.000Z",
  status: { pihole: true, watch: true, devices: devices.length, online: devices.length },
  questions: { contacts: { count: top.length, lookups: top.length * 2, top }, exploited: { count: 0, devices: [], top: [] }, newDevices: { count: 0, names: [] }, network: { failing: 0, unknown: 0, of: 3, factors: [] } },
  gaps: [], gapsTotal: 0, events: [], devices,
});

describe("the Overview (M22)", () => {
  it("B31: the Console inspector does not say none not blocked for a device whose row says otherwise", () => {
    // Five devices fill the top five; the sixth, selected, has one lookup that was not blocked.
    const top = [1, 2, 3, 4, 5].map((id) => lookup(id, "c2.example"));
    const screen = render(<Console data={data(top, [row(6, 1), ...[1, 2, 3, 4, 5].map((id) => row(id, 2))])} />);
    expect(screen.queryByText("none not blocked")).toBeNull();
    expect(screen.getByText("1 not blocked (see device page)")).toBeTruthy();
  });

  it("C39: two subdomains of one indicator from one address are two rows, not one key twice", () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    render(<Verdict data={data([lookup(1, "a.c2.example"), lookup(1, "b.c2.example")], [row(1, 4)])} />);
    expect(errors.mock.calls.map((c) => String(c[0])).filter((m) => /same key/.test(m))).toEqual([]);
  });
});
