import { describe, expect, it } from "vitest";
import { testServices } from "../test-helpers.mjs";

// A NetAlertX as its API behaves (checked against the real one in scripts/e2e-netalertx.sh):
// GET /devices, POST /device/<mac>/update-column for one field, and POST /device/<mac>, which
// replaces every field - so TheySpy must never call it.
function fakeNetAlertX(devices) {
  const calls = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(String(input));
    calls.push(`${init.method ?? "GET"} ${url.pathname}`);
    if (init.headers?.authorization !== "Bearer t_good") return Response.json({ success: false, error: "Forbidden" }, { status: 403 });
    if (url.pathname === "/devices") return Response.json({ success: true, devices });
    const column = /^\/device\/([^/]+)\/update-column$/.exec(url.pathname);
    if (column) { const d = devices.find((x) => x.devMac === decodeURIComponent(column[1])); const b = JSON.parse(init.body); d[b.columnName] = b.columnValue; return Response.json({ success: true }); }
    return Response.json({ success: false, error: "not used here" }, { status: 400 });
  };
  return { fetchImpl, calls };
}

describe("NetAlertX", () => {
  it("brings devices, names, owners and types in, and fills only empty fields there, one at a time", async () => {
    const devices = [
      { devMac: "AA:BB:CC:00:00:01", devName: "Living room TV", devOwner: "Family", devType: "TV", devLastIP: "192.168.1.50", devComments: "wall mount" },
      { devMac: "aa:bb:cc:00:00:02", devName: "(unknown)", devOwner: "", devType: "", devLastIP: "192.168.1.51", devComments: "found by arp" },
    ];
    const nax = fakeNetAlertX(devices);
    const s = testServices({ netalertxFetch: nax.fetchImpl });
    s.fleet.observe([{ ip: "192.168.1.51", mac: "aa:bb:cc:00:00:02", hostname: null, seenAt: "2026-10-30T12:00:00.000Z" }], "pihole", { inventory: true });
    s.fleet.edit(s.fleet.list()[0].id, { label: "Kids iPad", owner: "Sam", kind: "tablet" }, "owner");

    s.netalertx.configure({ url: "http://nax.lan:20212", token: "t_bad" }, "owner");
    await expect(s.netalertx.test()).rejects.toThrow(/refused the API token/);
    s.netalertx.configure({ token: "t_good" }, "owner");
    expect(s.netalertx.config()).toMatchObject({ configured: true, url: "http://nax.lan:20212", hasToken: true, write: false });

    expect(await s.netalertx.pull("owner")).toMatchObject({ devices: 2, added: 1, named: 1, filled: 1, toFill: 3 });
    expect(s.fleet.list().find((d) => d.mac === "aa:bb:cc:00:00:01")).toMatchObject({ name: "Living room TV", nameFrom: "NetAlertX", owner: "Family", kind: "TV" });
    expect(s.fleet.list().find((d) => d.mac === "aa:bb:cc:00:00:02")).toMatchObject({ name: "Kids iPad", owner: "Sam" }); // the owner's label wins over NetAlertX's

    await expect(s.netalertx.push("owner")).rejects.toThrow(/turned off/);
    s.netalertx.configure({ write: true }, "owner");
    expect((await s.netalertx.push("owner")).filled).toBe(3);
    expect(devices[1]).toMatchObject({ devName: "Kids iPad", devOwner: "Sam", devType: "tablet", devComments: "found by arp" });
    expect(devices[0]).toMatchObject({ devName: "Living room TV", devOwner: "Family", devType: "TV" });
    expect(nax.calls.filter((c) => c.startsWith("POST")).every((c) => c.endsWith("/update-column"))).toBe(true); // never the full replace
    expect((await s.netalertx.preview()).changes).toEqual([]);
  });

  it("keeps a configured token when another setting is saved", () => {
    const s = testServices();
    s.netalertx.configure({ url: "http://nax.lan:20212", token: "t_good" }, "owner");
    s.netalertx.configure({ write: true }, "owner");
    s.netalertx.configure({ url: "http://192.168.1.5:20212" }, "owner");
    expect(s.netalertx.config()).toMatchObject({ url: "http://192.168.1.5:20212", hasToken: true, write: true });
  });
});
