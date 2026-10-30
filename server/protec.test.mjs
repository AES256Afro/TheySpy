import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { inventoryFrom, upstreamVersion } from "./protec.mjs";
import { testServices } from "./test-helpers.mjs";

// The fixture is Protec 0.7's real /api/dashboard answer, read with a viewer credential, for a
// Debian 12 machine whose agent reported its dpkg packages (hostname c020fe528a78).
const dashboard = JSON.parse(readFileSync(new URL("./fixtures/protec-dashboard.json", import.meta.url), "utf8"));

describe("Protec packages", () => {
  it("takes the upstream version out of Debian's and Homebrew's", () => {
    expect(upstreamVersion("1:9.2p1-2+deb12u10", "dpkg")).toBe("9.2p1");
    expect(upstreamVersion("3.0.22-1~deb12u2", "dpkg")).toBe("3.0.22");
    expect(upstreamVersion("7.88.1-10+deb12u15", "dpkg")).toBe("7.88.1");
    expect(upstreamVersion("5.4.1+dfsg-1", "dpkg")).toBe("5.4.1");
    expect(upstreamVersion("3.3.2_1", "brew")).toBe("3.3.2");
    expect(upstreamVersion("not a version", "dpkg")).toBeNull();
  });

  it("finds the software TheySpy can check in a real Debian inventory", () => {
    const items = inventoryFrom(dashboard.devices[0].inventory.packages);
    expect(items).toEqual(expect.arrayContaining([
      { software: "openssh", version: "9.2p1" }, { software: "openssl", version: "3.0.22" }, { software: "curl", version: "7.88.1" },
      { software: "bash", version: "5.2.15" }, { software: "python", version: "3.11.2" }, { software: "glibc", version: expect.any(String) },
    ]));
    expect(new Set(items.map((i) => i.software)).size).toBe(items.length); // one version per product
  });

  it("matches machines to Fleet devices by hostname, lets the owner link the rest, and feeds CVE matching", async () => {
    const fetchImpl = async (_url, init) => (init.headers.authorization === "Bearer good" ? Response.json(dashboard) : new Response("", { status: 401 }));
    const s = testServices({ protecFetch: fetchImpl });
    s.protec.configure({ url: "http://protec.lan:8765", token: "bad" }, "owner");
    await expect(s.protec.sync("owner")).rejects.toThrow(/may have expired/);
    s.protec.configure({ token: "good" }, "owner");

    const first = await s.protec.sync("owner");
    expect(first).toMatchObject({ machines: 1, matched: 0, unmatched: [{ hostname: "c020fe528a78", os: "Linux" }] });

    s.fleet.observe([{ ip: "192.168.1.30", mac: "52:54:00:12:34:56", hostname: "debian-box", seenAt: "2026-10-30T12:00:00.000Z" }], "pihole", { inventory: true });
    const device = s.fleet.list()[0];
    s.protec.link(first.unmatched[0].id, device.id, "owner");
    const second = await s.protec.sync("owner");
    expect(second).toMatchObject({ matched: 1, unmatched: [] });
    expect(second.packages).toBeGreaterThanOrEqual(6);
    const inventory = s.agents.inventory(device.id);
    expect(inventory.find((i) => i.product === "openssh")).toMatchObject({ vendor: "openbsd", version: "9.2p1", source: "protec-dpkg" });
  });
});
