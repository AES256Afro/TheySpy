import { describe, expect, it } from "vitest";
import { fakeWeb, testServices } from "../test-helpers.mjs";
import { ouiUrl, parseOuiCsv } from "./oui.mjs";

const header = "Registry,Assignment,Organization Name,Organization Address\n";
const real = 'MA-L,A0AD9F,ASUSTek COMPUTER INC.,"15,Li-Te Rd., Peitou, Taipei 112, Taiwan Taipei  TW 112 "\nMA-L,286FB9,"Nokia Shanghai Bell Co., Ltd.","No.388 Ning Qiao Road"\nMA-M,70B3D5123,Somebody,Somewhere\n';
// The registry has about 40,000 prefixes; a reply with fewer than 10,000 is refused as broken.
const filler = Array.from({ length: 10_000 }, (_, i) => `MA-L,${(0x100000 + i).toString(16).toUpperCase()},Vendor ${i},Address`).join("\n");

describe("MAC vendors", () => {
  it("parses the IEEE registry's CSV, quotes and all", () => {
    const m = parseOuiCsv(header + real);
    expect(m.get("a0ad9f")).toBe("ASUSTek COMPUTER INC.");
    expect(m.get("286fb9")).toBe("Nokia Shanghai Bell Co., Ltd.");
    expect(m.size).toBe(2);
  });

  it("loads the registry, names devices that had no vendor, and skips private MACs", async () => {
    const web = fakeWeb({ [ouiUrl]: { body: header + real + filler, etag: '"v1"' } });
    const { oui, fleet } = testServices({ webFetch: web.fetchImpl });
    fleet.observe([{ ip: "192.168.8.10", mac: "a0:ad:9f:87:ad:ee", seenAt: "2026-10-29T11:00:00.000Z" }, { ip: "192.168.8.22", mac: "6a:5d:c7:7d:f3:b0", seenAt: "2026-10-29T11:00:00.000Z" }], "arp");
    expect(await oui.update()).toMatchObject({ changed: true, named: 1, prefixes: 10_002 });
    expect(fleet.list().find((d) => d.ip === "192.168.8.10").vendor).toBe("ASUSTek COMPUTER INC.");
    expect(oui.vendorOf("6a:5d:c7:7d:f3:b0")).toBeNull();
    // New devices are named as they are seen; an unchanged registry is not downloaded again.
    fleet.observe([{ ip: "192.168.8.30", mac: "28:6f:b9:00:00:01", seenAt: "2026-10-29T11:01:00.000Z" }], "arp");
    expect(fleet.list().find((d) => d.ip === "192.168.8.30").vendor).toBe("Nokia Shanghai Bell Co., Ltd.");
    expect(await oui.update()).toMatchObject({ changed: false, named: 0 });
  });

  it("keeps the current registry when a download looks wrong", async () => {
    const web = fakeWeb({ [ouiUrl]: header + real });
    const { oui } = testServices({ webFetch: web.fetchImpl });
    await expect(oui.update()).rejects.toThrow(/looked wrong/);
    expect(oui.status().prefixes).toBe(0);
  });
});
