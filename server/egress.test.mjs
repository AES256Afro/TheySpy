import http from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { fetch } from "undici";
import { createEgress, hostOf } from "./egress.mjs";

const servers = [];
afterEach(() => { for (const s of servers.splice(0)) s.close(); });
async function local() {
  const server = http.createServer((_req, res) => res.end("ok"));
  servers.push(server);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${/** @type {import("node:net").AddressInfo} */ (server.address()).port}/`;
}

describe("outbound allowlist", () => {
  it("allows the feeds, names under a dotted entry, and the owner's extra hosts only", () => {
    const egress = createEgress({ extraHosts: () => ["pihole.lan", null] });
    expect(["www.cisa.gov", "services.nvd.nist.gov", "release-assets.githubusercontent.com", "githubusercontent.com", "WWW.CISA.GOV.", "pihole.lan"].map((h) => egress.allows(h))).toEqual([true, true, true, true, true, true]);
    expect(["example.com", "evilgithubusercontent.com", "cisa.gov", "169.254.169.254", "pihole.lan.evil.com"].map((h) => egress.allows(h))).toEqual([false, false, false, false, false]);
    expect(hostOf("http://[fd00::1]:8080/x")).toBe("fd00::1");
  });

  it("refuses a connection to an unlisted host and records it once", async () => {
    const url = await local();
    const entries = [];
    const audit = /** @type {any} */ ({ record: (...args) => entries.push(args) });
    const blocked = createEgress({ audit }).dispatcher();
    for (let i = 0; i < 2; i += 1) {
      const error = await fetch(url, { dispatcher: blocked }).catch((e) => e);
      expect(error.cause).toMatchObject({ code: "TS_EGRESS_BLOCKED" });
    }
    expect(entries).toEqual([["system", "egress.blocked", "127.0.0.1", { mode: "enforce" }]]);

    const allowed = createEgress({ extraHosts: () => ["127.0.0.1"] }).dispatcher();
    expect(await (await fetch(url, { dispatcher: allowed })).text()).toBe("ok");
    const logOnly = createEgress({ mode: "log", audit }).dispatcher();
    expect((await fetch(url, { dispatcher: logOnly })).status).toBe(200);
    expect(entries.at(-1)).toEqual(["system", "egress.unlisted", "127.0.0.1", { mode: "log" }]);
  });
});
