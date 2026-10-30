// Driven by e2e-sites.sh: the hub adds the cabin with a read-only token made there, reads it, and
// is told about the lookup that got past the cabin's blocking - once. The token cannot change anything.
import assert from "node:assert/strict";
import { testServices } from "../server/test-helpers.mjs";

const site = String(process.env.SITE_URL);
const step = (text) => console.log(`- ${text}`);
let cookie = "";
const cabin = async (method, path, body) => {
  const r = await fetch(site + path, { method, headers: { "content-type": "application/json", "x-theyspy": "1", ...(cookie ? { cookie } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const set = r.headers.get("set-cookie"); if (set) cookie = set.split(";")[0];
  assert.ok(r.ok, `${method} ${path}: ${r.status}`);
  return /** @type {any} */ (await r.json());
};
await cabin("POST", "/api/login", { password: process.env.SITE_PASSWORD });
const { token } = await cabin("POST", "/api/briefing/tokens", { name: "home hub" });
step("the cabin made a read-only API token for the hub");

const hub = testServices();
hub.sites.add({ name: "Cabin", url: site, token }, "owner");
const [reading] = await hub.sites.refresh();
assert.equal(reading.error, null, `read without error: ${reading.error}`);
assert.deepEqual(reading.gotThrough.map((l) => [l.device, l.indicator, l.lookups, l.blocked]), [["cabin-laptop", "fearevolve[.]com", 1, 0]]);
assert.ok(reading.sections.some((s) => s.title === "Spyware and ad-intelligence" && s.tone === "bad"), "the cabin's own status says so too");
step(`read the cabin: ${reading.lookups} indicator lookup, got past blocking on ${reading.gotThrough[0].device}`);

const alerts = () => hub.audit.list(50).filter((e) => e.action === "sites.indicator_lookups");
assert.equal(alerts().length, 1, "one alert for the new lookup");
await hub.sites.refresh();
assert.equal(alerts().length, 1, "and not again on the next reading");
step("the hub raised one alert for it, and not again on the next reading");

// The token reads; it cannot act as the owner at the cabin.
const write = await fetch(`${site}/api/pihole/settings`, { method: "PUT", headers: { authorization: `Bearer ${token}`, "content-type": "application/json", "x-theyspy": "1" }, body: JSON.stringify({ write: true }) });
assert.equal(write.status, 401, "the read-only token cannot change the cabin");
step("the same token is refused for any change at the cabin");
