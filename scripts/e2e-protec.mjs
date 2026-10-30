// Driven by e2e-protec.sh: TheySpy reads a real Protec with a viewer credential, matches its
// machine to a Fleet device, and that device's packages become what its CVEs are matched against.
import assert from "node:assert/strict";
import { testServices } from "../server/test-helpers.mjs";

const step = (text) => console.log(`- ${text}`);
const s = testServices({ protecFetch: fetch });
s.protec.configure({ url: String(process.env.PROTEC_URL), token: String(process.env.PROTEC_VIEWER) }, "owner");
const first = await s.protec.sync("owner");
assert.equal(first.machines, 1);
assert.equal(first.unmatched.length, 1, "an enrolled machine TheySpy has not seen is listed to link");
step(`read Protec: ${first.machines} machine (${first.unmatched[0].hostname}, ${first.unmatched[0].os}) with ${first.unmatched[0].packages} checkable packages, not yet in the Fleet`);

s.fleet.observe([{ ip: "192.168.1.40", mac: null, hostname: first.unmatched[0].hostname, seenAt: new Date().toISOString() }], "pihole", { inventory: true });
const second = await s.protec.sync("owner");
assert.deepEqual([second.matched, second.unmatched.length], [1, 0], "matched by hostname once the Fleet knows it");
const device = s.fleet.list()[0];
const products = s.agents.inventory(device.id).map((i) => `${i.vendor}:${i.product}`);
assert.ok(products.includes("openssl:openssl") && products.includes("gnu:glibc"), `the machine's packages are its inventory: ${products.join(", ")}`);
step(`matched by hostname; its inventory for CVE matching: ${products.join(", ")}`);

const refused = await fetch(`${process.env.PROTEC_URL}/api/enrollments`, { method: "POST", headers: { authorization: `Bearer ${process.env.PROTEC_VIEWER}`, "content-type": "application/json" }, body: "{}" });
assert.equal(refused.status, 403, "the viewer credential cannot change Protec");
step("the viewer credential is refused for any change in Protec");
