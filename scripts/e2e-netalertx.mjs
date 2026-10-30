// Driven by e2e-netalertx.sh against a real NetAlertX: its devices and names come into the Fleet,
// TheySpy fills only NetAlertX fields that are empty, and only when allowed, one field at a time,
// leaving every other field there exactly as it was.
import assert from "node:assert/strict";
import { testServices } from "../server/test-helpers.mjs";

const url = String(process.env.NETALERTX_URL);
const token = String(process.env.NETALERTX_TOKEN);
const step = (text) => console.log(`- ${text}`);
/** @returns {Promise<any>} */
const nax = async (path, body) => {
  const r = await fetch(`${url}${path}`, { method: body ? "POST" : "GET", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  assert.ok(r.ok, `${path}: ${r.status}`);
  return r.json();
};

// NetAlertX: a TV the owner named there, and a device it knows only as "(unknown)".
await nax("/device/aa:bb:cc:00:00:01", { createNew: true, devName: "Living room TV", devOwner: "Family", devType: "TV", devLastIP: "192.168.1.50", devComments: "wall mount" });
await nax("/device/aa:bb:cc:00:00:02", { createNew: true, devName: "(unknown)", devLastIP: "192.168.1.51", devComments: "found by arp" });

// TheySpy: the second device already known, with the owner's label, owner and kind.
const s = testServices({ netalertxFetch: fetch });
s.fleet.observe([{ ip: "192.168.1.51", mac: "aa:bb:cc:00:00:02", hostname: null, seenAt: "2026-10-30T12:00:00.000Z" }], "pihole", { inventory: true });
const known = s.fleet.list()[0];
s.fleet.edit(known.id, { label: "Kids iPad", owner: "Sam", kind: "tablet" }, "owner");
s.netalertx.configure({ url, token }, "owner");
assert.equal((await s.netalertx.test()).devices, 2);

const pulled = await s.netalertx.pull("owner");
assert.equal(pulled.devices, 2);
const tv = s.fleet.list().find((d) => d.mac === "aa:bb:cc:00:00:01");
assert.ok(tv, "NetAlertX's TV joins the Fleet by MAC");
// The first sync is an inventory, as Pi-hole's first is: nothing in it is announced as new.
assert.deepEqual([tv.name, tv.nameFrom, tv.owner, tv.kind, tv.isNew], ["Living room TV", "NetAlertX", "Family", "TV", false]);
step(`pulled ${pulled.devices} devices: the TV arrived named "${tv.name}" (from ${tv.nameFrom}), with NetAlertX's owner and type`);

const { changes } = await s.netalertx.preview();
assert.deepEqual(changes.map((c) => [c.mac, c.column, c.to]), [["aa:bb:cc:00:00:02", "devName", "Kids iPad"], ["aa:bb:cc:00:00:02", "devOwner", "Sam"], ["aa:bb:cc:00:00:02", "devType", "tablet"]], "only empty NetAlertX fields, only where TheySpy knows better");
await assert.rejects(s.netalertx.push("owner"), /turned off/);
s.netalertx.configure({ write: true }, "owner");
const pushed = await s.netalertx.push("owner");
assert.equal(pushed.filled, 3);
const after = await nax("/device/aa:bb:cc:00:00:02");
assert.deepEqual([after.devName, after.devOwner, after.devType, after.devComments, after.devLastIP], ["Kids iPad", "Sam", "tablet", "found by arp", "192.168.1.51"], "filled fields, and the owner's comment and address untouched");
const tvAfter = await nax("/device/aa:bb:cc:00:00:01");
assert.deepEqual([tvAfter.devName, tvAfter.devOwner, tvAfter.devType, tvAfter.devComments], ["Living room TV", "Family", "TV", "wall mount"], "a device the owner filled in NetAlertX is left alone");
assert.deepEqual((await s.netalertx.preview()).changes, [], "nothing left to fill");
step(`filled ${pushed.filled} empty NetAlertX fields one at a time; comments, addresses and the TV's own fields unchanged`);

// A device NetAlertX finds later is new in TheySpy too, and filling its owner does not acknowledge it.
await nax("/device/aa:bb:cc:00:00:03", { createNew: true, devName: "Unknown phone", devOwner: "Guest", devLastIP: "192.168.1.52" });
await s.netalertx.pull("system");
const phone = s.fleet.list().find((d) => d.mac === "aa:bb:cc:00:00:03");
assert.deepEqual([phone.name, phone.owner, phone.isNew], ["Unknown phone", "Guest", true]);
assert.ok(s.audit.list(30).some((e) => e.action === "fleet.new_device"), "and it raises the new-device alert");
step("a device NetAlertX found later arrived as new, with its owner filled and still unacknowledged");
