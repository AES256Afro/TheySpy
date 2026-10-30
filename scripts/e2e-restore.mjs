// Driven by e2e-restore.sh: write state through the API (before), add a device and a finding while
// TheySpy is stopped (seed), and after the restore check that all of it came back (after).
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

const phase = process.argv[2];
const step = (text) => console.log(`- ${text}`);
const base = `http://127.0.0.1:${process.env.PORT}`;
let cookie = "";
/** @returns {Promise<any>} */
async function api(method, path, body, headers = {}) {
  const response = await fetch(base + path, { method, headers: { "content-type": "application/json", "x-theyspy": "1", ...(cookie ? { cookie } : {}), ...headers }, body: body ? JSON.stringify(body) : undefined });
  const set = response.headers.get("set-cookie");
  if (set) cookie = set.split(";")[0];
  if (!response.ok) throw new Error(`${method} ${path}: ${response.status} ${await response.text()}`);
  return (response.headers.get("content-type") ?? "").includes("json") ? response.json() : response.arrayBuffer();
}

if (phase === "seed") {
  const db = new DatabaseSync(String(process.env.DB));
  const { lastInsertRowid } = db.prepare("INSERT INTO devices (mac, ip, label, first_seen, last_seen) VALUES ('f0:18:98:00:00:77', '192.168.1.77', 'restore-test-laptop', '2026-10-29T12:00:00Z', '2026-10-29T12:00:00Z')").run();
  db.prepare("INSERT INTO device_addresses (device_id, ip, first_seen, last_seen) VALUES (?, '192.168.1.77', '2026-10-29T12:00:00Z', '2026-10-29T12:00:00Z')").run(lastInsertRowid);
  db.prepare("INSERT INTO findings (device_id, source, kind, indicator, at) VALUES (?, 'agent', 'contacted', 'fearevolve.com', '2026-10-29T12:00:00Z')").run(lastInsertRowid);
  db.close();
  step("added a device and a finding while TheySpy was stopped");
} else {
  await api("POST", "/api/login", { password: process.env.PASSWORD });
  if (phase === "before") {
    await api("PUT", "/api/appearance", { name: "Restore test" });
    const { token } = await api("POST", "/api/briefing/tokens", { name: "restore test" });
    const copy = new Uint8Array(await api("GET", "/api/backup"));
    assert.equal(Buffer.from(copy.subarray(0, 15)).toString(), "SQLite format 3", "the live backup is a SQLite file");
    writeFileSync(String(process.env.STATE), JSON.stringify({ token }));
    step("set the branding, created an API token, downloaded a live backup");
  } else {
    const { token } = JSON.parse(readFileSync(String(process.env.STATE), "utf8"));
    assert.equal((await api("GET", "/api/appearance")).appearance.name, "Restore test");
    const status = await api("GET", "/api/v1/status", undefined, { authorization: `Bearer ${token}`, cookie: "" });
    assert.ok(status, "the API token from before the restore still works");
    const devices = (await api("GET", "/api/fleet")).devices;
    assert.ok(devices.some((d) => d.ip === "192.168.1.77"), "the device came back");
    const findings = (await api("GET", "/api/evidence")).findings;
    assert.deepEqual(findings.map((f) => f.indicator), ["fearevolve[.]com"], "the finding came back");
    step("after the restore: branding, the API token, the device and the finding are all back");
  }
}
