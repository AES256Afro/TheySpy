// End-to-end check of Pi-hole Sentinel against a real Pi-hole 6 (run by scripts/e2e-pihole.sh, which
// starts an offline Pi-hole and sends DNS lookups from fixed client addresses first).
// Exit criterion M2: every lookup is found with the right client and time, and a push followed by
// a rollback leaves Pi-hole's lists exactly as they were.
//   PIHOLE_URL=http://127.0.0.1:18053 PIHOLE_PASSWORD=… node scripts/e2e-pihole.mjs
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createAuditLog } from "../server/audit.mjs";
import { createSettingsStore, openDatabase } from "../server/db.mjs";
import { createIocStore } from "../server/iocs/store.mjs";
import { createPiholeClient } from "../server/pihole/client.mjs";
import { createSentinel } from "../server/pihole/sentinel.mjs";
import { createSecretBox } from "../server/secrets.mjs";
import express from "express";
import { createBlocklistLibrary } from "../server/blocklists/library.mjs";
import { publicListRoutes } from "../server/blocklists/routes.mjs";
import { createBaselines } from "../server/blocklists/baselines.mjs";

const url = process.env.PIHOLE_URL ?? "http://127.0.0.1:18053";
const password = process.env.PIHOLE_PASSWORD ?? "";
const step = (text) => console.log(`- ${text}`);

// A throwaway TheySpy with a test indicator set: reserved .test names, so nothing real is looked up.
const db = openDatabase(":memory:");
const settings = createSettingsStore(db);
const audit = createAuditLog(db);
const iocStore = createIocStore({ db, audit });
iocStore.seedBundled();
const testSet = "# as-of: 2026-10-29\nads-sync.theyspy.test\tdelivery\tprimary\te2e\nc2-node.theyspy.test\tcc\tprimary\te2e\n";
iocStore.apply(iocStore.recordCandidate({ raw: testSet, provenance: { track: "main", note: "e2e" }, actor: "e2e" }).id, "e2e");
const sentinel = createSentinel({ db, settings, audit, iocStore, secretBox: createSecretBox(Buffer.alloc(32, 7)) });
sentinel.configure({ mode: "api", url, password, write: true }, "e2e");

const snapshot = async () => createPiholeClient({ url, password }).session(async (c) => {
  const lists = {};
  for (const type of ["allow", "deny"]) for (const kind of ["exact", "regex"]) lists[`${type}/${kind}`] = (await c.listDomains(type, kind)).map(({ date_modified: _modified, ...rest }) => rest);
  lists.adlists = (await c.listAdlists("block")).map((l) => `${l.id} ${l.address} ${l.enabled} ${JSON.stringify(l.groups)}`);
  lists.groups = (await c.listGroups()).map((g) => `${g.id} ${g.name}`);
  lists.clients = (await c.listClients()).map((x) => `${x.client} ${JSON.stringify(x.groups)} ${x.comment}`);
  return JSON.stringify(lists);
});

const version = await sentinel.test();
step(`connected to Pi-hole core ${version.core}, FTL ${version.ftl}`);

// Pi-hole makes a query visible through its API a few seconds after answering it. In real use the
// live watch re-reads the last 90 seconds on every poll; here, wait until the last lookup the shell
// script made (unrelated.theyspy.test) shows up before hunting.
for (let i = 0; i < 30; i += 1) {
  const visible = await createPiholeClient({ url, password }).session((c) => c.queries({ domain: "unrelated.theyspy.test" }));
  if (visible.length) break;
  await new Promise((resolve) => setTimeout(resolve, 1000));
}
const hunt = await sentinel.hunt({ windowDays: 1 });
const hits = sentinel.hits();
const pairs = hits.map((h) => `${h.domain} <- ${h.clientIp}`).sort();
step(`hunt: ${hunt.queriesSeen} queries looked at, ${hunt.hits} matching lookups`);
if (pairs.length !== 4) {
  // On failure, show Pi-hole's own log beside what the hunt found, to tell a missed lookup from one never made.
  const all = await createPiholeClient({ url, password }).session((c) => c.queries({}));
  console.log(`Pi-hole's log:\n${all.map((q) => `  ${q.id} ${q.type} ${q.domain} <- ${q.client.ip} ${q.status}`).join("\n")}`);
}
assert.deepEqual(pairs, [
  "ads-sync.theyspy.test <- 172.29.53.10",
  "ads-sync.theyspy.test <- 172.29.53.11",
  "c2-node.theyspy.test <- 172.29.53.11",
  "deep.ads-sync.theyspy.test <- 172.29.53.10",
], "every indicator lookup found with its client; the lookalike notads-sync is not");
const sent = Number(process.env.E2E_SENT_AT ?? 0);
for (const h of hits) assert.ok(!sent || Math.abs(Date.parse(h.lastSeen) / 1000 - sent) < 600, `${h.domain} time ${h.lastSeen} is when it was sent`);
assert.equal(hits.find((h) => h.domain === "c2-node.theyspy.test").lookups >= 2, true, "both c2-node lookups counted");
assert.equal((await sentinel.hunt({ windowDays: 1 })).newHits, 0, "a second hunt counts nothing twice");
step("every lookup has the right client and time; a second hunt adds nothing");

const coverage = await sentinel.coverage();
assert.equal(coverage.blocked, 0);
step(`coverage before: ${coverage.blocked} of ${coverage.total} blocked`);

const before = await snapshot();
const pushed = await sentinel.push(sentinel.pushPreview().domains, "e2e");
assert.equal(pushed.added, 2);
const after = await sentinel.coverage();
assert.equal(after.fullyBlocked, 2, "both domains and their subdomains blocked after the push");
step(`pushed ${pushed.added} wildcard deny entries; coverage now ${after.fullyBlocked} of ${after.total} with subdomains`);

if (process.env.E2E_DOCKER_NETWORK) {
  // One more lookup while TheySpy's entry is live; Pi-hole should block it and the watch should see it.
  // Pi-hole reloads its lists after a change and can drop a packet meanwhile, so retry like a device would.
  let blocked = null;
  for (let attempt = 1; attempt <= 6 && !blocked; attempt += 1) {
    try {
      execFileSync("docker", ["run", "--rm", "--network", process.env.E2E_DOCKER_NETWORK, "--ip", "172.29.53.14", "busybox:1.37", "nslookup", "-timeout=2", "deeper.c2-node.theyspy.test", "172.29.53.2"], { stdio: "ignore" });
    } catch { /* a blocked name can make nslookup exit non-zero; the poll below is what counts */ }
    await sentinel.watch.poll();
    blocked = sentinel.hits().find((h) => h.domain === "deeper.c2-node.theyspy.test");
    if (!blocked) await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  assert.ok(blocked, `the live watch saw the new lookup (${JSON.stringify(sentinel.watch.status())})`);
  assert.equal(blocked.lastStatus, "REGEX", "Pi-hole blocked it with TheySpy's entry");
  assert.equal(blocked.clientIp, "172.29.53.14");
  step(`live watch: new lookup of deeper.c2-node.theyspy.test seen, blocked by ${blocked.lastStatus}`);
}

const rolled = await sentinel.rollback(pushed.pushId, "e2e");
assert.equal(rolled.removed, 2);
assert.equal(await snapshot(), before, "Pi-hole's allow and deny lists are exactly as before");
step("rolled back: Pi-hole's lists are exactly as before the push");
// M3: Pi-hole subscribes to TheySpy's compiled spyware list, served over HTTP the way the app serves
// it, and blocks from it through gravity. Removing the subscription leaves Pi-hole's lists as they were.
if (process.env.E2E_LISTS_HOST) {
  const library = createBlocklistLibrary({ db, settings, audit, iocStore });
  library.seed();
  const baselines = createBaselines({ library, sentinel, settings, audit });
  const app = express().use("/lists", publicListRoutes({ library, baselines }));
  const listServer = await new Promise((resolve) => { const s = app.listen(18797, "0.0.0.0", () => resolve(s)); });
  const origin = `http://${process.env.E2E_LISTS_HOST}:18797`;
  // Adblock format, so Pi-hole also blocks each name's subdomains.
  const address = `${origin}/lists/${library.listToken()}/spyware.adblock`;
  const beforeSubscribe = await snapshot();
  const subscribed = await sentinel.subscribe(address, "Spyware & ADINT", "e2e");
  assert.equal(subscribed.entries, 2, "Pi-hole loaded both indicator domains from TheySpy's list");
  step(`subscribed Pi-hole to TheySpy's spyware list: ${subscribed.entries} entries loaded (${subscribed.retrieval})`);
  assert.deepEqual((await sentinel.subscriptions()).map((s) => s.address), [address]);
  const coverageNow = await sentinel.coverage();
  assert.equal(coverageNow.blocked, 2, "both domains now blocked by Pi-hole's gravity");
  assert.equal(coverageNow.fullyBlocked, 2, "and their subdomains (Adblock-style entries)");
  assert.ok(coverageNow.results.every((r) => r.by.includes(address)), "blocked by TheySpy's list");
  step("Pi-hole's own search shows both indicator domains and their subdomains blocked by TheySpy's list");
  await sentinel.unsubscribe(address, "e2e");
  assert.equal(await snapshot(), beforeSubscribe, "Pi-hole's lists are exactly as before the subscription");
  step("removed the subscription: Pi-hole's lists are exactly as before");

  // M3 baselines: Essential for one device only. That device's lookups are blocked through its own
  // Pi-hole group; another device's are not; removing it leaves groups, clients and lists as before.
  const beforeBaseline = await snapshot();
  const applied = await baselines.apply({ baselineId: "essential", client: "172.29.53.15", listsOrigin: origin }, "e2e");
  assert.equal(applied.entries, 2);
  step(`applied Essential to 172.29.53.15 through Pi-hole group "${applied.groupName}" (${applied.entries} entries)`);
  const lookupFrom = (ip, name) => { try { execFileSync("docker", ["run", "--rm", "--network", process.env.E2E_DOCKER_NETWORK, "--ip", ip, "busybox:1.37", "nslookup", "-timeout=2", name, "172.29.53.2"], { stdio: "ignore" }); } catch { /* blocked names can exit non-zero */ } };
  let mine = null;
  let theirs = null;
  for (let attempt = 1; attempt <= 6 && !(mine && theirs); attempt += 1) {
    if (!mine) lookupFrom("172.29.53.15", "x.ads-sync.theyspy.test");
    if (!theirs) lookupFrom("172.29.53.16", "y.ads-sync.theyspy.test");
    await sentinel.watch.poll();
    mine = sentinel.hits().find((h) => h.domain === "x.ads-sync.theyspy.test");
    theirs = sentinel.hits().find((h) => h.domain === "y.ads-sync.theyspy.test");
    if (!(mine && theirs)) await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  assert.ok(mine && theirs, "both lookups were seen");
  assert.equal(mine.lastStatus, "GRAVITY", "the device with the baseline is blocked by it");
  assert.notEqual(theirs.lastStatus, "GRAVITY", "another device is not");
  step(`a subdomain lookup from 172.29.53.15 is blocked (${mine.lastStatus}); the same from 172.29.53.16 is not (${theirs.lastStatus})`);
  await baselines.remove({ client: "172.29.53.15" }, "e2e");
  assert.equal(await snapshot(), beforeBaseline, "groups, clients and lists exactly as before the baseline");
  step("removed the baseline: Pi-hole's groups, clients and lists are exactly as before");
  listServer.close();
}
console.log("E2E OK");
