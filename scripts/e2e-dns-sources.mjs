// Driven by e2e-dns-sources.sh: a real AdGuard Home and a real Technitium DNS have answered lookups
// from fixed clients. Through TheySpy's own sentinel, each must give the same answers Pi-hole does:
// every indicator lookup found with its client (subdomains included, lookalikes not), the blocked
// one marked blocked, the live watch seeing new lookups, and one domain's and one device's lookups.
import assert from "node:assert/strict";
import { createAuditLog } from "../server/audit.mjs";
import { createSettingsStore, openDatabase } from "../server/db.mjs";
import { createIocStore } from "../server/iocs/store.mjs";
import { createMatcher } from "../server/pihole/match.mjs";
import { createSentinel } from "../server/pihole/sentinel.mjs";
import { createSecretBox } from "../server/secrets.mjs";

const step = (text) => console.log(`- ${text}`);
const testSet = "# as-of: 2026-10-30\nads-sync.theyspy.example\tdelivery\tprimary\te2e\nc2-node.theyspy.example\tcc\tprimary\te2e\n";
const sentAt = Number(process.env.E2E_SENT_AT) - 5;

const sources = [
  { label: "AdGuard Home", config: { mode: "adguard", url: process.env.ADGUARD_URL, username: "theyspy", password: process.env.E2E_PASSWORD } },
  { label: "Technitium", config: { mode: "technitium", url: process.env.TECHNITIUM_URL, password: process.env.E2E_TOKEN } },
];

for (const { label, config } of sources) {
  const db = openDatabase(":memory:");
  const settings = createSettingsStore(db);
  const audit = createAuditLog(db);
  const iocStore = createIocStore({ db, audit });
  iocStore.seedBundled();
  iocStore.apply(iocStore.recordCandidate({ raw: testSet, provenance: { track: "main", note: "e2e" }, actor: "e2e" }).id, "e2e");
  const sentinel = createSentinel({ db, settings, audit, iocStore, secretBox: createSecretBox(Buffer.alloc(32, 7)) });
  sentinel.configure(config, "e2e");
  assert.equal(sentinel.publicConfig().canWrite, false, `${label} is read-only`);

  const tested = await sentinel.test();
  step(`${label}: connected (${JSON.stringify(tested).slice(0, 120)})`);

  await sentinel.hunt({ windowDays: 1, actor: "e2e" });
  const hits = sentinel.hits();
  const found = hits.map((h) => `${h.domain} <- ${h.clientIp}`).sort();
  assert.deepEqual(found, [
    "ads-sync.theyspy.example <- 172.29.54.10",
    "c2-node.theyspy.example <- 172.29.54.11",
    "deep.ads-sync.theyspy.example <- 172.29.54.10",
  ], `${label}: every indicator lookup found with its client; the lookalike notads-sync is not`);
  const c2 = hits.find((h) => h.domain === "c2-node.theyspy.example");
  // nslookup asks for A and AAAA, so each lookup is at least one entry.
  assert.ok(c2.lookups >= 2, `${label}: both c2-node lookups counted`);
  assert.equal(c2.blocked, c2.lookups, `${label}: the blocked indicator is marked blocked`);
  assert.equal(hits.find((h) => h.domain === "ads-sync.theyspy.example").blocked, 0, `${label}: an allowed lookup is not marked blocked`);
  step(`${label}: hunt found ${hits.length} indicator lookups, c2-node blocked ${c2.blocked} of ${c2.lookups}, lookalike ignored`);

  const source = sentinel.source();
  const matcher = createMatcher(iocStore.activeSet());
  const watched = [];
  const recent = await source.recent(matcher, sentAt, (q) => { watched.push(q); });
  assert.ok(watched.some((q) => q.domain === "unrelated.theyspy.example"), `${label}: the live watch sees every new lookup`);
  assert.equal(recent.hits.length >= 4, true, `${label}: the live watch finds the indicator lookups`);

  const lookups = await source.lookupsOf("ads-sync.theyspy.example", { from: sentAt, until: Date.now() / 1000 + 60 });
  assert.deepEqual([...new Set(lookups.map((q) => q.domain))].sort(), ["ads-sync.theyspy.example", "deep.ads-sync.theyspy.example"], `${label}: a domain's lookups include its subdomains and not lookalikes`);
  const device = await source.domainCounts({ client: "172.29.54.12", from: sentAt, until: Date.now() / 1000 + 60 });
  assert.deepEqual(device.rows.map((r) => r.domain), ["unrelated.theyspy.example"], `${label}: one device's lookups`);
  step(`${label}: live watch saw ${watched.length} lookups; domain and device lookups match`);
}
