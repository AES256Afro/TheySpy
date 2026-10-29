import path from "node:path";
import { createApp } from "./app.mjs";
import { createAuditLog } from "./audit.mjs";
import { createAuth } from "./auth.mjs";
import { readConfig } from "./config.mjs";
import { createSettingsStore, openDatabase } from "./db.mjs";
import { createIocStore } from "./iocs/store.mjs";
import { createIocUpdater, iocJobKinds } from "./iocs/updater.mjs";
import { createJobRunner, jobKinds } from "./jobs.mjs";
import { createSentinel, piholeJobKinds } from "./pihole/sentinel.mjs";
import { blocklistJobKinds, createBlocklistLibrary } from "./blocklists/library.mjs";
import { baselineJobKinds, createBaselines } from "./blocklists/baselines.mjs";
import { createDiscovery, fleetJobKinds } from "./fleet/discovery.mjs";
import { createFleet } from "./fleet/registry.mjs";
import { createSecretBox } from "./secrets.mjs";
import { productVersion } from "./shared.mjs";

const config = readConfig();
const db = openDatabase(path.join(config.dataDirectory, "theyspy.db"));
const settings = createSettingsStore(db);
const audit = createAuditLog(db);
const auth = createAuth({ db, settings, audit, adminPassword: config.adminPassword, sessionSecret: config.sessionSecret });
const iocStore = createIocStore({ db, audit });
iocStore.seedBundled();
const sentinel = createSentinel({ db, settings, audit, iocStore, secretBox: createSecretBox(auth.deriveKey("settings")), env: config.pihole });
const library = createBlocklistLibrary({ db, settings, audit, iocStore, popular: () => sentinel.topDomains() });
const firstStart = library.seed();
const baselines = createBaselines({ db, library, sentinel, settings, audit });
const fleet = createFleet({ db, audit });
const discovery = createDiscovery({ fleet, sentinel, settings, audit, scanRanges: config.scanRanges });
const jobs = createJobRunner({ db, audit, kinds: { ...jobKinds, ...iocJobKinds({ store: iocStore, updater: createIocUpdater(), settings }), ...piholeJobKinds(sentinel), ...blocklistJobKinds(library), ...baselineJobKinds(baselines), ...fleetJobKinds(discovery) } });

if (auth.generatedPassword) {
  // Shown once. Only its hash is kept; set TS_ADMIN_PASSWORD to choose your own.
  console.log(`\nTheySpy owner password (shown once): ${auth.generatedPassword}\n`);
}

const server = createApp({ config, settings, audit, auth, jobs, iocStore, sentinel, library, baselines, fleet, discovery }).listen(config.port, config.host, () => {
  audit.record("system", "theyspy.started", null, { version: productVersion });
  console.log(`TheySpy ${productVersion} listening on http://${config.host}:${config.port} (data in ${config.dataDirectory})`);
});

// Look for a newer indicator set once a day (first check an hour after start). A found update
// waits on the Indicators screen; nothing is applied without the owner.
const day = 24 * 60 * 60 * 1000;
const scheduleCheck = () => { if (config.iocAutoCheck) jobs.enqueue("ioc.check", { actor: "system" }); };
const firstCheck = setTimeout(scheduleCheck, 60 * 60 * 1000);
const dailyCheck = setInterval(scheduleCheck, day);
firstCheck.unref();
dailyCheck.unref();

// Blocklists: fetch the starter lists right away on a new install, then update every 6 hours and
// look for new lists once a day. Discovery only adds candidates; nothing is enabled by itself.
if (config.blocklistsAuto) {
  if (firstStart) jobs.enqueue("blocklists.update", { actor: "system" });
  const listUpdates = setInterval(() => jobs.enqueue("blocklists.update", { actor: "system" }), 6 * 60 * 60 * 1000);
  const listDiscovery = setInterval(() => jobs.enqueue("blocklists.discover", { actor: "system" }), day);
  const firstDiscovery = setTimeout(() => jobs.enqueue("blocklists.discover", { actor: "system" }), 2 * 60 * 1000);
  for (const t of [listUpdates, listDiscovery, firstDiscovery]) t.unref();
}

// The library's per-category counts take a few seconds with multi-million-name lists; work them
// out shortly after start so the first visit to the screen is quick.
setTimeout(() => library.counts(), 5000).unref();

// Fleet: read Pi-hole's network table every 5 minutes (once Pi-hole is connected), and sweep the
// networks the owner chose every 30 minutes. Nothing is swept until the owner picks networks. These
// run quietly, outside the job log (which would fill with them); new devices are still audited.
if (config.fleetAuto) {
  const quietly = (name, work) => {
    let running = false;
    return () => {
      if (running) return;
      running = true;
      work().catch((error) => settings.set(`fleet_last_${name}_error`, { at: new Date().toISOString(), error: error.message })).finally(() => { running = false; });
    };
  };
  const sync = quietly("sync", async () => { if (sentinel.effective().mode) await discovery.sync(); });
  const sweep = quietly("sweep", async () => { if (discovery.targets().length) await discovery.sweep(); });
  const timers = [setInterval(sync, 5 * 60 * 1000), setInterval(sweep, 30 * 60 * 1000), setTimeout(sync, 20 * 1000)];
  for (const t of timers) t.unref();
}

// Watch Pi-hole's new queries every 30 seconds once it is connected (the loop idles until then).
sentinel.watch.start();

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => {
    sentinel.watch.stop();
    server.close(() => {
      db.close();
      process.exit(0);
    });
  });
}
