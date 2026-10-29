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
const jobs = createJobRunner({ db, audit, kinds: { ...jobKinds, ...iocJobKinds({ store: iocStore, updater: createIocUpdater(), settings }), ...piholeJobKinds(sentinel), ...blocklistJobKinds(library) } });

if (auth.generatedPassword) {
  // Shown once. Only its hash is kept; set TS_ADMIN_PASSWORD to choose your own.
  console.log(`\nTheySpy owner password (shown once): ${auth.generatedPassword}\n`);
}

const server = createApp({ config, settings, audit, auth, jobs, iocStore, sentinel, library }).listen(config.port, config.host, () => {
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
