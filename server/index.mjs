import path from "node:path";
import { createApp } from "./app.mjs";
import { createAuditLog } from "./audit.mjs";
import { createAuth } from "./auth.mjs";
import { readConfig } from "./config.mjs";
import { createSettingsStore, openDatabase } from "./db.mjs";
import { createIocStore } from "./iocs/store.mjs";
import { createIocUpdater, iocJobKinds } from "./iocs/updater.mjs";
import { createJobRunner, jobKinds } from "./jobs.mjs";
import { productVersion } from "./shared.mjs";

const config = readConfig();
const db = openDatabase(path.join(config.dataDirectory, "theyspy.db"));
const settings = createSettingsStore(db);
const audit = createAuditLog(db);
const auth = createAuth({ db, settings, audit, adminPassword: config.adminPassword, sessionSecret: config.sessionSecret });
const iocStore = createIocStore({ db, audit });
iocStore.seedBundled();
const jobs = createJobRunner({ db, audit, kinds: { ...jobKinds, ...iocJobKinds({ store: iocStore, updater: createIocUpdater(), settings }) } });

if (auth.generatedPassword) {
  // Shown once. Only its hash is kept; set TS_ADMIN_PASSWORD to choose your own.
  console.log(`\nTheySpy owner password (shown once): ${auth.generatedPassword}\n`);
}

const server = createApp({ config, settings, audit, auth, jobs, iocStore }).listen(config.port, config.host, () => {
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

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => {
    server.close(() => {
      db.close();
      process.exit(0);
    });
  });
}
