import path from "node:path";
import { createApp } from "./app.mjs";
import { createAuditLog } from "./audit.mjs";
import { createAuth } from "./auth.mjs";
import { readConfig } from "./config.mjs";
import { createSettingsStore, openDatabase } from "./db.mjs";
import { createJobRunner } from "./jobs.mjs";
import { productVersion } from "./shared.mjs";

const config = readConfig();
const db = openDatabase(path.join(config.dataDirectory, "theyspy.db"));
const settings = createSettingsStore(db);
const audit = createAuditLog(db);
const auth = createAuth({ db, settings, audit, adminPassword: config.adminPassword, sessionSecret: config.sessionSecret });
const jobs = createJobRunner({ db, audit });

if (auth.generatedPassword) {
  // Shown once. Only its hash is kept; set TS_ADMIN_PASSWORD to choose your own.
  console.log(`\nTheySpy owner password (shown once): ${auth.generatedPassword}\n`);
}

const server = createApp({ config, settings, audit, auth, jobs }).listen(config.port, config.host, () => {
  audit.record("system", "theyspy.started", null, { version: productVersion });
  console.log(`TheySpy ${productVersion} listening on http://${config.host}:${config.port} (data in ${config.dataDirectory})`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => {
    server.close(() => {
      db.close();
      process.exit(0);
    });
  });
}
