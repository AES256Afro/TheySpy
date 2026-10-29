import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import YAML from "yaml";

const root = fileURLToPath(new URL("..", import.meta.url));
const manifestFile = path.join(root, "boxpilot/theyspy.yaml");
const boxpilot = path.resolve(root, process.env.BOXPILOT_DIR ?? "../BoxPilot");
const schemaFile = path.join(boxpilot, "server/catalog/schema.mjs");

const raw = YAML.parse(readFileSync(manifestFile, "utf8"));

// Checks that need no BoxPilot checkout: the manifest agrees with what this repo ships.
const packageVersion = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")).version;
const local = [];
if (raw.image?.version !== packageVersion) local.push(`image.version is ${raw.image?.version}, package.json is ${packageVersion}`);
if (!String(raw.image?.reference ?? "").includes(`:${packageVersion}`)) local.push(`image.reference does not carry version ${packageVersion}`);
const looks = JSON.parse(readFileSync(path.join(root, "shared/looks.json"), "utf8")).looks.map((look) => look.id);
const lookOptions = raw.env?.find((entry) => entry.name === "TS_LOOK")?.options ?? [];
if (JSON.stringify(lookOptions) !== JSON.stringify(["auto", ...looks])) local.push(`TS_LOOK options ${JSON.stringify(lookOptions)} do not match shared/looks.json`);

if (local.length) {
  console.error(local.join("\n"));
  process.exit(1);
}

if (!existsSync(schemaFile)) {
  console.log(`BoxPilot manifest: local checks pass. Skipped the schema check: no BoxPilot checkout at ${boxpilot} (set BOXPILOT_DIR).`);
  process.exit(0);
}

const { validateManifest } = await import(pathToFileURL(schemaFile).href);
const { errors } = validateManifest(raw);
if (errors.length) {
  console.error(`boxpilot/theyspy.yaml fails BoxPilot's schema:\n- ${errors.join("\n- ")}`);
  process.exit(1);
}
console.log(`BoxPilot manifest: valid against ${path.relative(root, schemaFile)}.`);
