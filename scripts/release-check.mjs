// The release checklist (docs/PLAN.md M11), run by `npm run check` and before a tag publishes:
// one version everywhere, the vendored scanner still verifies, the docs a release promises exist,
// and nothing that looks like a live secret is tracked.
//   node scripts/release-check.mjs            (on a tag, GITHUB_REF_NAME must be v<version>)
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { verifiedScanner } from "../server/agents.mjs";

const problems = [];
const read = (file) => readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
const version = JSON.parse(read("package.json")).version;

const compose = /image: ghcr\.io\/aes256afro\/theyspy:([\w.-]+)/.exec(read("docker-compose.yml"))?.[1];
const manifest = read("boxpilot/theyspy.yaml");
const manifestVersion = /^\s+version: "([^"]+)"/m.exec(manifest)?.[1];
const reference = /^\s+reference: ghcr\.io\/aes256afro\/theyspy:([\w.-]+)/m.exec(manifest)?.[1];
for (const [where, found] of [["docker-compose.yml", compose], ["boxpilot/theyspy.yaml version", manifestVersion], ["boxpilot/theyspy.yaml reference", reference]]) {
  if (found !== version) problems.push(`${where} says ${found ?? "nothing"}, package.json says ${version}`);
}
const tag = process.env.GITHUB_REF_TYPE === "tag" ? process.env.GITHUB_REF_NAME : null;
if (tag && tag !== `v${version}`) problems.push(`the tag is ${tag} but the version is ${version}`);

try { verifiedScanner(); } catch (error) { problems.push(`zero-breach's scanner: ${error.message}`); }

for (const file of ["README.md", "SECURITY.md", "docs/GUIDE.md", "docs/PLAN.md", "LICENSE"]) if (!existsSync(new URL(`../${file}`, import.meta.url))) problems.push(`${file} is missing`);

// Tokens TheySpy and GitHub issue, private keys, and passwords written into example files.
const patterns = /(tsy_[A-Za-z0-9_-]{24,}|tsa_[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{30,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|^TS_[A-Z_]*(?:PASSWORD|SECRET|TOKEN)=\S+)/m;
const tracked = execFileSync("git", ["ls-files"], { encoding: "utf8" }).split("\n").filter((f) => f && !/(^|\/)(node_modules|third_party|docs\/mockups)\/|\.test\.mjs$|package-lock\.json$|\.(png|jpg|ico|woff2?)$/.test(f));
for (const file of tracked) {
  let text;
  try { text = readFileSync(file, "utf8"); } catch { continue; }
  const hit = patterns.exec(text);
  if (hit) problems.push(`${file} contains what looks like a secret (${hit[0].slice(0, 12)}…)`);
}

if (problems.length) {
  console.error(`Release check failed:\n- ${problems.join("\n- ")}`);
  process.exit(1);
}
console.log(`Release check passed for ${version}: versions agree, the scanner verifies, docs present, no secrets tracked.`);
