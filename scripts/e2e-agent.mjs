// Driven by e2e-agent.sh: enroll a lab container, let it scan and report, check the evidence.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

const base = `http://127.0.0.1:${process.env.PORT}`;
const step = (text) => console.log(`- ${text}`);
let cookie = "";
/** @returns {Promise<any>} */
async function api(method, path, body) {
  const response = await fetch(base + path, { method, headers: { "content-type": "application/json", "x-theyspy": "1", ...(cookie ? { cookie } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const set = response.headers.get("set-cookie");
  if (set) cookie = set.split(";")[0];
  if (!response.ok) throw new Error(`${method} ${path}: ${response.status} ${await response.text()}`);
  return response.json();
}

await api("POST", "/api/login", { password: process.env.PASSWORD });
const { token } = await api("POST", "/api/evidence/agents/enroll", { label: "lab VM" });
step("created a one-time enrollment token");
const seed = `import sqlite3, os
p = os.path.expanduser("~/.config/google-chrome/Default"); os.makedirs(p, exist_ok=True)
db = sqlite3.connect(os.path.join(p, "History"))
db.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER)")
db.execute("INSERT INTO urls (url, title, visit_count, typed_count, last_visit_time, hidden) VALUES ('https://cdn.fearevolve.com/ad.js', 'ad', 1, 0, 13370000000000000, 0)")
db.commit()`;
const server = `http://host.docker.internal:${process.env.PORT}`;
const out = execFileSync("docker", ["run", "--rm", "-e", "SEED", "--add-host", "host.docker.internal:host-gateway", "python:3.12-slim", "sh", "-c",
  `python3 -c "$SEED" && python3 -c "import urllib.request; open('/tmp/agent.py','wb').write(urllib.request.urlopen('${server}/agent/theyspy-agent.py').read())" && python3 /tmp/agent.py enroll ${server} ${token} && python3 /tmp/agent.py run --quick; echo "agent exit $?"`],
  { env: { ...process.env, SEED: seed }, encoding: "utf8" }).replace(/^/gm, "    ");
process.stdout.write(out);
assert.match(out, /agent exit 2/, "the agent reports an indicator hit");

const evidence = await api("GET", "/api/evidence");
const contacted = evidence.findings.filter((f) => f.kind === "contacted");
const gaps = evidence.findings.filter((f) => f.kind === "gap");
assert.deepEqual(contacted.map((f) => f.indicator), ["fearevolve[.]com"]);
assert.match(contacted[0].location, /google-chrome\/Default\/History$/);
assert.ok(gaps.some((g) => /--quick/.test(g.detail)), "the skipped fingerprinting is a gap, not clean");
assert.equal(evidence.agents[0].verdict.status, "INDICATORS_FOUND");
step(`TheySpy shows a contacted finding for ${contacted[0].indicator} in ${contacted[0].location} and ${gaps.length} gaps`);
console.log("E2E OK");
