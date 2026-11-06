import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { verifiedScanner } from "./agents.mjs";

// agent/theyspy-agent.py is what runs on other people's computers, so what it refuses matters as
// much as what it does. The hash check needs no Python; the behaviour is driven through the real
// file when a python3 is about to hand, which CI and the image both have.

const script = fileURLToPath(new URL("../agent/theyspy-agent.py", import.meta.url));
const source = readFileSync(script, "utf8");
const pinned = (name) => new RegExp(`^${name} = "([^"]+)"`, "m").exec(source)?.[1];

const python = (() => {
  try { execFileSync("python3", ["-V"], { stdio: "ignore" }); return "python3"; } catch { return null; }
})();

/** Runs a snippet with the agent imported as `m`, isolated from the project's own files. */
function inAgent(body) {
  const code = [
    "import importlib.util, json, sys",
    `spec = importlib.util.spec_from_file_location("agent", ${JSON.stringify(script)})`,
    "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
    body,
  ].join("\n");
  return execFileSync(python, ["-I", "-c", code], { encoding: "utf8" }).trim();
}

describe("the agent script", () => {
  it("pins zero-breach's released hash, the same one TheySpy verifies from the signature", () => {
    const scanner = verifiedScanner();
    // If these drift, the agent refuses the scanner its own TheySpy serves - so they are one test.
    expect(pinned("SCANNER_SHA256")).toBe(scanner.sha256);
    expect(pinned("SCANNER_VERSION")).toBe(scanner.version);
  });

  it.skipIf(!python)("refuses a scanner that is not the pinned one, whatever the server says about it", () => {
    const out = inAgent([
      // A server that sends a different program and a matching hash of its own: the old check
      // compared the two and was satisfied.
      'm.request = lambda url, data=None, headers=None, timeout=120: (',
      '    json.dumps({"version": m.SCANNER_VERSION, "sha256": "0"*64, "iocsSha256": "0"*64}).encode()',
      '    if url.endswith("/api/agent/scanner") else b"print(1)")',
      'code, report, error = m.scan({"server": "https://x", "agentId": 1, "secret": "k"}, False)',
      'print(json.dumps([code, report, error]))',
    ].join("\n"));
    const [code, report, error] = JSON.parse(out);
    expect([code, report]).toEqual([1, null]);
    expect(error).toContain("not zero-breach 0.1.8");
  });

  it.skipIf(!python)("refuses a server whose zero-breach is newer than it knows, and says to update", () => {
    const out = inAgent([
      'm.request = lambda url, data=None, headers=None, timeout=120: (',
      '    json.dumps({"version": "0.2.0", "sha256": "0"*64, "iocsSha256": "0"*64}).encode()',
      '    if url.endswith("/api/agent/scanner") else b"print(1)")',
      'code, report, error = m.scan({"server": "https://x", "agentId": 1, "secret": "k"}, False)',
      'print(json.dumps([code, report, error]))',
    ].join("\n"));
    const [, , error] = JSON.parse(out);
    expect(error).toContain("offers zero-breach 0.2.0");
    expect(error).toContain("update the agent");
  });

  it.skipIf(!python)("refuses a plain-HTTP TheySpy unless told to accept one", () => {
    const out = inAgent([
      'try:',
      '    m.check_server("http://theyspy.lan:8797"); print("allowed")',
      'except SystemExit as e:',
      '    print("refused" if "Refusing to use" in str(e) and "signing key" in str(e) else "wrong message")',
      'm.check_server("http://theyspy.lan:8797", insecure=True)',
      'm.check_server("https://theyspy.lan:8797")',
      'print("https and --insecure both fine")',
    ].join("\n"));
    expect(out.split("\n")).toEqual(["refused", "https and --insecure both fine"]);
  });

  it.skipIf(!python)("turns a failure before the scan into a gap it can report, not a traceback", () => {
    const out = inAgent([
      'def boom(*a, **k): raise OSError("connection refused")',
      'm.request = boom',
      'code, report, error = m.scan({"server": "https://x", "agentId": 1, "secret": "k"}, False)',
      'print(json.dumps([code, report, error]))',
    ].join("\n"));
    const [code, report, error] = JSON.parse(out);
    // ingest() turns exactly this into "The scan could not run: …. Nothing on this device was checked."
    expect([code, report]).toEqual([1, null]);
    expect(error).toBe("connection refused");
  });

  it.skipIf(!python)("cleans up after a scanner that left a directory behind", () => {
    const out = inAgent([
      'import os, tempfile',
      'made = []',
      'real = tempfile.mkdtemp',
      'def mkdtemp(**kw):',
      '    d = real(**kw); made.append(d)',
      '    os.makedirs(os.path.join(d, "leftover", "deep"))',
      '    return d',
      'm.tempfile.mkdtemp = mkdtemp',
      'm.request = lambda *a, **k: (_ for _ in ()).throw(OSError("stop here"))',
      'code, report, error = m.scan({"server": "https://x", "agentId": 1, "secret": "k"}, False)',
      'print(json.dumps([error, [os.path.exists(d) for d in made]]))',
    ].join("\n"));
    const [error, left] = JSON.parse(out);
    // The real error survives, and nothing is left in the temp directory.
    expect(error).toBe("stop here");
    expect(left).toEqual([]);
  });
});
