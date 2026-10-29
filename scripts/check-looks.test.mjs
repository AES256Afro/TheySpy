import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { colourLiterals, contrastProblems } from "./check-looks.mjs";

describe("look checks", () => {
  it("passes for the shipped looks and the shipped UI", () => {
    expect(contrastProblems()).toEqual([]);
    expect(colourLiterals()).toEqual([]);
  });

  it("catches an unreadable look", () => {
    const bad = { looks: [{ id: "grey", tokens: { bg: "#777777", panel: "#777777", panel2: "#777777", text: "#888888", muted: "#888888", accent: "#888888", onAccent: "#777777", crit: "#888888", high: "#888888", med: "#888888", low: "#888888", ok: "#888888" } }] };
    expect(contrastProblems(bad).length).toBeGreaterThan(10);
  });

  it("catches a colour written straight into the UI", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "theyspy-src-"));
    writeFileSync(path.join(dir, "x.css"), ".a { color: #ff0000; }\n.b { background: rgba(0, 0, 0, .5); }\n/* #abcdef in a comment is fine */\n");
    expect(colourLiterals(dir)).toHaveLength(2);
  });
});
