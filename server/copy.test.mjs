import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// M15: a screen gets a title and at most one short technical line. No quotations, no slogans.
const dir = new URL("../src/screens/", import.meta.url);

/** Drops JSX expressions ({...}, nested braces included) so only the prose is measured. */
function prose(text) {
  let out = "";
  let depth = 0;
  for (const ch of text) {
    if (ch === "{") depth += 1;
    else if (ch === "}") depth = Math.max(0, depth - 1);
    else if (depth === 0) out += ch;
  }
  return out;
}

describe("screen copy", () => {
  it("keeps every title paragraph short and free of quotations", () => {
    for (const file of readdirSync(dir).filter((f) => f.endsWith(".tsx"))) {
      const source = readFileSync(new URL(file, dir), "utf8");
      for (const match of source.matchAll(/<h1>[^<]*<\/h1><p className="muted small">([\s\S]*?)<\/p>/g)) {
        const text = prose(match[1]);
        expect(text.length, `${file}: ${text}`).toBeLessThanOrEqual(160);
        expect(text, `${file}: ${text}`).not.toMatch(/[“”"]/);
        expect(text, `${file}: ${text}`).not.toMatch(/—/);
      }
    }
  });
});
