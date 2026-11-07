import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import config from "../vite.config.ts";

// M29, B40: the app's CSP is default-src 'self' with no font-src, so a stylesheet that carries a
// font as a data: URL loses that font on every page and logs an error for it. The build must write
// every asset as a file.
const dist = fileURLToPath(new URL("../dist/assets/", import.meta.url));

describe("the built stylesheet", () => {
  it("inlines nothing as a data: URL", () => {
    expect(/** @type {any} */ (config).build.assetsInlineLimit).toBe(0);
  });
  it.skipIf(!existsSync(dist))("carries no font as data: (checked on the dist/ the check just built)", () => {
    for (const file of readdirSync(dist).filter((f) => f.endsWith(".css"))) {
      expect(readFileSync(path.join(dist, file), "utf8")).not.toMatch(/url\(data:/);
    }
  });
});
