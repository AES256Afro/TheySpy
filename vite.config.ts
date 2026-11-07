import { readFileSync } from "node:fs";
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

const { version } = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8")) as { version: string };
const serverPort = process.env.TS_PORT ?? "8797";

export default defineConfig({
  plugins: [react()],
  define: { __THEYSPY_VERSION__: JSON.stringify(version) },
  // `npm run dev` serves the UI on 5173 and hands the API to `npm run dev:server`.
  server: { port: 5173, proxy: { "/api": `http://127.0.0.1:${serverPort}`, "/healthz": `http://127.0.0.1:${serverPort}` } },
  // Nothing inlined as a data: URL: the CSP is default-src 'self' with no font-src, so an inlined
  // font subset (JetBrains Mono's Cyrillic-extended, under 4 KB) was refused on every page (B40).
  build: { outDir: "dist", sourcemap: false, assetsInlineLimit: 0 },
  test: {
    globals: true,
    environment: "node",
    include: ["server/**/*.test.mjs", "scripts/**/*.test.mjs", "src/**/*.test.{ts,tsx}"],
  },
});
