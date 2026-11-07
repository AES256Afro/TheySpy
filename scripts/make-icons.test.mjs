import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { iconPng } from "./make-icons.mjs";

// Installable on a phone (docs/PLAN.md M36): the shell links a web manifest and an Apple touch icon,
// the manifest opens on This device, and each icon it names is a PNG of the size it says.
const root = new URL("../", import.meta.url);
const read = (file) => readFileSync(new URL(file, root));
const pngSize = (bytes) => {
  expect(bytes.subarray(0, 8)).toEqual(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  return `${bytes.readUInt32BE(16)}x${bytes.readUInt32BE(20)}`;
};

describe("the web manifest and its icons (M36)", () => {
  it("is linked from the shell, starts on This device, and names icons that exist at their sizes", () => {
    const html = read("index.html").toString();
    expect(html).toContain('<link rel="manifest" href="/manifest.webmanifest" />');
    expect(html).toContain('<link rel="apple-touch-icon" href="/apple-touch-icon.png" />');
    expect(html).toContain('<meta name="theme-color" content="#0b1020" />');
    const manifest = JSON.parse(read("public/manifest.webmanifest").toString());
    expect(manifest).toMatchObject({ name: "TheySpy", start_url: "/this-device", display: "standalone", scope: "/" });
    expect(read("shared/screens.json").toString()).toContain('"path": "/this-device"');
    for (const icon of manifest.icons.filter((i) => i.type === "image/png")) expect(pngSize(read(`public${icon.src}`))).toBe(icon.sizes);
    expect(pngSize(read("public/apple-touch-icon.png"))).toBe("180x180");
  });

  it("draws the icons the script draws, so a regenerated icon matches the committed one", () => {
    expect(read("public/icon-192.png").equals(iconPng(192))).toBe(true);
    expect(read("public/apple-touch-icon.png").equals(iconPng(180))).toBe(true);
  });
});
