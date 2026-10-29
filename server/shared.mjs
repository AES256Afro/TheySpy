import { readFileSync } from "node:fs";

/** The look and screen lists the UI also reads, so the server validates against the same ids. */
function readShared(name) {
  return JSON.parse(readFileSync(new URL(`../shared/${name}`, import.meta.url), "utf8"));
}

/** @type {{ looks: { id: string, name: string }[], glyphs: string[], accentPresets: string[] }} */
export const looksFile = readShared("looks.json");
/** @type {{ screens: { id: string, path: string, label: string, milestone: string }[] }} */
export const screensFile = readShared("screens.json");

export const lookIds = Object.freeze(["auto", ...looksFile.looks.map((look) => look.id)]);
export const screenIds = Object.freeze(screensFile.screens.map((screen) => screen.id));
export const productVersion = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
