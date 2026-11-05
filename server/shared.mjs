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

/**
 * How much of one outside answer TheySpy will hold in memory. Feeds are megabytes (NVD's pages,
 * CISA's catalogue, the IEEE registry); nothing TheySpy reads is anywhere near this. The point is
 * that a service which answers with a gigabyte — because it broke, or because someone took it
 * over — fails that one read instead of the container.
 */
export const maxResponseBytes = 32 * 1024 * 1024;

/** @param {Response} response */
const nameOf = (response) => {
  try { return new URL(response.url).hostname; } catch { return "the service"; }
};

/**
 * A response body read with a ceiling. `Content-Length` is checked first when the server declares
 * one, and then the bytes are counted as they arrive, because a declared length is not a promise.
 * @param {Response} response
 * @param {{ maxBytes?: number, what?: string }} [options]
 * @returns {Promise<Buffer>}
 */
export async function readCappedBytes(response, { maxBytes = maxResponseBytes, what } = {}) {
  const label = what ?? nameOf(response);
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (declared > maxBytes) throw new Error(`${label} says its answer is ${declared} bytes; TheySpy reads at most ${maxBytes}`);
  const reader = response.body?.getReader();
  if (!reader) return Buffer.alloc(0);
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel();
      throw new Error(`${label} answered more than ${maxBytes} bytes; TheySpy stopped reading it`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

/**
 * The same, as text.
 * @param {Response} response
 * @param {{ maxBytes?: number, what?: string }} [options]
 * @returns {Promise<string>}
 */
export async function readCapped(response, options = {}) {
  return (await readCappedBytes(response, options)).toString("utf8");
}

/**
 * The same, parsed as JSON. The error says which service was unreadable rather than quoting its
 * body back, which may be an HTML error page or something worse.
 * @param {Response} response
 * @param {{ maxBytes?: number, what?: string }} [options]
 * @returns {Promise<any>}
 */
export async function readCappedJson(response, options = {}) {
  const text = await readCapped(response, options);
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${options.what ?? nameOf(response)} did not answer JSON`);
  }
}
