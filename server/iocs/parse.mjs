import { isIP } from "node:net";
import { domainToASCII } from "node:url";

// A port of zero-breach's loader (scan/adint_scan/iocs.py), so TheySpy accepts exactly the files
// zero-breach accepts and refuses exactly what it refuses. Format, one indicator per line:
//   indicator <TAB> tier <TAB> confidence [<TAB> source-tag]
// `#` lines are comments; `# as-of: YYYY-MM-DD` is the curation date.

export const tiers = Object.freeze(["cc", "validator", "delivery", "historical", "sample", "vuln-driver", "candiru", "candiru-ip"]);
export const confidences = Object.freeze(["primary", "secondary"]);
export const maxIndicators = 20000;

export class IocError extends Error {}

const sha256Pattern = /^[0-9a-f]{64}$/;
const ipv4Pattern = /^\d{1,3}(\.\d{1,3}){3}$/;
const asofPattern = /^#\s*as-of:\s*(\d{4}-\d{2}-\d{2})\s*$/;
const labelPattern = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
const invisible = ["\u200b", "\u200c", "\u200d", "\u2060"];
// Python's str.strip() whitespace. JavaScript's trim() also removes U+FEFF, which would hide a
// stray byte-order mark that zero-breach deliberately refuses.
const pyWhitespace = "[\\t\\n\\v\\f\\r\\x1c-\\x20\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]";
const pyStripPattern = new RegExp(`^${pyWhitespace}+|${pyWhitespace}+$`, "g");
const pyStrip = (text) => text.replace(pyStripPattern, "");

/** Type from shape: 64 hex digits is a SHA-256, an address is an IP, anything else a domain. */
export function inferType(indicator) {
  const s = pyStrip(indicator).toLowerCase();
  if (sha256Pattern.test(s)) return "sha256";
  if (ipv4Pattern.test(s) || (s.includes(":") && /^[0-9a-f:]+$/.test(s))) return "ip";
  return "domain";
}

/**
 * Why a value is unsafe to match on, or "". A lone "." would match everywhere, 0.0.0.0 matches
 * every blocked lookup, and control characters would end up in reports people forward.
 */
function valueProblem(value, type) {
  if (type === "ip") {
    if (!isIP(value)) return "not a valid IP address";
    if (value === "0.0.0.0" || /^[0:]+$/.test(value) || value.length < 7) return "would match far more than the intended host";
    return "";
  }
  if (type === "domain") {
    if (value.length < 4 || value.length > 253) return "not the length of a hostname";
    const labels = value.split(".");
    if (labels.length < 2) return "a hostname needs at least one dot";
    for (const label of labels) {
      if (label.length < 1 || label.length > 63 || !labelPattern.test(label)) return `label ${JSON.stringify(label.slice(0, 70))} is not a valid hostname label`;
    }
  }
  return "";
}

/**
 * @typedef {{ value: string, type: "domain" | "ip" | "sha256", tier: string, confidence: string, source: string }} Indicator
 * @typedef {{ asof: string | null, indicators: Indicator[] }} IocSet
 */

/**
 * Parses an indicator file. Throws IocError, with the line number, on anything zero-breach would
 * refuse; an empty set is an error too, because it would read as "nothing found".
 * @param {string} text
 * @returns {IocSet}
 */
export function parseIocText(text) {
  /** @type {Map<string, Indicator>} */
  const seen = new Map();
  let asof = null;
  // Windows editors prepend a byte-order mark; without stripping it the first indicator never matches.
  const lines = text.replace(/^\uFEFF/, "").split(/\r\n|\n|\r/);
  if (lines.length && lines[lines.length - 1] === "") lines.pop();
  lines.forEach((raw, index) => {
    const lineno = index + 1;
    const line = pyStrip(raw);
    if (!line || line.startsWith("#")) {
      const match = asofPattern.exec(line);
      if (match) asof = match[1];
      return;
    }
    const parts = line.split("\t").map(pyStrip).filter((part) => part !== "");
    if (parts.length < 3) throw new IocError(`line ${lineno}: expected 3 or 4 tab-separated columns, got ${JSON.stringify(line)}`);
    let value = parts[0].toLowerCase();
    const [, tier, confidence] = parts;
    const source = parts[3] ?? "";
    if (!tiers.includes(tier)) throw new IocError(`line ${lineno}: unknown tier ${JSON.stringify(tier)}`);
    if (!confidences.includes(confidence)) throw new IocError(`line ${lineno}: unknown confidence ${JSON.stringify(confidence)}`);
    if (value.startsWith("\uFEFF") || invisible.some((c) => value.includes(c))) {
      throw new IocError(`line ${lineno}: invisible character in ${JSON.stringify(value)} - the file was probably re-saved by an editor`);
    }
    const type = inferType(value);
    if (type === "domain") {
      value = value.replace(/\.+$/, "");
      if (!/^\p{ASCII}*$/u.test(value)) {
        // Internationalised names are stored as the punycode browsers and DNS actually record.
        const ascii = domainToASCII(value);
        if (!ascii) throw new IocError(`line ${lineno}: ${JSON.stringify(value)} is not a valid domain name`);
        value = ascii;
      }
    }
    const problem = valueProblem(value, type);
    if (problem) throw new IocError(`line ${lineno}: ${JSON.stringify(value.slice(0, 80))}: ${problem}`);
    seen.set(value, { value, type, tier, confidence, source });
    if (seen.size > maxIndicators) throw new IocError(`more than ${maxIndicators.toLocaleString("en")} indicators - refusing what looks like a corrupted or hostile feed`);
  });
  if (!seen.size) throw new IocError("indicator file contains no indicators");
  const indicators = [...seen.values()].sort((a, b) => (a.value < b.value ? -1 : a.value > b.value ? 1 : 0));
  return { asof, indicators };
}

/**
 * Makes an indicator safe to paste into email or chat without a link scanner fetching it, the
 * same way zero-breach's reports do: the last dot of a domain, every dot of an IP.
 * @param {string} value
 */
export function defang(value) {
  const out = value.replace(/http:\/\//g, "hxxp://").replace(/https:\/\//g, "hxxps://");
  if (/[a-z]/i.test(value) && out.includes(".")) {
    const cut = out.lastIndexOf(".");
    return `${out.slice(0, cut)}[.]${out.slice(cut + 1)}`;
  }
  return out.replaceAll(".", "[.]");
}
