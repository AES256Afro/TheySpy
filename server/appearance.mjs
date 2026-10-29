import { looksFile, lookIds, screenIds } from "./shared.mjs";

/** @typedef {{ look: string, name: string, tagline: string, glyph: string, accent: string, home: string, density: string }} Appearance */

/** @type {Readonly<Appearance>} */
export const appearanceDefaults = Object.freeze({
  look: "auto",
  name: "TheySpy",
  tagline: "",
  glyph: "◉",
  accent: "",
  home: "overview",
  density: "comfortable",
});

const limits = { name: 28, tagline: 40, glyph: 4 };

/**
 * Checks an appearance object field by field. Unknown fields are refused so a typo is not saved
 * silently; missing fields are left alone.
 * @param {unknown} input
 * @returns {{ value: Partial<Appearance>, errors: string[] }}
 */
export function validateAppearance(input) {
  const errors = [];
  /** @type {Partial<Appearance>} */
  const value = {};
  if (!input || typeof input !== "object" || Array.isArray(input)) return { value, errors: ["appearance must be an object"] };
  for (const [key, raw] of Object.entries(input)) {
    if (!Object.hasOwn(appearanceDefaults, key)) { errors.push(`${key} is not an appearance setting`); continue; }
    if (typeof raw !== "string") { errors.push(`${key} must be text`); continue; }
    const text = raw.trim();
    switch (key) {
      case "look": if (!lookIds.includes(text)) errors.push(`look must be one of ${lookIds.join(", ")}`); else value.look = text; break;
      case "home": if (!screenIds.includes(text)) errors.push(`home must be one of ${screenIds.join(", ")}`); else value.home = text; break;
      case "density": if (text !== "comfortable" && text !== "compact") errors.push("density must be comfortable or compact"); else value.density = text; break;
      case "accent": if (text && !/^#[0-9a-f]{6}$/i.test(text)) errors.push("accent must be empty or a colour like #39c6ff"); else value.accent = text.toLowerCase(); break;
      case "glyph":
        if (!text || [...text].length > limits.glyph) errors.push(`glyph must be 1 to ${limits.glyph} characters`);
        else value.glyph = text;
        break;
      default:
        if (key === "name" && !text) errors.push("name cannot be empty");
        // eslint-disable-next-line no-control-regex -- rejecting control characters is the point
        else if (/[\u0000-\u001f<>]/.test(text)) errors.push(`${key} cannot contain < > or control characters`);
        else if (text.length > limits[key]) errors.push(`${key} must be at most ${limits[key]} characters`);
        else value[key] = text;
    }
  }
  return { value, errors };
}

/**
 * The appearance everyone gets unless their browser overrides it: built-in defaults, then the
 * TS_* environment (BoxPilot's Config), then what the owner saved in Settings → Appearance.
 * @param {{ env: Record<string, string | undefined>, stored: unknown }} sources
 */
export function effectiveAppearance({ env, stored }) {
  const fromEnv = validateAppearance(Object.fromEntries(Object.entries(env).filter(([, v]) => v !== undefined))).value;
  const fromStore = stored ? validateAppearance(stored).value : {};
  return { ...appearanceDefaults, ...fromEnv, ...fromStore };
}

export const appearanceOptions = Object.freeze({
  looks: lookIds,
  screens: screenIds,
  glyphs: looksFile.glyphs,
  accentPresets: looksFile.accentPresets,
});
