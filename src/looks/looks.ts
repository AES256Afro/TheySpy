import looksFile from "../../shared/looks.json";
import { contrast } from "../../shared/contrast.mjs";

export type TokenName = "bg" | "panel" | "panel2" | "line" | "text" | "muted" | "accent" | "accent2" | "onAccent" | "crit" | "high" | "med" | "low" | "ok";
export type FontName = keyof typeof looksFile.fonts;
export type Look = {
  id: string;
  name: string;
  description: string;
  tokens: Record<TokenName, string>;
  fonts: { body: FontName; heading: FontName };
  background?: string;
  blur?: boolean;
  radius?: number;
};

export const looks = looksFile.looks as Look[];
export const glyphs: string[] = looksFile.glyphs;
export const accentPresets: string[] = looksFile.accentPresets;

export type Appearance = {
  look: string; // "auto" or a look id
  name: string;
  tagline: string;
  glyph: string;
  accent: string; // "" = the look's own
  home: string; // a screen id
  density: "comfortable" | "compact";
};

export const appearanceDefaults: Appearance = { look: "auto", name: "TheySpy", tagline: "", glyph: "◉", accent: "", home: "overview", density: "comfortable" };

const cssName: Record<TokenName, string> = {
  bg: "--bg", panel: "--panel", panel2: "--panel-2", line: "--line", text: "--text", muted: "--muted",
  accent: "--accent", accent2: "--accent-2", onAccent: "--on-accent", crit: "--crit", high: "--high", med: "--med", low: "--low", ok: "--ok",
};

export function lookById(id: string): Look {
  return looks.find((look) => look.id === id) ?? looks[0];
}

/** "auto" means each screen keeps the look it was designed in. */
export function resolveLook(preference: string, screenLook: string): Look {
  return lookById(preference === "auto" ? screenLook : preference);
}

/** Text colour for a custom accent: whichever of the look's text or background reads better on it. */
export function onAccentFor(look: Look, accent: string): string {
  return contrast(look.tokens.text, accent) >= contrast(look.tokens.bg, accent) ? look.tokens.text : look.tokens.bg;
}

/** Writes a look onto an element as CSS custom properties; the stylesheet only ever reads these. */
export function applyLook(element: HTMLElement, look: Look, appearance: Pick<Appearance, "accent" | "density">): void {
  const style = element.style;
  for (const [token, name] of Object.entries(cssName) as [TokenName, string][]) style.setProperty(name, look.tokens[token]);
  if (appearance.accent) {
    style.setProperty("--accent", appearance.accent);
    style.setProperty("--on-accent", onAccentFor(look, appearance.accent));
  }
  style.setProperty("--font-body", looksFile.fonts[look.fonts.body]);
  style.setProperty("--font-heading", looksFile.fonts[look.fonts.heading]);
  style.setProperty("--font-mono", looksFile.fonts.mono);
  style.setProperty("--radius", `${look.radius ?? 12}px`);
  style.setProperty("--page-bg", look.background ?? look.tokens.bg);
  style.setProperty("--blur", look.blur ? "18px" : "0px");
  element.dataset.look = look.id;
  element.dataset.density = appearance.density;
}

/** Inline custom properties for a small preview drawn in another look (Appearance page). */
export function lookPreviewStyle(look: Look): Record<string, string> {
  const vars: Record<string, string> = {};
  for (const [token, name] of Object.entries(cssName) as [TokenName, string][]) vars[name] = look.tokens[token];
  vars["--page-bg"] = look.background ?? look.tokens.bg;
  return vars;
}

const localKey = "theyspy.appearance.local";

/** This browser's overrides on top of the owner's defaults. Storage can be missing or refuse. */
export function readLocalAppearance(): Partial<Appearance> {
  try {
    const parsed = JSON.parse(localStorage.getItem(localKey) ?? "{}");
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

export function writeLocalAppearance(value: Partial<Appearance>): void {
  try {
    if (Object.keys(value).length) localStorage.setItem(localKey, JSON.stringify(value));
    else localStorage.removeItem(localKey);
  } catch {
    // Private window or blocked storage: the change still applies until the page reloads.
  }
}

export function mergeAppearance(server: Partial<Appearance>, local: Partial<Appearance>): Appearance {
  const merged = { ...appearanceDefaults, ...server };
  for (const [key, value] of Object.entries(local) as [keyof Appearance, string][]) {
    if (typeof value === "string" && key in appearanceDefaults) (merged as Record<string, string>)[key] = value;
  }
  if (!looks.some((look) => look.id === merged.look) && merged.look !== "auto") merged.look = "auto";
  return merged;
}
