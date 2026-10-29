// WCAG 2.x contrast for the look tokens. Shared by scripts/check-looks.mjs (CI) and the
// Appearance page (warns when a custom accent is hard to read).

/** @param {string} value "#rgb", "#rrggbb" or "rgba(r, g, b, a)" @returns {[number, number, number, number]} */
export function parseColor(value) {
  const text = value.trim().toLowerCase();
  let match = /^#([0-9a-f]{3})$/.exec(text);
  if (match) return [...match[1]].map((c) => parseInt(c + c, 16)).concat(1);
  match = /^#([0-9a-f]{6})$/.exec(text);
  if (match) return [0, 2, 4].map((i) => parseInt(match[1].slice(i, i + 2), 16)).concat(1);
  match = /^rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*(?:,\s*([\d.]+)\s*)?\)$/.exec(text);
  if (match) return [Number(match[1]), Number(match[2]), Number(match[3]), match[4] === undefined ? 1 : Number(match[4])];
  throw new Error(`Not a colour: ${value}`);
}

/** Paints a possibly translucent colour over an opaque one. */
export function over(top, bottom) {
  const [r, g, b, a] = parseColor(top);
  const [r2, g2, b2] = parseColor(bottom);
  const mixed = [r * a + r2 * (1 - a), g * a + g2 * (1 - a), b * a + b2 * (1 - a)].map((v) => Math.round(v));
  return `rgba(${mixed.join(", ")}, 1)`;
}

/** Like CSS color-mix(in srgb, a pct%, b). */
export function mix(a, pct, b) {
  const [r, g, bl] = parseColor(a);
  const [r2, g2, b2] = parseColor(b);
  const p = pct / 100;
  return `rgba(${[r * p + r2 * (1 - p), g * p + g2 * (1 - p), bl * p + b2 * (1 - p)].map((v) => Math.round(v)).join(", ")}, 1)`;
}

function luminance(color) {
  const [r, g, b] = parseColor(color).map((v) => v / 255);
  const lin = (c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

/** @returns {number} contrast ratio, 1 to 21 */
export function contrast(a, b) {
  const [l1, l2] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (l1 + 0.05) / (l2 + 0.05);
}

/**
 * Every pairing the UI draws, with the ratio it must reach. Translucent panels (Glass) are checked
 * over the plain background and over each colour in the page gradient.
 * @param {{ id: string, tokens: Record<string, string>, background?: string }} look
 * @returns {{ pair: string, ratio: number, needs: number }[]}
 */
export function lookContrastFailures(look) {
  const t = look.tokens;
  const backdrops = [t.bg, ...((look.background ?? "").match(/#[0-9a-f]{6}\b/gi) ?? [])];
  const failures = [];
  for (const backdrop of backdrops) {
    const surfaces = { bg: backdrop, panel: over(t.panel, backdrop), panel2: over(t.panel2, over(t.panel, backdrop)) };
    const check = (name, fg, bg, needs) => {
      const ratio = contrast(fg, bg);
      if (ratio < needs) failures.push({ pair: `${name}${backdrops.length > 1 ? ` (over ${backdrop})` : ""}`, ratio: Math.round(ratio * 100) / 100, needs });
    };
    for (const [surface, color] of Object.entries(surfaces)) {
      check(`text on ${surface}`, t.text, color, 4.5);
      check(`muted on ${surface}`, t.muted, color, 4.5);
    }
    check("accent on panel", t.accent, surfaces.panel, 4.5);
    check("onAccent on accent", t.onAccent, t.accent, 4.5);
    for (const severity of ["crit", "high", "med", "low", "ok"]) {
      check(`${severity} on panel`, t[severity], surfaces.panel, 4.5);
      check(`${severity} badge`, t[severity], mix(t[severity], 18, surfaces.panel), 4.5);
    }
  }
  return failures;
}
