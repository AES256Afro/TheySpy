// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { applyLook, lookById, looks, mergeAppearance, onAccentFor, resolveLook } from "./looks.ts";
import { screens } from "../screens.ts";

describe("looks", () => {
  it("has a look for every mockup style, and every screen names a real look", () => {
    expect(looks.map((look) => look.id)).toEqual(["ops", "light", "pihole", "evidence", "paper", "glass"]);
    for (const screen of screens) expect(looks.some((look) => look.id === screen.look)).toBe(true);
  });

  it("keeps each screen's own look under 'Per screen'", () => {
    expect(resolveLook("auto", "pihole").id).toBe("pihole");
    expect(resolveLook("glass", "pihole").id).toBe("glass");
  });

  it("writes tokens as custom properties, with an accent override and a readable text colour on it", () => {
    const element = document.createElement("div");
    applyLook(element, lookById("light"), { accent: "#123456", density: "compact" });
    expect(element.style.getPropertyValue("--panel")).toBe(lookById("light").tokens.panel);
    expect(element.style.getPropertyValue("--accent")).toBe("#123456");
    expect(element.style.getPropertyValue("--on-accent")).toBe(onAccentFor(lookById("light"), "#123456"));
    expect(element.dataset).toMatchObject({ look: "light", density: "compact" });
  });

  it("lets this browser override the owner's defaults, ignoring junk", () => {
    const merged = mergeAppearance({ look: "glass", name: "NetWatch" }, { look: "paper", name: 42 as unknown as string, bogus: "x" } as never);
    expect(merged).toMatchObject({ look: "paper", name: "NetWatch", home: "overview" });
    expect(mergeAppearance({ look: "neon" }, {}).look).toBe("auto");
  });
});
