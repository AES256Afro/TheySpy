import { describe, expect, it } from "vitest";
import { appearanceDefaults, effectiveAppearance, validateAppearance } from "./appearance.mjs";

describe("appearance", () => {
  it("layers defaults, then environment, then what the owner saved", () => {
    expect(effectiveAppearance({ env: {}, stored: undefined })).toEqual(appearanceDefaults);
    const env = { look: "glass", name: "NetWatch", tagline: undefined, accent: undefined };
    expect(effectiveAppearance({ env, stored: undefined })).toMatchObject({ look: "glass", name: "NetWatch" });
    expect(effectiveAppearance({ env, stored: { look: "paper" } })).toMatchObject({ look: "paper", name: "NetWatch" });
  });

  it("ignores invalid environment values instead of failing to start", () => {
    expect(effectiveAppearance({ env: { look: "neon" }, stored: undefined }).look).toBe("auto");
  });

  it("validates each field", () => {
    expect(validateAppearance({ look: "evidence", accent: "#AABBCC", home: "pihole", density: "compact" })).toEqual({
      value: { look: "evidence", accent: "#aabbcc", home: "pihole", density: "compact" },
      errors: [],
    });
    const { errors } = validateAppearance({ look: "neon", accent: "red", home: "nowhere", name: "", tagline: "<script>", colour: "x", glyph: "toolong" });
    expect(errors).toHaveLength(7);
    expect(validateAppearance([]).errors).toEqual(["appearance must be an object"]);
  });
});
