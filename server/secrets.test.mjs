import { describe, expect, it } from "vitest";
import { createSecretBox } from "./secrets.mjs";
import { testServices } from "./test-helpers.mjs";

describe("secret box", () => {
  it("seals and opens, with a fresh nonce each time", () => {
    const box = createSecretBox(Buffer.alloc(32, 1));
    const a = box.seal("app-password");
    expect(a).toMatch(/^v1:/);
    expect(a).not.toContain("app-password");
    expect(box.seal("app-password")).not.toBe(a);
    expect(box.open(a)).toBe("app-password");
  });

  it("returns null for another key, tampering or junk", () => {
    const sealed = createSecretBox(Buffer.alloc(32, 1)).seal("app-password");
    expect(createSecretBox(Buffer.alloc(32, 2)).open(sealed)).toBeNull();
    const raw = Buffer.from(sealed.slice(3), "base64");
    raw[raw.length - 1] ^= 1;
    expect(createSecretBox(Buffer.alloc(32, 1)).open(`v1:${raw.toString("base64")}`)).toBeNull();
    expect(createSecretBox(Buffer.alloc(32, 1)).open("plain")).toBeNull();
  });

  it("derives keys per purpose from the session secret, so changing it locks stored secrets", () => {
    const one = testServices({ sessionSecret: "one" }).auth;
    const two = testServices({ sessionSecret: "two" }).auth;
    expect(one.deriveKey("settings")).toHaveLength(32);
    expect(one.deriveKey("settings").equals(one.deriveKey("other"))).toBe(false);
    expect(createSecretBox(two.deriveKey("settings")).open(createSecretBox(one.deriveKey("settings")).seal("x"))).toBeNull();
  });
});
