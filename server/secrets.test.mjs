import { describe, expect, it } from "vitest";
import { createSecretBox } from "./secrets.mjs";
import { testServices } from "./test-helpers.mjs";

describe("secret box", () => {
  it("seals and opens, with a fresh nonce each time", () => {
    const box = createSecretBox(Buffer.alloc(32, 1));
    const a = box.seal("app-password");
    expect(a).toMatch(/^v2:/);
    expect(a).not.toContain("app-password");
    expect(box.seal("app-password")).not.toBe(a);
    expect(box.open(a)).toBe("app-password");
  });

  it("returns null for another key, tampering or junk", () => {
    const sealed = createSecretBox(Buffer.alloc(32, 1)).seal("app-password");
    expect(createSecretBox(Buffer.alloc(32, 2)).open(sealed)).toBeNull();
    const raw = Buffer.from(sealed.slice(3), "base64");
    raw[raw.length - 1] ^= 1;
    expect(createSecretBox(Buffer.alloc(32, 1)).open(`v2:${raw.toString("base64")}`)).toBeNull();
    expect(createSecretBox(Buffer.alloc(32, 1)).open("plain")).toBeNull();
  });

  it("binds a value to what it belongs to, so one row's secret is no use in another", () => {
    const box = createSecretBox(Buffer.alloc(32, 1));
    const sealed = box.seal("agent-key", "agent:7");
    expect(box.open(sealed, "agent:7")).toBe("agent-key");
    // The same key, the same blob, a different row: it does not open.
    expect(box.open(sealed, "agent:8")).toBeNull();
    expect(box.open(sealed)).toBeNull();
  });

  it("still opens what an older TheySpy sealed, which carried no context", () => {
    const key = Buffer.alloc(32, 3);
    // How 1.7.1 and earlier wrote it: the same AES-256-GCM, no associated data, a "v1:" prefix.
    const legacy = `v1:${createSecretBox(key).seal("app-password").slice(3)}`;
    expect(createSecretBox(key).open(legacy, "agent:7")).toBe("app-password");
    expect(createSecretBox(key).open(legacy)).toBe("app-password");
  });

  it("derives keys per purpose from the session secret, so changing it locks stored secrets", () => {
    const one = testServices({ sessionSecret: "one" }).auth;
    const two = testServices({ sessionSecret: "two" }).auth;
    expect(one.deriveKey("settings")).toHaveLength(32);
    expect(one.deriveKey("settings").equals(one.deriveKey("other"))).toBe(false);
    expect(createSecretBox(two.deriveKey("settings")).open(createSecretBox(one.deriveKey("settings")).seal("x"))).toBeNull();
  });
});
