import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseChecksums, readPublicKey, SignatureError, verifyDetached } from "./openpgp.mjs";

const vendored = (path) => readFileSync(new URL(`../../third_party/zero-breach/${path}`, import.meta.url));
const release = "release-signatures/v0.1.8/";
const key = readPublicKey(vendored(`${release}archivegenocide-signing-key.asc`).toString("utf8"));
const manifest = vendored(`${release}SHA256SUMS.txt`);
const signature = vendored(`${release}SHA256SUMS.txt.asc`).toString("utf8");

describe("OpenPGP verification", () => {
  it("reads the publisher's key with the fingerprint SIGNING.md publishes", () => {
    expect(key.fingerprint).toBe("C24EC92B12D6670A2516065F9B4D575499AFA53C");
  });

  it("accepts zero-breach's signed v0.1.8 manifest", () => {
    const result = verifyDetached(manifest, signature, key);
    expect(result.issuer).toBe(key.fingerprint);
    expect(result.signedAt.getUTCFullYear()).toBe(2026);
  });

  it("finds the vendored indicator file's hash in the signed manifest", () => {
    const iocs = vendored("iocs/adfection_iocs.txt");
    expect(parseChecksums(manifest.toString("utf8")).get("adfection_iocs.txt")).toBe(createHash("sha256").update(iocs).digest("hex"));
  });

  it("refuses a manifest with one byte changed", () => {
    const tampered = Buffer.from(manifest);
    tampered[10] = tampered[10] === 0x61 ? 0x62 : 0x61;
    expect(() => verifyDetached(tampered, signature, key)).toThrow(SignatureError);
  });

  it("refuses a signature that names another key", () => {
    const other = { ...key, fingerprint: "0".repeat(40) };
    expect(() => verifyDetached(manifest, signature, other)).toThrow(/signed by/);
  });

  it("refuses something that is not armoured OpenPGP", () => {
    expect(() => verifyDetached(manifest, "hello", key)).toThrow(/not ASCII-armoured/);
  });
});
