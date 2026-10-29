import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * AES-256-GCM for the few settings that are credentials. The stored form is "v1:" + base64 of
 * nonce, tag and ciphertext; the key comes from auth.deriveKey, so changing TS_SESSION_SECRET makes
 * stored credentials unreadable (they must be entered again) rather than readable by the wrong key.
 * @param {Buffer} key 32 bytes
 */
export function createSecretBox(key) {
  return {
    /** @param {string} plain */
    seal(plain) {
      const nonce = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", key, nonce);
      const body = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
      return `v1:${Buffer.concat([nonce, cipher.getAuthTag(), body]).toString("base64")}`;
    },
    /** @param {string} sealed @returns {string | null} null when it cannot be opened with this key */
    open(sealed) {
      if (typeof sealed !== "string" || !sealed.startsWith("v1:")) return null;
      const raw = Buffer.from(sealed.slice(3), "base64");
      try {
        const decipher = createDecipheriv("aes-256-gcm", key, raw.subarray(0, 12));
        decipher.setAuthTag(raw.subarray(12, 28));
        return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString("utf8");
      } catch {
        return null;
      }
    },
  };
}
