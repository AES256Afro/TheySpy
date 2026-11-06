import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * AES-256-GCM for the few settings that are credentials. The stored form is "v2:" + base64 of
 * nonce, tag and ciphertext; the key comes from auth.deriveKey, so changing TS_SESSION_SECRET makes
 * stored credentials unreadable (they must be entered again) rather than readable by the wrong key.
 *
 * Each caller has its own key (one per `deriveKey` purpose), so a sealed Pi-hole password is
 * already no use in the ntfy field. `context` closes the gap inside one caller: where a key seals
 * many rows — every agent's signing secret, every site's token — the row it belongs to is bound
 * in as associated data, so moving one row's blob into another row no longer lets one agent sign
 * as another. Values sealed before this (the "v1:" prefix) carry no context and still open.
 * @param {Buffer} key 32 bytes
 */
export function createSecretBox(key) {
  return {
    /**
     * @param {string} plain
     * @param {string} [context] what this value belongs to, e.g. "agent:12"; bound into the seal
     */
    seal(plain, context = "") {
      const nonce = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", key, nonce);
      if (context) cipher.setAAD(Buffer.from(context, "utf8"));
      const body = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
      return `v2:${Buffer.concat([nonce, cipher.getAuthTag(), body]).toString("base64")}`;
    },
    /**
     * @param {string} sealed
     * @param {string} [context] the same context it was sealed with
     * @returns {string | null} null when it cannot be opened with this key and context
     */
    open(sealed, context = "") {
      if (typeof sealed !== "string") return null;
      const version = sealed.slice(0, 3);
      if (version !== "v1:" && version !== "v2:") return null;
      const raw = Buffer.from(sealed.slice(3), "base64");
      try {
        const decipher = createDecipheriv("aes-256-gcm", key, raw.subarray(0, 12));
        // "v1:" predates context, so it was sealed without any.
        if (context && version === "v2:") decipher.setAAD(Buffer.from(context, "utf8"));
        decipher.setAuthTag(raw.subarray(12, 28));
        return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString("utf8");
      } catch {
        return null;
      }
    },
  };
}
