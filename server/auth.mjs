import { createHmac, hkdfSync, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

export const sessionCookie = "ts_session";
export const sessionLifetimeMs = 14 * 24 * 60 * 60 * 1000;
const failureWindowMs = 15 * 60 * 1000;
const failuresAllowed = 5;

function hashPassword(password, salt = randomBytes(16)) {
  return { salt: salt.toString("base64"), hash: scryptSync(password, salt, 32).toString("base64") };
}

function passwordMatches(password, stored) {
  const expected = Buffer.from(stored.hash, "base64");
  const actual = scryptSync(String(password), Buffer.from(stored.salt, "base64"), expected.length);
  return timingSafeEqual(actual, expected);
}

/**
 * Owner sign-in. One owner password (from TS_ADMIN_PASSWORD, or generated on first start and printed
 * once), sessions as random tokens whose HMAC under the session secret is the stored id, so rotating
 * TS_SESSION_SECRET signs everyone out without touching other data.
 * @param {{
 *   db: import("node:sqlite").DatabaseSync,
 *   settings: ReturnType<typeof import("./db.mjs").createSettingsStore>,
 *   audit: ReturnType<typeof import("./audit.mjs").createAuditLog>,
 *   adminPassword: string | null,
 *   sessionSecret: string | null,
 *   now?: () => Date,
 * }} options
 */
export function createAuth({ db, settings, audit, adminPassword, sessionSecret, now = () => new Date() }) {
  /** Set only when this start generated the owner password, so the caller can print it once. */
  let generatedPassword = null;
  let ownerPassword;
  if (adminPassword) {
    ownerPassword = hashPassword(adminPassword);
  } else {
    ownerPassword = settings.get("owner_password");
    if (!ownerPassword) {
      generatedPassword = randomBytes(15).toString("base64url");
      ownerPassword = hashPassword(generatedPassword);
      settings.set("owner_password", ownerPassword);
      audit.record("system", "owner.password_generated");
    }
  }

  let secret = sessionSecret;
  if (!secret) {
    secret = settings.get("session_secret");
    if (!secret) {
      secret = randomBytes(32).toString("base64url");
      settings.set("session_secret", secret);
    }
  }
  const sessionId = (token) => createHmac("sha256", secret).update(token).digest("hex");

  const insertSession = db.prepare("INSERT INTO sessions (id, created_at, last_seen_at, expires_at, user_agent) VALUES (?, ?, ?, ?, ?)");
  const findSession = db.prepare("SELECT id, last_seen_at, expires_at FROM sessions WHERE id = ?");
  const touchSession = db.prepare("UPDATE sessions SET last_seen_at = ? WHERE id = ?");
  const deleteSession = db.prepare("DELETE FROM sessions WHERE id = ?");
  const deleteExpired = db.prepare("DELETE FROM sessions WHERE expires_at <= ?");

  /** @type {Map<string, { failures: number, since: number }>} */
  const failures = new Map();

  return {
    generatedPassword,

    /**
     * A 32-byte key for one purpose, derived from the session secret. Settings encrypted with it
     * (the Pi-hole password) become unreadable when the secret changes, like sessions do. Keep
     * TS_SESSION_SECRET outside the database so a copied database alone does not unlock them.
     * @param {string} purpose
     */
    deriveKey(purpose) {
      return Buffer.from(hkdfSync("sha256", secret, "theyspy", purpose, 32));
    },

    /**
     * @param {unknown} password
     * @param {{ ip: string, userAgent?: string }} client
     * @returns {{ ok: true, token: string, expiresAt: Date } | { ok: false, retryAfterSeconds?: number }}
     */
    login(password, { ip, userAgent }) {
      const at = now().getTime();
      const record = failures.get(ip);
      if (record && at - record.since >= failureWindowMs) failures.delete(ip);
      const current = failures.get(ip);
      if (current && current.failures >= failuresAllowed) {
        return { ok: false, retryAfterSeconds: Math.ceil((current.since + failureWindowMs - at) / 1000) };
      }
      if (typeof password !== "string" || !password || !passwordMatches(password, ownerPassword)) {
        failures.set(ip, { failures: (current?.failures ?? 0) + 1, since: current?.since ?? at });
        audit.record("anonymous", "owner.sign_in_failed", ip);
        return { ok: false };
      }
      failures.delete(ip);
      deleteExpired.run(now().toISOString());
      const token = randomBytes(32).toString("base64url");
      const expiresAt = new Date(at + sessionLifetimeMs);
      insertSession.run(sessionId(token), now().toISOString(), now().toISOString(), expiresAt.toISOString(), userAgent?.slice(0, 300) ?? null);
      audit.record("owner", "owner.signed_in", ip);
      return { ok: true, token, expiresAt };
    },

    /** @param {string | undefined} token @returns {boolean} */
    verify(token) {
      if (!token) return false;
      const row = /** @type {any} */ (findSession.get(sessionId(token)));
      if (!row) return false;
      if (Date.parse(row.expires_at) <= now().getTime()) {
        deleteSession.run(row.id);
        return false;
      }
      if (now().getTime() - Date.parse(row.last_seen_at) > 60_000) touchSession.run(now().toISOString(), row.id);
      return true;
    },

    /** @param {string | undefined} token */
    logout(token) {
      if (!token) return;
      deleteSession.run(sessionId(token));
      audit.record("owner", "owner.signed_out");
    },
  };
}
