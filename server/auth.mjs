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

  const insertSession = db.prepare("INSERT INTO sessions (id, created_at, last_seen_at, expires_at, user_agent, role) VALUES (?, ?, ?, ?, ?, ?)");
  const findSession = db.prepare("SELECT id, last_seen_at, expires_at, role FROM sessions WHERE id = ?");
  const deleteHousehold = db.prepare("DELETE FROM sessions WHERE role = 'household'");
  const touchSession = db.prepare("UPDATE sessions SET last_seen_at = ? WHERE id = ?");
  const deleteSession = db.prepare("DELETE FROM sessions WHERE id = ?");
  const deleteExpired = db.prepare("DELETE FROM sessions WHERE expires_at <= ?");

  /** @type {Map<string, { failures: number, since: number }>} */
  const failures = new Map();

  return {
    generatedPassword,

    /**
     * Whether the key that seals stored credentials lives in this database. It does when
     * TS_SESSION_SECRET is not set in the environment: TheySpy generates one and keeps it in
     * `settings`, which a backup copies along with the credentials it opens. The Activity screen
     * says so, because nothing else would.
     */
    sessionSecretStored: !sessionSecret,

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
     * @returns {{ ok: true, token: string, expiresAt: Date, role: "owner" | "household" } | { ok: false, retryAfterSeconds?: number }}
     */
    login(password, { ip, userAgent }) {
      const at = now().getTime();
      const record = failures.get(ip);
      if (record && at - record.since >= failureWindowMs) failures.delete(ip);
      const current = failures.get(ip);
      if (current && current.failures >= failuresAllowed) {
        return { ok: false, retryAfterSeconds: Math.ceil((current.since + failureWindowMs - at) / 1000) };
      }
      // The owner's password first; then the household's, when one is set (M37). The same lockout
      // counts both, so a guess at either costs the same.
      const household = settings.get("household_password");
      const role = typeof password === "string" && password ? (passwordMatches(password, ownerPassword) ? "owner" : household && passwordMatches(password, household) ? "household" : null) : null;
      if (!role) {
        failures.set(ip, { failures: (current?.failures ?? 0) + 1, since: current?.since ?? at });
        audit.record("anonymous", "owner.sign_in_failed", ip);
        return { ok: false };
      }
      failures.delete(ip);
      deleteExpired.run(now().toISOString());
      const token = randomBytes(32).toString("base64url");
      const expiresAt = new Date(at + sessionLifetimeMs);
      insertSession.run(sessionId(token), now().toISOString(), now().toISOString(), expiresAt.toISOString(), userAgent?.slice(0, 300) ?? null, role);
      audit.record(role, `${role}.signed_in`, ip);
      return { ok: true, token, expiresAt, role };
    },

    /** @param {string | undefined} token @returns {boolean} */
    verify(token) { return Boolean(this.role(token)); },

    /**
     * Whose session a token is: "owner", "household", or null when it is no session at all.
     * @param {string | undefined} token @returns {"owner" | "household" | null}
     */
    role(token) {
      if (!token) return null;
      const row = /** @type {any} */ (findSession.get(sessionId(token)));
      if (!row) return null;
      if (Date.parse(row.expires_at) <= now().getTime()) {
        deleteSession.run(row.id);
        return null;
      }
      if (now().getTime() - Date.parse(row.last_seen_at) > 60_000) touchSession.run(now().toISOString(), row.id);
      return row.role === "household" ? "household" : "owner";
    },

    /** Whether a household password is set. */
    householdSet() { return Boolean(settings.get("household_password")); },

    /**
     * Sets the read-only password the household signs in with, or clears it (null), which also
     * ends every household session. Eight characters at least, and never the owner's own.
     * @param {unknown} password @param {string} actor
     */
    setHouseholdPassword(password, actor) {
      if (password === null || password === "") {
        settings.delete("household_password");
        deleteHousehold.run();
        audit.record(actor, "household.password_cleared");
        return { set: false };
      }
      if (typeof password !== "string" || password.length < 8) throw Object.assign(new Error("The household password needs at least 8 characters"), { status: 400 });
      if (password.length > 200) throw Object.assign(new Error("The household password is too long (200 characters at most)"), { status: 400 });
      if (passwordMatches(password, ownerPassword)) throw Object.assign(new Error("The household password must differ from the owner's"), { status: 400 });
      settings.set("household_password", hashPassword(password));
      deleteHousehold.run();
      audit.record(actor, "household.password_set");
      return { set: true };
    },

    /** @param {string | undefined} token */
    logout(token) {
      if (!token) return;
      const row = /** @type {any} */ (findSession.get(sessionId(token)));
      deleteSession.run(sessionId(token));
      const role = row?.role === "household" ? "household" : "owner";
      audit.record(role, `${role}.signed_out`);
    },
  };
}
