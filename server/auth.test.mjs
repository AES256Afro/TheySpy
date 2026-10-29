import { describe, expect, it } from "vitest";
import { createAuditLog } from "./audit.mjs";
import { createAuth, sessionLifetimeMs } from "./auth.mjs";
import { createSettingsStore, openDatabase } from "./db.mjs";
import { testClock, testServices } from "./test-helpers.mjs";

const client = { ip: "192.0.2.10" };

describe("owner sign-in", () => {
  it("accepts the owner password and verifies the session token", () => {
    const { auth } = testServices();
    const result = auth.login("correct horse", client);
    expect(result.ok).toBe(true);
    expect(auth.verify(result.ok ? result.token : "")).toBe(true);
    expect(auth.verify("forged")).toBe(false);
    expect(auth.verify(undefined)).toBe(false);
  });

  it("refuses a wrong password and locks an address out after five failures", () => {
    const now = testClock();
    const { auth } = testServices({ now });
    for (let attempt = 0; attempt < 5; attempt += 1) expect(auth.login("nope", client)).toEqual({ ok: false });
    const locked = auth.login("correct horse", client);
    expect(locked.ok).toBe(false);
    expect(!locked.ok && locked.retryAfterSeconds).toBeGreaterThan(0);
    expect(auth.login("correct horse", { ip: "192.0.2.11" }).ok).toBe(true);
    now.advance(15 * 60 * 1000);
    expect(auth.login("correct horse", client).ok).toBe(true);
  });

  it("expires sessions and signs out", () => {
    const now = testClock();
    const { auth } = testServices({ now });
    const first = auth.login("correct horse", client);
    const second = auth.login("correct horse", client);
    if (!first.ok || !second.ok) throw new Error("sign-in failed");
    auth.logout(first.token);
    expect(auth.verify(first.token)).toBe(false);
    now.advance(sessionLifetimeMs + 1);
    expect(auth.verify(second.token)).toBe(false);
  });

  it("signs everyone out when the session secret changes", () => {
    const db = openDatabase(":memory:");
    const before = testServices({ db, sessionSecret: "one" });
    const result = before.auth.login("correct horse", client);
    if (!result.ok) throw new Error("sign-in failed");
    const after = testServices({ db, sessionSecret: "two" });
    expect(after.auth.verify(result.token)).toBe(false);
  });

  it("generates an owner password once when none is configured, and keeps only its hash", () => {
    const db = openDatabase(":memory:");
    const settings = createSettingsStore(db);
    const audit = createAuditLog(db);
    const first = createAuth({ db, settings, audit, adminPassword: null, sessionSecret: null });
    expect(first.generatedPassword).toMatch(/^[A-Za-z0-9_-]{20}$/);
    expect(JSON.stringify(settings.get("owner_password"))).not.toContain(first.generatedPassword);
    const second = createAuth({ db, settings, audit, adminPassword: null, sessionSecret: null });
    expect(second.generatedPassword).toBeNull();
    expect(second.login(first.generatedPassword, client).ok).toBe(true);
  });
});
