import { describe, expect, it } from "vitest";
import { createSettingsStore, migrate, migrations, openDatabase } from "./db.mjs";

describe("database", () => {
  it("migrates a new database to the latest version and is idempotent", () => {
    const db = openDatabase(":memory:");
    expect(Number(/** @type {any} */ (db.prepare("PRAGMA user_version").get()).user_version)).toBe(migrations.length);
    expect(migrate(db)).toBe(migrations.length);
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((row) => /** @type {any} */ (row).name);
    expect(tables).toEqual(expect.arrayContaining(["settings", "sessions", "jobs", "audit_log"]));
  });

  it("stores settings as JSON and overwrites by key", () => {
    const settings = createSettingsStore(openDatabase(":memory:"));
    expect(settings.get("missing")).toBeUndefined();
    settings.set("appearance", { look: "glass" });
    settings.set("appearance", { look: "paper" });
    expect(settings.get("appearance")).toEqual({ look: "paper" });
    settings.delete("appearance");
    expect(settings.get("appearance")).toBeUndefined();
  });


  it("refuses data a newer TheySpy wrote rather than running against a schema it does not know", () => {
    const db = openDatabase(":memory:");
    // What a rollback to an older image finds: the data has been migrated past what this code knows.
    db.exec(`PRAGMA user_version = ${migrations.length + 1}`);
    expect(() => migrate(db)).toThrow(/written by a newer TheySpy/);
    expect(() => migrate(db)).toThrow(/restore the backup taken before the update/);
    // The same version it knows is of course fine.
    db.exec(`PRAGMA user_version = ${migrations.length}`);
    expect(migrate(db)).toBe(migrations.length);
  });
});
