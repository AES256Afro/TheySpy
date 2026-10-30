import { rmSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { contentsOf } from "./backup.mjs";
import { openDatabase } from "./db.mjs";
import { createFleet } from "./fleet/registry.mjs";
import { testServices } from "./test-helpers.mjs";

describe("backup and restore", () => {
  it("copies a running database and the copy restores the same devices, findings and settings", () => {
    const services = testServices();
    const { db, fleet, settings, backup, audit } = services;
    fleet.observe([{ ip: "192.168.1.20", mac: "f0:18:98:00:00:0c", hostname: "macbook", seenAt: "2026-10-29T11:59:00.000Z" }], "pihole");
    const [device] = fleet.list();
    db.prepare("INSERT INTO findings (device_id, source, kind, indicator, at) VALUES (?, 'agent', 'contacted', 'fearevolve.com', ?)").run(device.id, "2026-10-29T12:00:00.000Z");
    settings.set("fleet_gateway", "192.168.1.1");

    const { dir, file, contents } = backup.snapshot();
    try {
      // The live database has one more audit entry: the backup itself.
      expect({ ...contents, audit: contents.audit + 1 }).toEqual(contentsOf(db));
      expect(contents).toMatchObject({ devices: 1, findings: 1 });
      expect(audit.list(5)[0]).toMatchObject({ action: "backup.downloaded" });

      // Restore: TheySpy starts on the copy as it would on its own file.
      const restored = openDatabase(file);
      try {
        const again = createFleet({ db: restored, audit, now: services.now, vendorOf: () => null, gateway: () => null }).list();
        expect(again.map((d) => [d.ip, d.mac])).toEqual([[device.ip, device.mac]]);
        expect(restored.prepare("SELECT indicator FROM findings").all()).toEqual([{ indicator: "fearevolve.com" }]);
        expect(restored.prepare("SELECT value FROM settings WHERE key = 'fleet_gateway'").get()).toEqual({ value: JSON.stringify("192.168.1.1") });
      } finally {
        restored.close();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
