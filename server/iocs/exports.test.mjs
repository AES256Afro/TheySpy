import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { blocklistDomains, exportFormats, renderExport, uuid5 } from "./exports.mjs";
import { parseIocText } from "./parse.mjs";

const vendored = (path) => readFileSync(new URL(`../../third_party/zero-breach/${path}`, import.meta.url), "utf8");
const set = parseIocText(vendored("iocs/adfection_iocs.txt"));

describe("exports", () => {
  it.each(Object.keys(exportFormats))("%s matches zero-breach's own file byte for byte", (format) => {
    const expected = vendored(`dist/${exportFormats[format].file}`);
    expect(renderExport(format, set)).toBe(expected);
  });

  it("leaves IPs, hashes and the excluded parent out of blocklists", () => {
    const domains = blocklistDomains(set);
    expect(domains).toHaveLength(291);
    expect(domains).not.toContain("adtimizer.co");
    expect(domains.every((d) => /[a-z]/.test(d) && d.length < 64)).toBe(true);
    expect(blocklistDomains(set, { includeHistorical: false }).length).toBeLessThan(domains.length);
  });

  it("makes the same uuid5 as Python", () => {
    // python3 -c "import uuid;print(uuid.uuid5(uuid.UUID('6f0b4a2e-5d1c-4f3b-9a7e-adf3c70f1001'),'bundle:adfection'))"
    expect(uuid5("bundle:adfection")).toBe(JSON.parse(vendored("dist/adfection.stix.json")).id.replace("bundle--", ""));
  });

  it("stamps a set without an as-of date with the injected clock, not the wall clock", () => {
    const undated = parseIocText("example-delivery.com\tdelivery\tprimary\tx\n");
    const now = () => new Date("2027-01-02T03:04:05Z");
    expect(renderExport("hosts", undated, { now })).toContain("generated 2027-01-02");
    expect(JSON.parse(renderExport("misp", undated, { now })).Event.date).toBe("2027-01-02");
  });

  it("refuses an unknown format", () => {
    expect(() => renderExport(/** @type {any} */ ("csv"), set)).toThrow(/Unknown export format/);
  });
});
