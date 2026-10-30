import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseNetworkLog } from "./netlogs.mjs";
import { testServices } from "./test-helpers.mjs";

// The fixtures are real output: one capture (DNS lookups of test names, HTTPS to example.com, and
// an HTTP request with the Host c2-node.theyspy.example) read by Suricata 8.0 with JA4 on, and by
// Zeek 9.0 in ASCII and JSON. 172.17.0.2 is the container that made the traffic.
const fixture = (name) => readFileSync(new URL(`./fixtures/netlogs/${name}`, import.meta.url), "utf8");
const testSet = "# as-of: 2026-10-30\nads-sync.theyspy.example\tdelivery\tprimary\te2e\nc2-node.theyspy.example\tcc\tprimary\te2e\n";
const realJa4 = "t13d3112h2_e8f1e7e78f70_6bebaf5329ac";

function services() {
  const s = testServices();
  s.iocStore.apply(s.iocStore.recordCandidate({ raw: testSet, provenance: { track: "main", note: "test" }, actor: "test" }).id, "test");
  s.fleet.observe([{ ip: "172.17.0.2", mac: "02:42:ac:11:00:02", hostname: "lab", seenAt: "2026-10-30T16:30:00.000Z" }], "pihole");
  return s;
}

describe("reading network logs", () => {
  it("reads Suricata's eve.json: DNS requests only, TLS server names with JA4, HTTP hosts", () => {
    const { tool, events } = parseNetworkLog("eve.json", fixture("eve.json"));
    expect(tool).toBe("suricata");
    expect(events.filter((e) => e.kind === "dns").map((e) => e.name)).toEqual(expect.arrayContaining(["ads-sync.theyspy.example", "deep.ads-sync.theyspy.example", "example.com"]));
    expect(events.every((e) => e.client === "172.17.0.2")).toBe(true); // responses (from the resolver) are not read as lookups
    expect(events.find((e) => e.kind === "tls")).toMatchObject({ name: "example.com", ja4: realJa4 });
    expect(events.find((e) => e.kind === "http")).toMatchObject({ name: "c2-node.theyspy.example" });
  });

  it("reads Zeek's logs in ASCII and in JSON alike", () => {
    for (const [file, log] of [["zeek-dns.log", "dns"], ["zeek-dns.json.log", "dns"], ["zeek-http.log", "http"], ["zeek-http.json.log", "http"], ["zeek-ssl.log", "ssl"]]) {
      const parsed = parseNetworkLog(file, fixture(file));
      expect(parsed, file).toMatchObject({ tool: "zeek", log });
      expect(parsed.events.length, file).toBeGreaterThan(0);
      expect(parsed.events.every((e) => e.client === "172.17.0.2" && !Number.isNaN(Date.parse(e.at))), file).toBe(true);
    }
    expect(parseNetworkLog("dns.log", fixture("zeek-dns.log")).events.map((e) => e.name)).toEqual(parseNetworkLog("dns.json", fixture("zeek-dns.json.log")).events.map((e) => e.name));
    expect(parseNetworkLog("ssl.log", fixture("zeek-ssl.log")).events[0]).toMatchObject({ kind: "tls", name: "example.com", ja4: null }); // ja4 needs FoxIO's package
    // With FoxIO's JA4 package, Zeek adds a ja4 column to ssl.log.
    const withJa4 = fixture("zeek-ssl.log").replace(/^(#fields.*)$/m, "$1\tja4").replace(/^(\d+\.\d+\t.*)$/m, `$1\t${realJa4}`).replace(/^(#types.*)$/m, "$1\tstring");
    expect(parseNetworkLog("ssl.log", withJa4).events[0].ja4).toBe(realJa4);
  });

  it("refuses a file that is neither", () => {
    expect(() => parseNetworkLog("notes.txt", "hello\nworld\n")).toThrow(/not a Zeek dns, ssl or http log, nor a Suricata eve.json/);
  });
});

describe("importing network logs", () => {
  it("turns indicator contacts into findings on the device that made them, once", () => {
    const s = services();
    const first = s.netlogs.importLogs([{ name: "eve.json", content: fixture("eve.json") }, { name: "dns.log", content: fixture("zeek-dns.log") }], "owner");
    // ads-sync (dns) and c2-node (http) from Suricata, ads-sync (dns) from Zeek. deep.ads-sync falls
    // under the same indicator, tool and kind as ads-sync, so it is the same finding.
    expect(first.findings).toBe(3);
    const findings = s.db.prepare("SELECT source, indicator, location, detail, device_id FROM findings ORDER BY id").all().map((r) => ({ ...r }));
    expect(findings.map((f) => [f.source, f.indicator, f.location])).toEqual(expect.arrayContaining([["suricata", "ads-sync.theyspy.example", "suricata dns"], ["suricata", "c2-node.theyspy.example", "suricata http"], ["zeek", "ads-sync.theyspy.example", "zeek dns"]]));
    expect(findings.every((f) => f.device_id === s.fleet.list()[0].id)).toBe(true);
    expect(findings.find((f) => f.location === "suricata http").detail).toMatch(/^172\.17\.0\.2 \(lab\) asked HTTP for c2-node\.theyspy\.example at /);
    // The same logs again add nothing.
    expect(s.netlogs.importLogs([{ name: "eve.json", content: fixture("eve.json") }], "owner").findings).toBe(0);
    expect(s.audit.list(10).some((e) => e.action === "agent.indicator_found")).toBe(true);
  });

  it("keeps each device's TLS fingerprints: the first import is the baseline, a new one later is flagged", () => {
    const s = services();
    expect(s.netlogs.importLogs([{ name: "eve.json", content: fixture("eve.json") }], "owner").newFingerprints).toEqual([]);
    expect(s.netlogs.fingerprints()).toMatchObject([{ client: "172.17.0.2", device: "lab", ja4: realJa4, sni: "example.com", isNew: false }]);

    const implant = "t13d1516h2_8daaf6152771_02713d6af862";
    const later = fixture("eve.json").replaceAll(realJa4, implant).replaceAll("2026-", "2027-");
    const second = s.netlogs.importLogs([{ name: "eve.json", content: later }], "owner");
    expect(second.newFingerprints).toEqual([{ client: "172.17.0.2", device: "lab", ja4: implant, sni: "example.com" }]);
    expect(s.netlogs.fingerprints()[0]).toMatchObject({ ja4: implant, isNew: true });
    expect(s.audit.list(5).find((e) => e.action === "evidence.ja4_new")).toBeTruthy();

    s.netlogs.acknowledge("172.17.0.2", implant, "owner");
    expect(s.netlogs.fingerprints().every((f) => !f.isNew)).toBe(true);
  });
});
