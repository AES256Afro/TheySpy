import { describe, expect, it } from "vitest";
import { testClock, testServices } from "../test-helpers.mjs";
import { advisoryUrls, parseMsrc, parseRss } from "./advisories.mjs";

const appleIndex = (rows) => rows.map(([id, name, date]) => `<tr><td><p><a href="https://support.apple.com/en-us/${id}" class="gb-anchor">${name}</a></p></td><td><p>iPhone 11 and later</p></td><td><p class="gb-paragraph">${date}</p></td></tr>`).join("");
const appleRelease = (cve) => `<h2>WebKit</h2><p>Impact: Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack.</p><p>Description: A use-after-free issue was addressed.</p><p>${cve}: an anonymous researcher</p><h2>Kernel</h2><p>Impact: An app may crash.</p><p>CVE-2026-90001: someone</p>`;

function web(files) {
  return async (input) => {
    const url = String(input);
    const body = files[url];
    if (body === undefined) return new Response("", { status: 404 });
    return typeof body === "string" ? new Response(body) : Response.json(body);
  };
}

describe("vendor and research zero-day reports", () => {
  it("parses Microsoft's exploited flag and research feeds", () => {
    const msrc = { DocumentTracking: { CurrentReleaseDate: "2026-10-14T07:00:00" }, Vulnerability: [
      { CVE: "CVE-2026-96951", Title: { Value: "Windows Kernel Elevation of Privilege" }, Threats: [{ Type: 1, Description: { Value: "Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected" } }] },
      { CVE: "CVE-2026-96952", Threats: [{ Type: 1, Description: { Value: "Exploited:No" } }] },
    ] };
    expect(parseMsrc(msrc, "2026-Oct")).toEqual([{ cveId: "CVE-2026-96951", source: "Microsoft", at: "2026-10-14", url: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96951", note: "Microsoft (2026-Oct): exploited · Windows Kernel Elevation of Privilege" }]);
    const rss = "<rss><channel><item><title>Exposing AdFection</title><link>https://citizenlab.ca/2026/10/adfection/</link><pubDate>Mon, 26 Oct 2026 10:00:00 +0000</pubDate><description><![CDATA[Ads delivered spyware using CVE-2026-4092.]]></description></item></channel></rss>";
    expect(parseRss(rss, "Citizen Lab")).toEqual([{ source: "Citizen Lab", title: "Exposing AdFection", url: "https://citizenlab.ca/2026/10/adfection/", at: "2026-10-26", cves: ["CVE-2026-4092"] }]);
  });

  it("flags CVEs vendors report as exploited, quietly the first time, then with an alert for software you run", async () => {
    const files = {
      [advisoryUrls.chrome]: "<feed><entry><published>2026-10-20T10:00:00Z</published><link rel='alternate' href='https://chromereleases.googleblog.com/x'/><content>Google is aware that an exploit for CVE-2026-4127 exists in the wild.</content></entry></feed>",
      [advisoryUrls.apple]: appleIndex([["149227", "iOS 26.7.2 and iPadOS 26.7.2", "26 Oct 2026"]]),
      "https://support.apple.com/en-us/149227": appleRelease("CVE-2026-4092"),
      [advisoryUrls.msrc("2026-Oct")]: { Vulnerability: [] },
      [advisoryUrls.research[0][1]]: "<rss></rss>", [advisoryUrls.research[1][1]]: "<rss></rss>",
    };
    const now = testClock("2026-10-29T12:00:00.000Z");
    const { advisories, cves, alerts, checker } = testServices({ webFetch: web(files), now, network: { probeHost: async () => ({ port: 22, answer: "open" }), checkPortsImpl: async () => [{ port: 22, proto: "tcp", service: "ssh", banner: "x", product: "OpenSSH", version: "9.6p1", tls: null, risk: null }] } });
    const first = await advisories.sync();
    expect(first.added.sort()).toEqual(["CVE-2026-4092", "CVE-2026-4127"]);
    expect(cves.get("CVE-2026-4092")).toMatchObject({ zeroDay: true, kev: null, zeroDaySources: [{ source: "Apple", note: "Apple (iOS 26.7.2 and iPadOS 26.7.2): may have been exploited" }] });
    expect(cves.recentEvents()).toEqual([]);

    // Later: Chrome's CVE turns up in KEV too (no news), and a new vendor report about OpenSSH, which a device runs.
    await checker.run({ query: "192.168.8.5", profile: "standard" }, "owner");
    cves.upsertNvd([{ cveId: "CVE-2026-7777", published: "2026-10-28", modified: "2026-10-28", status: "Analyzed", description: "OpenSSH bug", cvssScore: 8.1, cvssSeverity: "high", cvssVector: null, cwes: [], products: ["openbsd:openssh"], cpeMatches: [{ criteria: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", vee: "9.9" }] }], { announce: false });
    files[advisoryUrls.chrome] += "<entry><published>2026-10-29T10:00:00Z</published><content>Google is aware that an exploit for CVE-2026-7777 exists in the wild.</content></entry>";
    now.advance(6 * 3_600_000);
    const second = await advisories.sync();
    expect(second.added).toEqual(["CVE-2026-7777"]);
    await new Promise((r) => setTimeout(r, 0));
    expect(alerts.recent()[0]).toMatchObject({ kind: "kev_match", message: expect.stringContaining("CVE-2026-7777 (on 192.168.8.5)") });
    expect(alerts.recent()[0].message).toContain("Chrome Releases reports it as exploited");
  });
});
