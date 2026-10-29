import { describe, expect, it } from "vitest";
import { testClock, testServices } from "../test-helpers.mjs";
import { fingerprint } from "./scan.mjs";

const nvd = (ids) => Response.json({ totalResults: ids.length, vulnerabilities: ids.map(([id, score]) => ({ cve: { id, descriptions: [{ lang: "en", value: `${id} in PHP` }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: score, baseSeverity: score >= 9 ? "CRITICAL" : "HIGH" } }] } } })) });

/** A small fake web: each site is a map of path → response; NVD answers by the version asked for. */
function web(sites, requests = []) {
  return async (input, init = {}) => {
    const url = new URL(String(input));
    requests.push(`${init.method ?? "GET"} ${url.href}`);
    if (url.hostname === "services.nvd.nist.gov") {
      const match = url.searchParams.get("virtualMatchString");
      if (match === "cpe:2.3:a:php:php:7.4.3") return nvd([["CVE-2024-4577", 9.8], ["CVE-2022-31626", 8.8]]);
      if (match === "cpe:2.3:a:wordpress:wordpress:6.2") return nvd([["CVE-2023-38000", 5.4]]);
      return nvd([]);
    }
    const site = sites[url.origin];
    const page = site?.[url.pathname] ?? site?.["*"];
    if (!page) return new Response("not found", { status: 404 });
    return new Response(page.body ?? "", { status: page.status ?? 200, headers: page.headers ?? {} });
  };
}

const vulnerable = {
  "/": { headers: { "x-powered-by": "PHP/7.4.3" }, body: '<html><head><meta name="generator" content="WordPress 6.2"></head><body>wp-content/</body></html>' },
  "/.env": { body: "APP_KEY=base64:abc\nDB_PASSWORD=hunter2\n" },
  "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php": { body: "" },
  "/.git/HEAD": { body: "ref: refs/heads/main\n" },
};

describe("website check", () => {
  it("reads PHP and CMS versions from headers and pages", () => {
    const found = fingerprint(new Headers({ "x-powered-by": "PHP/8.2.12", "set-cookie": "PHPSESSID=x" }), '<meta name="generator" content="WordPress 6.6.1">');
    expect(found.map((f) => [f.product, f.version])).toEqual([["PHP", "8.2.12"], ["WordPress", "6.6.1"]]);
    expect(fingerprint(new Headers({ "set-cookie": "PHPSESSID=abc; path=/" }), "")).toMatchObject([{ product: "PHP", version: null }]);
  });

  it("checks a site on this network: versions, CVEs, unsupported PHP and exposed files, without keeping secrets", async () => {
    const requests = [];
    const { checker, cves } = testServices({ webFetch: web({ "https://shop.lan": vulnerable }, requests), now: testClock("2026-10-29T12:00:00Z"), network: { lookup: async (h) => (h === "shop.lan" ? "192.168.1.30" : null) } });
    cves.applyKev({ version: "1", entries: [{ cveId: "CVE-2024-4577", added: "2024-06-12", due: "2024-07-03", ransomware: true, name: "PHP-CGI argument injection", description: "x", action: "x", product: "php:php", cwes: [] }] });
    const r = await checker.run({ query: "https://shop.lan/some/page" }, "owner");
    expect(r).toMatchObject({ kind: "website", url: "https://shop.lan", access: "on this network" });
    const php = r.software.find((s) => s.product === "PHP");
    expect(php).toMatchObject({ version: "7.4.3", supported: false, supportEnds: "2022-11-28" });
    expect(php.cves.map((c) => [c.cveId, c.kev])).toEqual([["CVE-2024-4577", true], ["CVE-2022-31626", false]]);
    expect(r.software.find((s) => s.product === "WordPress")).toMatchObject({ version: "6.2", cves: [{ cveId: "CVE-2023-38000" }] });
    expect(r.findings.map((f) => [f.severity, f.path])).toEqual([["critical", "/.env"], ["critical", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"], ["high", "/.git/HEAD"], ["high", "/"], ["low", "/"], ["low", "/"]]);
    expect(JSON.stringify(r)).not.toContain("hunter2");
    expect(r.findings[0].evidence).toBe("variables: APP_KEY, DB_PASSWORD");
    // Only GETs, and only to the site and NVD.
    expect(requests.every((x) => x.startsWith("GET https://shop.lan/") || x.startsWith("GET https://services.nvd.nist.gov/"))).toBe(true);
    expect(checker.recent()[0]).toMatchObject({ kind: "website", query: "https://shop.lan" });
  });

  it("does not take a page that answers 200 for everything as a finding", async () => {
    const soft = { "/": { body: "<html>Welcome</html>" }, "*": { body: "<html>Page not found</html>" } };
    const { checker } = testServices({ webFetch: web({ "http://nas.lan": soft }), network: { lookup: async () => "192.168.1.10" } });
    const r = await checker.run({ query: "http://nas.lan" }, "owner");
    expect(r.findings).toEqual([]);
  });

  it("refuses a public site until its owner publishes the token", async () => {
    const sites = { "https://example.org": { ...vulnerable } };
    const { checker, web: scanner } = testServices({ webFetch: web(sites), network: { lookup: async () => "93.184.216.34" } });
    const refused = await checker.run({ query: "https://example.org" }, "owner").catch((e) => e);
    expect(refused).toMatchObject({ status: 403, verification: { host: "example.org" } });
    expect(refused.message).toContain(scanner.tokenFor("example.org"));
    sites["https://example.org"]["/.well-known/theyspy-verification.txt"] = { body: `${scanner.tokenFor("example.org")}\n` };
    expect(await checker.run({ query: "https://example.org" }, "owner")).toMatchObject({ access: "verification file" });
    expect(scanner.tokenFor("example.org")).not.toBe(scanner.tokenFor("example.com"));
  });
});
