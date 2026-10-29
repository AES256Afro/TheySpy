import { describe, expect, it } from "vitest";
import { vendored } from "../test-helpers.mjs";
import { defang, inferType, IocError, parseIocText } from "./parse.mjs";

const line = (value, tier = "delivery", confidence = "primary", source = "test") => `${value}\t${tier}\t${confidence}\t${source}\n`;

describe("indicator parser", () => {
  it("reads zero-breach's set: 405 indicators, its as-of date, sorted", () => {
    const set = parseIocText(vendored("iocs/adfection_iocs.txt").toString("utf8"));
    expect(set.asof).toBe("2026-10-18");
    expect(set.indicators).toHaveLength(405);
    const types = set.indicators.reduce((acc, i) => ({ ...acc, [i.type]: (acc[i.type] ?? 0) + 1 }), {});
    // zero-breach's README: 292 domains, 111 IPs, one spyware hash and one vulnerable-driver hash.
    expect(types).toEqual({ domain: 292, ip: 111, sha256: 2 });
    const values = set.indicators.map((i) => i.value);
    expect(values).toEqual([...values].sort());
  });

  it("infers type from shape", () => {
    expect(inferType("a".repeat(64))).toBe("sha256");
    expect(inferType("203.0.113.5")).toBe("ip");
    expect(inferType("2001:db8::1")).toBe("ip");
    expect(inferType("ads.example.com")).toBe("domain");
  });

  it("normalises case, trailing dots and IDNs, and keeps the last duplicate", () => {
    const set = parseIocText(line("Ads.Example.COM.") + line("bücher.example") + line("ads.example.com", "cc"));
    expect(set.indicators.map((i) => [i.value, i.tier])).toEqual([["ads.example.com", "cc"], ["xn--bcher-kva.example", "delivery"]]);
  });

  it("strips a byte-order mark at the start of the file", () => {
    expect(parseIocText(`\uFEFF${line("ads.example.com")}`).indicators[0].value).toBe("ads.example.com");
  });

  it.each([
    ["an unknown tier", line("ads.example.com", "bogus"), /unknown tier/],
    ["an unknown confidence", line("ads.example.com", "cc", "maybe"), /unknown confidence/],
    ["too few columns", "ads.example.com\tcc\n", /expected 3 or 4/],
    ["the unspecified address", line("0.0.0.0", "candiru-ip"), /far more than the intended host/],
    ["a single label", line("localhost"), /at least one dot/],
    ["a lone dot", line("."), /not the length of a hostname/],
    ["a bad label", line("bad_label.example.com"), /not a valid hostname label/],
    ["a zero-width space", line("ads\u200b.example.com"), /invisible character/],
    ["a stray byte-order mark mid-file", line("ads.example.com") + line("\uFEFFother.example.com"), /invisible character/],
    ["an empty file", "# nothing here\n", /no indicators/],
  ])("refuses %s", (_name, text, message) => {
    expect(() => parseIocText(text)).toThrow(IocError);
    expect(() => parseIocText(text)).toThrow(message);
  });

  it("refuses a set over 20,000 indicators", () => {
    const huge = Array.from({ length: 20001 }, (_, i) => line(`h${i}.example.com`)).join("");
    expect(() => parseIocText(huge)).toThrow(/more than 20,000/);
  });

  it("defangs domains at the last dot and IPs at every dot", () => {
    expect(defang("noas.powerium.net")).toBe("noas.powerium[.]net");
    expect(defang("203.0.113.5")).toBe("203[.]0[.]113[.]5");
    expect(defang("a".repeat(64))).toBe("a".repeat(64));
  });
});
