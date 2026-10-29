import { describe, expect, it } from "vitest";
import { canonical, parseBlocklist } from "./parse.mjs";
import { fromAdguard, fromFilterListsTags, fromName } from "./taxonomy.mjs";

describe("blocklist parser", () => {
  it("reads every format into one set of hostnames", () => {
    const text = [
      "# hosts", "0.0.0.0 hosts.example", "127.0.0.1 a.example b.example # two names", ":: v6.example",
      "! Adblock", "||abp.example^", "||important.example^$important", "||path.example/ads^", "||opt.example^$third-party", "@@||allowed.example^", "example.com##.banner",
      "plain.example", "*.wild.example",
      "address=/dnsmasq.example/0.0.0.0", "server=/server.example/",
      "rpz.example CNAME .", "*.rpzwild.example 300 IN CNAME .",
      "localhost", "0.0.0.0 0.0.0.0", "203.0.113.5", "bad_name..example", "Bücher.Example.",
    ].join("\n");
    const { domains } = parseBlocklist(text);
    expect([...domains].sort()).toEqual([
      "a.example", "abp.example", "b.example", "dnsmasq.example", "hosts.example", "important.example", "plain.example",
      "rpz.example", "rpzwild.example", "server.example", "v6.example", "wild.example", "xn--bcher-kva.example",
    ]);
  });

  it("strips a byte-order mark and ignores section headers", () => {
    expect([...parseBlocklist("\uFEFF[Adblock Plus 2.0]\n||x.example^\n").domains]).toEqual(["x.example"]);
  });

  it("canonicalises names and rejects what is not a hostname", () => {
    expect(canonical("ADS.Example.")).toBe("ads.example");
    expect(canonical("*.ads.example")).toBe("ads.example");
    expect(canonical("localhost")).toBeNull();
    expect(canonical("10.0.0.1")).toBeNull();
    expect(canonical("singlelabel")).toBeNull();
    expect(canonical("-bad.example")).toBeNull();
  });
});

describe("categories", () => {
  it("maps FilterLists tags, and treats allowlists as not blocklists", () => {
    expect(fromFilterListsTags([2, 3])).toEqual(["ads", "trackers"]);
    expect(fromFilterListsTags([6, 7])).toEqual(["malware", "phishing"]);
    expect(fromFilterListsTags([10, 2])).toBeNull();
    expect(fromFilterListsTags([22])).toEqual(["other"]);
  });

  it("maps AdGuard registry entries by key, then by group", () => {
    expect(fromAdguard({ filterKey: "staklerware_indicators_list", groupId: 4, name: "Stalkerware Indicators List" })).toEqual(["spyware"]);
    expect(fromAdguard({ filterKey: "hagezi_samsung_tracker_blocklist", groupId: 2, name: "HaGeZi's Samsung Tracker Blocklist" })).toEqual(["telemetry"]);
    expect(fromAdguard({ filterKey: "some_new_general_list", groupId: 1, name: "New" })).toEqual(["ads", "trackers"]);
    expect(fromAdguard({ filterKey: "hagezi_allowlist_referral", groupId: 2, name: "HaGeZi's Allowlist Referral" })).toBeNull();
  });

  it("guesses from a name when nothing else labels a list", () => {
    expect(fromName("Phishing Army")).toEqual(["phishing"]);
    expect(fromName("KADhosts")).toEqual(["ads"]);
    expect(fromName("Something")).toEqual(["other"]);
  });
});
