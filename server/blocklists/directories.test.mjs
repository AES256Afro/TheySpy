import { describe, expect, it } from "vitest";
import { listName } from "./directories.mjs";

describe("M17 C28: a list's readable name", () => {
  it("survives a malformed percent-sequence in a path, as one Firebog entry can carry", () => {
    expect(listName("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt")).toBe("hagezi/dns-blocklists (pro)");
    expect(() => listName("https://example.net/hosts/%E0%A4%A.txt")).not.toThrow();
    expect(listName("https://example.net/hosts/%E0%A4%A.txt")).toBe("example.net %E0%A4%A");
  });
});
