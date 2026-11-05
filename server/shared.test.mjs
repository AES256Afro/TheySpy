import { describe, expect, it } from "vitest";
import { maxResponseBytes, readCapped, readCappedBytes, readCappedJson } from "./shared.mjs";

describe("reading an outside answer", () => {
  it("reads text, bytes and JSON", async () => {
    expect(await readCapped(new Response("hello"))).toBe("hello");
    expect(await readCapped(new Response(""))).toBe("");
    expect(await readCappedBytes(new Response("ab"))).toEqual(Buffer.from("ab"));
    expect(await readCappedJson(new Response('{"a":1}'))).toEqual({ a: 1 });
  });

  it("stops at the ceiling whether or not the server declared its length", async () => {
    // A declared length over the ceiling fails before a byte is read.
    await expect(readCapped(new Response("x", { headers: { "content-length": "999" } }), { maxBytes: 10, what: "a feed" }))
      .rejects.toThrow("a feed says its answer is 999 bytes; TheySpy reads at most 10");
    // A declared length is not a promise, so the bytes are counted as they arrive.
    const lying = new Response("0123456789abcdef", { headers: { "content-length": "2" } });
    await expect(readCapped(lying, { maxBytes: 10, what: "a feed" }))
      .rejects.toThrow("a feed answered more than 10 bytes; TheySpy stopped reading it");
  });

  it("names the service when its answer is not JSON, without quoting the answer back", async () => {
    const error = await readCappedJson(new Response("<html>an error page</html>"), { what: "NVD" }).catch((e) => e);
    expect(error.message).toBe("NVD did not answer JSON");
    expect(error.message).not.toContain("html");
  });

  it("falls back to the host when the caller does not name the service", async () => {
    const response = new Response("x".repeat(20), { headers: { "content-length": "20" } });
    Object.defineProperty(response, "url", { value: "https://services.nvd.nist.gov/rest/json/cves/2.0" });
    await expect(readCapped(response, { maxBytes: 5 })).rejects.toThrow(/^services\.nvd\.nist\.gov says/);
  });

  it("has a ceiling far above anything TheySpy actually reads", () => {
    expect(maxResponseBytes).toBeGreaterThan(8 * 1024 * 1024);
  });
});
