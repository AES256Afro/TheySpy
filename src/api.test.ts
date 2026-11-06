import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, safeLink, waitForJob, whenSessionEnds } from "./api.ts";

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
  whenSessionEnds(() => {});
});

/** Answers every call with the same status and body. */
function answering(status: number, body: unknown = {}) {
  const calls: string[] = [];
  globalThis.fetch = (async (url: string) => {
    calls.push(String(url));
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return calls;
}

describe("the browser's API calls", () => {
  it("tells the shell when the session has gone, so it can show sign-in again", async () => {
    answering(401, { error: "Sign in first" });
    let ended = 0;
    whenSessionEnds(() => { ended += 1; });
    await expect(api("GET", "/api/fleet")).rejects.toThrow("Sign in first");
    expect(ended).toBe(1);
    // Every screen's call says so, not just the first.
    await expect(api("GET", "/api/cves")).rejects.toBeInstanceOf(ApiError);
    expect(ended).toBe(2);
  });

  it("does not mistake a wrong password for an ended session", async () => {
    answering(401, { error: "That password is not right." });
    let ended = 0;
    whenSessionEnds(() => { ended += 1; });
    await expect(api("POST", "/api/login", { password: "no" })).rejects.toThrow("That password is not right.");
    expect(ended).toBe(0);
  });

  it("says nothing when a call works, or fails some other way", async () => {
    let ended = 0;
    whenSessionEnds(() => { ended += 1; });
    answering(200, { ok: true });
    expect(await api("GET", "/api/session")).toEqual({ ok: true });
    answering(500, { error: "Something went wrong on the server." });
    await expect(api("GET", "/api/fleet")).rejects.toThrow(/went wrong/);
    expect(ended).toBe(0);
  });

  it("sends the CSRF header on anything that changes something, and not on a GET", async () => {
    const sent: RequestInit[] = [];
    globalThis.fetch = (async (_url: string, init: RequestInit) => {
      sent.push(init);
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch;
    await api("GET", "/api/jobs");
    await api("POST", "/api/jobs", { kind: "noop" });
    expect((sent[0].headers as Record<string, string>)["x-theyspy"]).toBeUndefined();
    expect((sent[1].headers as Record<string, string>)["x-theyspy"]).toBe("1");
  });

  it("stops watching a job when the screen that asked has gone", async () => {
    vi.useFakeTimers();
    try {
      const calls = answering(200, { job: { id: 1, status: "running" } });
      const stopped = { aborted: false };
      const watching = waitForJob(1, stopped).catch((error: Error) => error.message);
      await vi.advanceTimersByTimeAsync(2_000);
      const sofar = calls.length;
      expect(sofar).toBeGreaterThan(1);
      stopped.aborted = true;
      await vi.advanceTimersByTimeAsync(5_000);
      expect(await watching).toMatch(/Stopped watching/);
      // Nothing after it was told to stop.
      expect(calls.length).toBeLessThanOrEqual(sofar + 1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("only lets an http(s) link from somewhere else reach an href", () => {
    expect(safeLink("https://github.com/hagezi/dns-blocklists")).toBe("https://github.com/hagezi/dns-blocklists");
    expect(safeLink("http://firebog.net")).toBe("http://firebog.net");
    // A blocklist directory or a research feed is third-party data; these are not links.
    for (const bad of ["javascript:alert(document.cookie)", "JaVaScRiPt:alert(1)", "data:text/html,<script>1</script>", "vbscript:x", "file:///etc/passwd", "not a url", "", null, undefined, 42]) {
      expect(safeLink(bad), String(bad)).toBeNull();
    }
  });
});
