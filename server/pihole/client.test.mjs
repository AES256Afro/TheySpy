import { describe, expect, it } from "vitest";
import { fakePihole } from "../test-helpers.mjs";
import { createPiholeClient } from "./client.mjs";

describe("Pi-hole client", () => {
  it("retries a write while Pi-hole's gravity database is busy, and gives up on other errors", async () => {
    const pihole = fakePihole();
    let busy = 2;
    const fetchImpl = async (url, init) => {
      if (init.method === "POST" && String(url).endsWith("/api/groups") && busy > 0) {
        busy -= 1;
        return new Response(JSON.stringify({ error: { key: "database_error", message: "Could not add to gravity database" } }), { status: 400, headers: { "content-type": "application/json" } });
      }
      return pihole.fetchImpl(url, init);
    };
    const client = createPiholeClient({ url: "http://192.0.2.5", password: "pihole-pass", fetchImpl, retryDelayMs: 1 });
    const group = await client.session((c) => c.addGroup("TheySpy 192.168.1.42", "test"));
    expect(group).toMatchObject({ name: "TheySpy 192.168.1.42" });
    expect(busy).toBe(0);

    const refusing = createPiholeClient({ url: "http://192.0.2.5", password: "wrong", fetchImpl: pihole.fetchImpl, retryDelayMs: 1 });
    await expect(refusing.login()).rejects.toThrow(/refused the password/);
  });
});
