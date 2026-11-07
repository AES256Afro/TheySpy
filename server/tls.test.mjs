import { createPublicKey, X509Certificate } from "node:crypto";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import { Agent } from "undici";
import { afterEach, describe, expect, it } from "vitest";
import { ensureCertificate, selfSignedCertificate } from "./tls.mjs";

const dirs = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

describe("TLS of its own (M40)", () => {
  it("writes a certificate Node accepts: self-signed, ten years, with the names and addresses given", () => {
    const now = () => new Date("2026-11-07T12:00:00.000Z");
    const made = selfSignedCertificate({ names: ["theyspy", "BigBox", "bigbox.tail6233fa.ts.net"], addresses: ["127.0.0.1", "192.168.8.5", "fd7a:115c:a1e0::1"], now });
    const x = new X509Certificate(made.cert);
    expect(x.subject).toBe("CN=TheySpy");
    expect(x.issuer).toBe("CN=TheySpy");
    expect(x.verify(x.publicKey)).toBe(true);
    expect(x.verify(createPublicKey(made.key))).toBe(true);
    expect(x.subjectAltName).toBe("DNS:theyspy, DNS:bigbox, DNS:bigbox.tail6233fa.ts.net, IP Address:127.0.0.1, IP Address:192.168.8.5, IP Address:FD7A:115C:A1E0:0:0:0:0:1");
    expect(x.checkHost("bigbox")).toBe("bigbox");
    expect(x.checkIP("192.168.8.5")).toBe("192.168.8.5");
    expect(x.ca).toBe(false);
    expect(new Date(x.validFrom).toISOString()).toBe("2026-11-07T11:59:00.000Z");
    expect(new Date(x.validTo).toISOString()).toBe("2036-11-04T11:59:00.000Z");
    expect(made.fingerprint).toBe(x.fingerprint256);
    expect(made.fingerprint).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
  });

  it("serves HTTPS with it, and the fingerprint on the wire is the one shown", async () => {
    const made = selfSignedCertificate({ names: ["localhost"], addresses: ["127.0.0.1"] });
    const server = https.createServer({ key: made.key, cert: made.cert }, (_req, res) => res.end("hello over tls"));
    await new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(null)));
    try {
      const { port } = /** @type {import("node:net").AddressInfo} */ (server.address());
      let seen = null;
      const dispatcher = new Agent({ connect: { rejectUnauthorized: false, checkServerIdentity: () => undefined } });
      const response = await fetch(`https://127.0.0.1:${port}/`, { dispatcher });
      expect(await response.text()).toBe("hello over tls");
      await new Promise((resolve, reject) => {
        const req = https.request({ host: "127.0.0.1", port, rejectUnauthorized: false }, (res) => { seen = /** @type {import("node:tls").TLSSocket} */ (res.socket).getPeerCertificate().fingerprint256; res.resume(); res.on("end", resolve); });
        req.on("error", reject);
        req.end();
      });
      expect(seen).toBe(made.fingerprint);
      await dispatcher.close();
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it("makes the files once, keeps the key to the owner, and reads them back after", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "theyspy-tls-"));
    dirs.push(dir);
    const first = ensureCertificate(dir, { names: ["theyspy"], addresses: ["127.0.0.1"] });
    expect(first.made).toBe(true);
    expect(statSync(first.keyFile).mode & 0o777).toBe(0o600);
    expect(first.names).toEqual(["theyspy"]);
    expect(first.addresses).toEqual(["127.0.0.1"]);
    const again = ensureCertificate(dir);
    expect(again.made).toBe(false);
    expect(again.fingerprint).toBe(first.fingerprint);
    expect(again.cert).toBe(first.cert);
  });
});
