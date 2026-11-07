import { generateKeyPairSync, randomBytes, sign, X509Certificate } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

// TLS of its own (docs/PLAN.md M40). TheySpy used to rely on a reverse proxy or Tailscale for
// HTTPS and warn on Activity when reached in the clear. Now it makes itself a certificate on first
// start and serves HTTPS on a second port. Node can sign but not write certificates, and the
// image carries no openssl, so the certificate is written here: X.509 v3, ECDSA P-256 with
// SHA-256, the names and addresses the install answers to in its subjectAltName, ten years, self-
// signed. The fingerprint is shown on Activity so a phone can pin it.

// --- DER ---------------------------------------------------------------------------------------

/** @param {number} tag @param {Buffer} content */
function der(tag, content) {
  const n = content.length;
  const length = n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : n < 0x10000 ? Buffer.from([0x82, n >> 8, n & 0xff]) : Buffer.from([0x83, n >> 16, (n >> 8) & 0xff, n & 0xff]);
  return Buffer.concat([Buffer.from([tag]), length, content]);
}
const sequence = (...parts) => der(0x30, Buffer.concat(parts));
const set = (...parts) => der(0x31, Buffer.concat(parts));
/** A positive INTEGER from bytes (a leading zero keeps the sign bit clear). @param {Buffer} bytes */
const integer = (bytes) => der(0x02, bytes[0] & 0x80 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes);
const utf8 = (text) => der(0x0c, Buffer.from(text, "utf8"));
const octets = (bytes) => der(0x04, bytes);
const boolean = (value) => der(0x01, Buffer.from([value ? 0xff : 0x00]));
const bitString = (bytes) => der(0x03, Buffer.concat([Buffer.from([0]), bytes]));
/** "1.2.840.10045.4.3.2" → OBJECT IDENTIFIER. @param {string} dotted */
function oid(dotted) {
  const [a, b, ...rest] = dotted.split(".").map(Number);
  const bytes = [40 * a + b];
  for (const n of rest) {
    const chunk = [];
    let v = n;
    do { chunk.unshift(v & 0x7f); v = Math.floor(v / 128); } while (v > 0);
    for (let i = 0; i < chunk.length - 1; i++) chunk[i] |= 0x80;
    bytes.push(...chunk);
  }
  return der(0x06, Buffer.from(bytes));
}
/** UTCTime for years to 2049, GeneralizedTime after. @param {Date} date */
function time(date) {
  const iso = date.toISOString().replace(/[-:T]/g, "").slice(0, 14);
  return date.getUTCFullYear() < 2050 ? der(0x17, Buffer.from(`${iso.slice(2)}Z`)) : der(0x18, Buffer.from(`${iso}Z`));
}
const explicit = (n, content) => der(0xa0 | n, content);
const name = (commonName) => sequence(set(sequence(oid("2.5.4.3"), utf8(commonName))));
const ecdsaWithSha256 = sequence(oid("1.2.840.10045.4.3.2"));

/**
 * A self-signed certificate and its key, as PEM, with the SHA-256 fingerprint.
 * @param {{ names?: string[], addresses?: string[], days?: number, now?: () => Date, commonName?: string }} [options]
 */
export function selfSignedCertificate({ names = ["theyspy", "localhost"], addresses = ["127.0.0.1"], days = 3650, now = () => new Date(), commonName = "TheySpy" } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const notBefore = new Date(now().getTime() - 60_000);
  const notAfter = new Date(notBefore.getTime() + days * 86_400_000);
  const serial = randomBytes(16);
  serial[0] &= 0x7f;
  const altNames = sequence(
    ...[...new Set(names)].filter(Boolean).map((n) => der(0x82, Buffer.from(n.toLowerCase(), "ascii"))),
    ...[...new Set(addresses)].map(ipBytes).filter((b) => b).map((b) => der(0x87, /** @type {Buffer} */ (b))),
  );
  const extensions = explicit(3, sequence(
    sequence(oid("2.5.29.19"), boolean(true), octets(sequence(boolean(false)))), // basicConstraints: not a CA
    sequence(oid("2.5.29.17"), octets(altNames)), // subjectAltName
  ));
  const tbs = sequence(
    explicit(0, integer(Buffer.from([2]))), // v3
    integer(serial),
    ecdsaWithSha256,
    name(commonName),
    sequence(time(notBefore), time(notAfter)),
    name(commonName),
    /** @type {Buffer} */ (publicKey.export({ type: "spki", format: "der" })),
    extensions,
  );
  const signature = sign("sha256", tbs, privateKey); // DER-encoded ECDSA signature
  const certificate = sequence(tbs, ecdsaWithSha256, bitString(signature));
  const cert = pem("CERTIFICATE", certificate);
  const key = /** @type {string} */ (privateKey.export({ type: "pkcs8", format: "pem" }));
  return { cert, key, fingerprint: new X509Certificate(cert).fingerprint256, notAfter: notAfter.toISOString(), names: [...new Set(names)], addresses: [...new Set(addresses)] };
}

/** @param {string} ip @returns {Buffer | null} */
function ipBytes(ip) {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return Buffer.from(ip.split(".").map(Number));
  if (!ip.includes(":")) return null;
  const [head, tail = ""] = ip.split("::");
  const parts = head ? head.split(":") : [];
  const rest = tail ? tail.split(":") : [];
  const words = [...parts, ...Array(8 - parts.length - rest.length).fill("0"), ...rest];
  if (words.length !== 8) return null;
  const out = Buffer.alloc(16);
  words.forEach((w, i) => out.writeUInt16BE(parseInt(w || "0", 16), i * 2));
  return out;
}

const pem = (label, bytes) => `-----BEGIN ${label}-----\n${bytes.toString("base64").match(/.{1,64}/g)?.join("\n")}\n-----END ${label}-----\n`;

/** The names and addresses this machine answers to, for the certificate's subjectAltName. */
export function ownNames() {
  const names = ["theyspy", "localhost", os.hostname().toLowerCase()];
  const addresses = ["127.0.0.1", "::1"];
  for (const list of Object.values(os.networkInterfaces())) for (const i of list ?? []) if (!i.internal && (i.family === "IPv4" || i.family === "IPv6")) addresses.push(i.address.replace(/%.*$/, ""));
  return { names, addresses };
}

/**
 * The certificate in `<dataDirectory>/tls/`, written on the first start that has none (and read
 * back after). Returns what the HTTPS server and the Activity screen need.
 * @param {string} dataDirectory @param {{ names?: string[], addresses?: string[], now?: () => Date }} [options]
 */
export function ensureCertificate(dataDirectory, { names, addresses, now = () => new Date() } = {}) {
  const directory = path.join(dataDirectory, "tls");
  const keyFile = path.join(directory, "theyspy.key");
  const certFile = path.join(directory, "theyspy.crt");
  let made = false;
  if (!existsSync(keyFile) || !existsSync(certFile)) {
    const own = ownNames();
    const made_ = selfSignedCertificate({ names: names ?? own.names, addresses: addresses ?? own.addresses, now });
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    writeFileSync(keyFile, made_.key, { mode: 0o600 });
    writeFileSync(certFile, made_.cert, { mode: 0o644 });
    made = true;
  }
  const cert = readFileSync(certFile, "utf8");
  const key = readFileSync(keyFile, "utf8");
  const x = new X509Certificate(cert);
  const alt = String(x.subjectAltName ?? "");
  return {
    cert, key, made, keyFile, certFile,
    fingerprint: x.fingerprint256,
    notAfter: new Date(x.validTo).toISOString(),
    names: [...alt.matchAll(/DNS:([^,]+)/g)].map((m) => m[1]),
    addresses: [...alt.matchAll(/IP Address:([^,]+)/g)].map((m) => m[1]),
  };
}
