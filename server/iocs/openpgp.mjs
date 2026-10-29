import { createHash, createPublicKey, verify } from "node:crypto";

// Just enough OpenPGP (RFC 4880 / RFC 9580) to check a detached Ed25519 signature: zero-breach signs
// each release's SHA256SUMS.txt with ArchiveGenocide's Ed25519 key, and that manifest lists the
// indicator file's hash. Anything outside that shape (other algorithms, partial lengths, v5/v6
// packets) is refused rather than half-understood.

export class SignatureError extends Error {}

/** Strips ASCII armour; checks the CRC-24 when present. */
export function dearmor(text) {
  const lines = text.replace(/\r/g, "").split("\n");
  const begin = lines.findIndex((line) => /^-----BEGIN PGP [A-Z ]+-----$/.test(line));
  const end = lines.findIndex((line, i) => i > begin && /^-----END PGP [A-Z ]+-----$/.test(line));
  if (begin < 0 || end < 0) throw new SignatureError("not ASCII-armoured OpenPGP data");
  let body = lines.slice(begin + 1, end);
  const blank = body.findIndex((line) => line.trim() === "");
  if (blank >= 0) body = body.slice(blank + 1); // armour headers end at the first blank line
  let checksum = null;
  if (body.length && body[body.length - 1].startsWith("=")) checksum = body.pop().slice(1);
  const data = Buffer.from(body.join(""), "base64");
  if (checksum !== null && crc24(data) !== Buffer.from(checksum, "base64").readUIntBE(0, 3)) throw new SignatureError("armour checksum does not match");
  return data;
}

function crc24(data) {
  let crc = 0xb704ce;
  for (const byte of data) {
    crc ^= byte << 16;
    for (let i = 0; i < 8; i += 1) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x1864cfb;
    }
  }
  return crc & 0xffffff;
}

/** @returns {{ tag: number, body: Buffer }[]} */
export function readPackets(data) {
  const packets = [];
  let at = 0;
  while (at < data.length) {
    const first = data[at];
    if (!(first & 0x80)) throw new SignatureError("not an OpenPGP packet");
    let tag;
    let length;
    if (first & 0x40) {
      tag = first & 0x3f;
      const o1 = data[at + 1];
      if (o1 < 192) { length = o1; at += 2; }
      else if (o1 < 224) { length = ((o1 - 192) << 8) + data[at + 2] + 192; at += 3; }
      else if (o1 === 255) { length = data.readUInt32BE(at + 2); at += 6; }
      else throw new SignatureError("partial-length packets are not supported");
    } else {
      tag = (first >> 2) & 0x0f;
      const kind = first & 0x03;
      if (kind === 0) { length = data[at + 1]; at += 2; }
      else if (kind === 1) { length = data.readUInt16BE(at + 1); at += 3; }
      else if (kind === 2) { length = data.readUInt32BE(at + 1); at += 5; }
      else throw new SignatureError("indeterminate-length packets are not supported");
    }
    if (at + length > data.length) throw new SignatureError("truncated packet");
    packets.push({ tag, body: data.subarray(at, at + length) });
    at += length;
  }
  return packets;
}

const ed25519Oid = Buffer.from("2b06010401da470f01", "hex");
const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");

function readMpi(buffer, at) {
  const bits = buffer.readUInt16BE(at);
  const bytes = Math.ceil(bits / 8);
  return { value: buffer.subarray(at + 2, at + 2 + bytes), next: at + 2 + bytes };
}

/**
 * The primary public key from an armoured key block: its v4 fingerprint and a Node key object.
 * @param {string} armored
 */
export function readPublicKey(armored) {
  const packet = readPackets(dearmor(armored)).find((p) => p.tag === 6);
  if (!packet) throw new SignatureError("no public key packet");
  const body = packet.body;
  if (body[0] !== 4) throw new SignatureError(`public key version ${body[0]} is not supported`);
  const algorithm = body[5];
  if (algorithm !== 22) throw new SignatureError(`public key algorithm ${algorithm} is not supported (expected EdDSA)`);
  const oidLength = body[6];
  if (!body.subarray(7, 7 + oidLength).equals(ed25519Oid)) throw new SignatureError("only Ed25519 keys are supported");
  const { value: point } = readMpi(body, 7 + oidLength);
  if (point.length !== 33 || point[0] !== 0x40) throw new SignatureError("malformed Ed25519 public point");
  const lengthPrefix = Buffer.alloc(3);
  lengthPrefix[0] = 0x99;
  lengthPrefix.writeUInt16BE(body.length, 1);
  const fingerprint = createHash("sha1").update(lengthPrefix).update(body).digest("hex").toUpperCase();
  const key = createPublicKey({ key: Buffer.concat([spkiPrefix, point.subarray(1)]), format: "der", type: "spki" });
  return { fingerprint, key };
}

const hashNames = { 8: "sha256", 9: "sha384", 10: "sha512", 11: "sha224" };

function parseSubpackets(area) {
  const out = [];
  let at = 0;
  while (at < area.length) {
    let length = area[at];
    if (length < 192) at += 1;
    else if (length < 255) { length = ((length - 192) << 8) + area[at + 1] + 192; at += 2; }
    else { length = area.readUInt32BE(at + 1); at += 5; }
    out.push({ type: area[at] & 0x7f, data: area.subarray(at + 1, at + length) });
    at += length;
  }
  return out;
}

/**
 * Verifies a detached, armoured signature over `data` with `publicKey`.
 * @param {Buffer} data the signed file's bytes
 * @param {string} armoredSignature
 * @param {ReturnType<typeof readPublicKey>} publicKey
 * @returns {{ signedAt: Date, issuer: string }}
 */
export function verifyDetached(data, armoredSignature, publicKey) {
  const packet = readPackets(dearmor(armoredSignature)).find((p) => p.tag === 2);
  if (!packet) throw new SignatureError("no signature packet");
  const sig = packet.body;
  if (sig[0] !== 4) throw new SignatureError(`signature version ${sig[0]} is not supported`);
  const [, type, algorithm, hashAlgorithm] = sig;
  if (type !== 0x00 && type !== 0x01) throw new SignatureError(`signature type ${type} is not a document signature`);
  if (algorithm !== 22) throw new SignatureError(`signature algorithm ${algorithm} is not supported (expected EdDSA)`);
  const hashName = hashNames[hashAlgorithm];
  if (!hashName) throw new SignatureError(`hash algorithm ${hashAlgorithm} is not supported`);
  const hashedLength = sig.readUInt16BE(4);
  const hashedArea = sig.subarray(6, 6 + hashedLength);
  const unhashedLength = sig.readUInt16BE(6 + hashedLength);
  const unhashedArea = sig.subarray(8 + hashedLength, 8 + hashedLength + unhashedLength);
  let at = 8 + hashedLength + unhashedLength;
  const left16 = sig.subarray(at, at + 2);
  const r = readMpi(sig, at + 2);
  const s = readMpi(sig, r.next);

  const subpackets = [...parseSubpackets(hashedArea), ...parseSubpackets(unhashedArea)];
  const created = subpackets.find((p) => p.type === 2);
  const issuerFingerprint = subpackets.find((p) => p.type === 33);
  const issuerKeyId = subpackets.find((p) => p.type === 16);
  const issuer = issuerFingerprint ? issuerFingerprint.data.subarray(1).toString("hex").toUpperCase() : issuerKeyId?.data.toString("hex").toUpperCase() ?? "";
  if (!issuer || !publicKey.fingerprint.endsWith(issuer)) throw new SignatureError(`signed by ${issuer || "an unnamed key"}, not ${publicKey.fingerprint}`);

  // Text signatures hash the document with CRLF line endings.
  const document = type === 0x01 ? Buffer.from(data.toString("utf8").replace(/\r?\n/g, "\r\n"), "utf8") : data;
  const trailer = Buffer.alloc(6);
  trailer[0] = 0x04;
  trailer[1] = 0xff;
  trailer.writeUInt32BE(6 + hashedLength, 2);
  const digest = createHash(hashName).update(document).update(sig.subarray(0, 6 + hashedLength)).update(trailer).digest();
  if (!digest.subarray(0, 2).equals(left16)) throw new SignatureError("signature does not match these bytes");
  const pad = (value) => Buffer.concat([Buffer.alloc(Math.max(0, 32 - value.length)), value]);
  if (!verify(null, digest, publicKey.key, Buffer.concat([pad(r.value), pad(s.value)]))) throw new SignatureError("signature does not match these bytes");
  return { signedAt: new Date((created ? created.data.readUInt32BE(0) : 0) * 1000), issuer };
}

/** Parses a `sha256sum`-style manifest into file name → lowercase hex digest. */
export function parseChecksums(text) {
  const out = new Map();
  for (const line of text.split(/\r?\n/)) {
    const match = /^([0-9a-fA-F]{64}) [ *]?(.+)$/.exec(line.trim());
    if (match) out.set(match[2].trim(), match[1].toLowerCase());
  }
  return out;
}
