// The home-screen icons (docs/PLAN.md M36): the favicon's badge (a blue-to-violet gradient on a
// rounded square, a white ring and a dot) drawn as PNGs, because a phone's home screen does not
// take an SVG. Run `node scripts/make-icons.mjs` after changing public/favicon.svg; the PNGs are
// committed, and src/manifest.test.ts checks they are what the manifest says.
import { writeFileSync } from "node:fs";
import { deflateSync } from "node:zlib";

const crcTable = new Uint32Array(256).map((_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc32 = (bytes) => { let c = 0xffffffff; for (const b of bytes) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
function chunk(type, data) {
  const length = Buffer.alloc(4); length.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "latin1"), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body));
  return Buffer.concat([length, body, crc]);
}

/** @param {number} size */
export function iconPng(size) {
  const s = size / 32; // the favicon's 32-unit viewBox
  const rows = [];
  const mix = (a, b, t) => Math.round(a + (b - a) * t);
  for (let y = 0; y < size; y++) {
    const row = Buffer.alloc(1 + size * 4);
    for (let x = 0; x < size; x++) {
      const u = (x + 0.5) / s; const v = (y + 0.5) / s; // in viewBox units
      // The rounded square, radius 8: outside it the pixel is transparent.
      const r = 8; const cx = Math.min(Math.max(u, r), 32 - r); const cy = Math.min(Math.max(v, r), 32 - r);
      const outside = Math.hypot(u - cx, v - cy) - r; // signed distance to the rounded edge
      const cover = Math.min(1, Math.max(0, 0.5 - outside * s * 0.8)); // soft edge, under a pixel
      const t = Math.min(1, Math.max(0, (u + v) / 64)); // gradient from top-left #39c6ff to bottom-right #7c5cff
      let [R, G, B] = [mix(0x39, 0x7c, t), mix(0xc6, 0x5c, t), mix(0xff, 0xff, t)];
      const d = Math.hypot(u - 16, v - 16);
      const ring = Math.max(0, 1 - Math.abs(d - 7) / 1.25 * 0.9); // stroke 2.5 wide
      const dot = d <= 2.5 ? 1 : Math.max(0, 1 - (d - 2.5) * s * 0.8);
      const white = Math.min(1, Math.max(ring > 0.1 ? 1 : 0, dot));
      if (white) { R = mix(R, 255, white); G = mix(G, 255, white); B = mix(B, 255, white); }
      row[1 + x * 4] = R; row[2 + x * 4] = G; row[3 + x * 4] = B; row[4 + x * 4] = Math.round(cover * 255);
    }
    rows.push(row);
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0); header.writeUInt32BE(size, 4); header[8] = 8; header[9] = 6; // 8-bit RGBA
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", header), chunk("IDAT", deflateSync(Buffer.concat(rows))), chunk("IEND", Buffer.alloc(0))]);
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/^.*\//, ""))) {
  for (const [file, size] of /** @type {[string, number][]} */ ([["public/icon-192.png", 192], ["public/icon-512.png", 512], ["public/apple-touch-icon.png", 180]])) {
    writeFileSync(new URL(`../${file}`, import.meta.url), iconPng(size));
    console.log(`${file}: ${size}×${size}`);
  }
}
