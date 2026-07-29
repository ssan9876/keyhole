// Generates the PWA icons as PNG files under apps/web/public/.
//
// Why generated, not fetched: Keyhole serves under a strict CSP
// (default-src 'self') and the whole PWA plan turns on putting nothing on the
// device that did not come from the app's own origin. These icons are produced
// locally from a shape function — no network, no binary blob of unknown
// provenance checked into the tree. Re-run with `node scripts/generate-icons.mjs`.
//
// The encoder is hand-rolled on Node's built-in zlib so this needs no image
// dependency (see keyhole-toolchain-quirks: new deps are friction here).
//
// The glyph: a plain keyhole — a circular bow over a tapered blade — in the
// Mono dark-mode ink (#f2f2ef) on the Mono dark ground (#111110). It is sized
// inside the maskable safe zone (the centre 80% circle a launcher may crop to),
// so no part of the keyhole is clipped on a round, squircle, or square mask.

import { deflateSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const publicDir = join(here, "..", "public");

// Mono ground and ink, dark set (tokens.css). The manifest's theme/background
// use this same dark ground, so the splash and the icon field are one colour.
const GROUND = [0x11, 0x11, 0x10];
const INK = [0xf2, 0xf2, 0xef];

// CRC-32 (PNG uses the standard IEEE polynomial).
const crcTable = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([Buffer.from(type, "latin1"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}

function encodePng(width, height, rgba) {
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // colour type: RGBA
  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0; // filter: none
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, y * stride + stride);
  }
  const idat = deflateSync(raw, { level: 9 });
  return Buffer.concat([
    sig,
    chunk("IHDR", ihdr),
    chunk("IDAT", idat),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

// Coverage of the keyhole glyph at a normalised point (0..1). A circular bow
// centred high, and a blade that tapers wider toward the bottom.
function inGlyph(nx, ny) {
  const bowX = 0.5;
  const bowY = 0.4;
  const bowR = 0.135;
  if ((nx - bowX) ** 2 + (ny - bowY) ** 2 <= bowR ** 2) return true;

  const bladeTop = 0.4;
  const bladeBottom = 0.66;
  if (ny >= bladeTop && ny <= bladeBottom) {
    const t = (ny - bladeTop) / (bladeBottom - bladeTop);
    const halfWidth = 0.05 + (0.11 - 0.05) * t; // narrow under the bow, wider at the foot
    if (Math.abs(nx - bowX) <= halfWidth) return true;
  }
  return false;
}

// Render with 4x4 supersampling per pixel so the curved edges are anti-aliased
// rather than stair-stepped.
function renderIcon(size) {
  const rgba = Buffer.alloc(size * size * 4);
  const sub = 4;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let hits = 0;
      for (let sy = 0; sy < sub; sy++) {
        for (let sx = 0; sx < sub; sx++) {
          const nx = (x + (sx + 0.5) / sub) / size;
          const ny = (y + (sy + 0.5) / sub) / size;
          if (inGlyph(nx, ny)) hits++;
        }
      }
      const cov = hits / (sub * sub);
      const o = (y * size + x) * 4;
      rgba[o] = Math.round(GROUND[0] + (INK[0] - GROUND[0]) * cov);
      rgba[o + 1] = Math.round(GROUND[1] + (INK[1] - GROUND[1]) * cov);
      rgba[o + 2] = Math.round(GROUND[2] + (INK[2] - GROUND[2]) * cov);
      rgba[o + 3] = 255; // opaque: a maskable icon must fill its whole box
    }
  }
  return rgba;
}

mkdirSync(publicDir, { recursive: true });
for (const [name, size] of [
  ["icon-192.png", 192],
  ["icon-512.png", 512],
  ["apple-touch-icon.png", 180],
]) {
  const png = encodePng(size, size, renderIcon(size));
  writeFileSync(join(publicDir, name), png);
  console.log(`wrote ${name} (${size}x${size}, ${png.length} bytes)`);
}
