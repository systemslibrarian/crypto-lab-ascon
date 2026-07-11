/**
 * Generates public/og-image.png (1200x630) with zero dependencies.
 *
 * The bit grid in the image is a REAL Ascon state — the permutation below is
 * the same math as src/permutation.ts (duplicated here because this one-off
 * script runs in plain Node, not through the Vite/TS pipeline). Every square
 * in the social preview is an actual bit of p12(p12(IV ‖ 0)).
 *
 * Run: node scripts/generate-og-image.mjs
 */

import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// --- Ascon permutation (mirrors src/permutation.ts) ------------------------

const MASK64 = (1n << 64n) - 1n;
const ROUND_CONSTANTS = [0xf0n, 0xe1n, 0xd2n, 0xc3n, 0xb4n, 0xa5n, 0x96n, 0x87n, 0x78n, 0x69n, 0x5an, 0x4bn];

const rotr64 = (x, n) => ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK64;

function round(s, c) {
  let [x0, x1, x2, x3, x4] = s;
  x2 ^= c;
  x0 ^= x4; x4 ^= x3; x2 ^= x1;
  const t0 = x0 ^ ((~x1 & MASK64) & x2);
  const t1 = x1 ^ ((~x2 & MASK64) & x3);
  const t2 = x2 ^ ((~x3 & MASK64) & x4);
  const t3 = x3 ^ ((~x4 & MASK64) & x0);
  const t4 = x4 ^ ((~x0 & MASK64) & x1);
  x0 = t0; x1 = t1 ^ t0; x2 = ~t2 & MASK64; x3 = t3 ^ t2; x4 = t4;
  x0 ^= x4;
  return [
    (x0 ^ rotr64(x0, 19) ^ rotr64(x0, 28)) & MASK64,
    (x1 ^ rotr64(x1, 61) ^ rotr64(x1, 39)) & MASK64,
    (x2 ^ rotr64(x2, 1) ^ rotr64(x2, 6)) & MASK64,
    (x3 ^ rotr64(x3, 10) ^ rotr64(x3, 17)) & MASK64,
    (x4 ^ rotr64(x4, 7) ^ rotr64(x4, 41)) & MASK64,
  ];
}

const p12 = (s) => ROUND_CONSTANTS.reduce((acc, c) => round(acc, c), s);

// Ascon-AEAD128 IV, keyless: a deterministic, genuinely-diffused state.
const state = p12(p12([0x00001000808c0001n, 0n, 0n, 0n, 0n]));

// --- Tiny 5x7 pixel font ----------------------------------------------------

const FONT = {
  A: ['01110', '10001', '10001', '11111', '10001', '10001', '10001'],
  B: ['11110', '10001', '10001', '11110', '10001', '10001', '11110'],
  C: ['01110', '10001', '10000', '10000', '10000', '10001', '01110'],
  E: ['11111', '10000', '10000', '11110', '10000', '10000', '11111'],
  F: ['11111', '10000', '10000', '11110', '10000', '10000', '10000'],
  G: ['01110', '10001', '10000', '10111', '10001', '10001', '01111'],
  H: ['10001', '10001', '10001', '11111', '10001', '10001', '10001'],
  I: ['01110', '00100', '00100', '00100', '00100', '00100', '01110'],
  L: ['10000', '10000', '10000', '10000', '10000', '10000', '11111'],
  N: ['10001', '11001', '11001', '10101', '10011', '10011', '10001'],
  O: ['01110', '10001', '10001', '10001', '10001', '10001', '01110'],
  P: ['11110', '10001', '10001', '11110', '10000', '10000', '10000'],
  R: ['11110', '10001', '10001', '11110', '10100', '10010', '10001'],
  S: ['01111', '10000', '10000', '01110', '00001', '00001', '11110'],
  T: ['11111', '00100', '00100', '00100', '00100', '00100', '00100'],
  W: ['10001', '10001', '10001', '10101', '10101', '10101', '01010'],
  Y: ['10001', '10001', '01010', '00100', '00100', '00100', '00100'],
  '0': ['01110', '10001', '10011', '10101', '11001', '10001', '01110'],
  '2': ['01110', '10001', '00001', '00010', '00100', '01000', '11111'],
  '3': ['11110', '00001', '00001', '01110', '00001', '00001', '11110'],
  '8': ['01110', '10001', '10001', '01110', '10001', '10001', '01110'],
  '-': ['00000', '00000', '00000', '01110', '00000', '00000', '00000'],
  ' ': ['00000', '00000', '00000', '00000', '00000', '00000', '00000'],
};

// --- Canvas -----------------------------------------------------------------

const W = 1200;
const H = 630;
const px = new Uint8Array(W * H * 3);

function put(x, y, [r, g, b]) {
  if (x < 0 || y < 0 || x >= W || y >= H) return;
  const i = (y * W + x) * 3;
  px[i] = r; px[i + 1] = g; px[i + 2] = b;
}

function rect(x, y, w, h, color) {
  for (let yy = y; yy < y + h; yy += 1) {
    for (let xx = x; xx < x + w; xx += 1) {
      put(xx, yy, color);
    }
  }
}

function textWidth(text, scale) {
  return text.length * 6 * scale - scale;
}

function drawText(text, x, y, scale, color) {
  let cx = x;
  for (const ch of text) {
    const glyph = FONT[ch];
    if (!glyph) throw new Error(`No glyph for "${ch}"`);
    for (let gy = 0; gy < 7; gy += 1) {
      for (let gx = 0; gx < 5; gx += 1) {
        if (glyph[gy][gx] === '1') {
          rect(cx + gx * scale, y + gy * scale, scale, scale, color);
        }
      }
    }
    cx += 6 * scale;
  }
}

// Background: near-black with the demo's two radial accent glows.
const BG = [5, 7, 13];
const RATE = [0, 212, 255];
const CAPACITY = [255, 0, 170];
for (let y = 0; y < H; y += 1) {
  for (let x = 0; x < W; x += 1) {
    const d1 = Math.hypot(x - 180, y + 60) / 500;   // cyan glow, top-left
    const d2 = Math.hypot(x - 1020, y + 30) / 450;  // magenta glow, top-right
    const g1 = Math.max(0, 1 - d1) * 0.22;
    const g2 = Math.max(0, 1 - d2) * 0.2;
    put(x, y, [
      Math.min(255, BG[0] + RATE[0] * g1 + CAPACITY[0] * g2),
      Math.min(255, BG[1] + RATE[1] * g1 + CAPACITY[1] * g2),
      Math.min(255, BG[2] + RATE[2] * g1 + CAPACITY[2] * g2),
    ].map(Math.round));
  }
}

// Title block.
const title = 'ASCON';
const titleScale = 16;
drawText(title, Math.round((W - textWidth(title, titleScale)) / 2), 70, titleScale, [234, 255, 248]);

const sub1 = 'NIST LIGHTWEIGHT CRYPTOGRAPHY';
drawText(sub1, Math.round((W - textWidth(sub1, 5)) / 2), 220, 5, [157, 176, 205]);

const sub2 = 'FIPS SP 800-232';
drawText(sub2, Math.round((W - textWidth(sub2, 4)) / 2), 275, 4, [94, 139, 128]);

// The bit grid: 5 words x 64 bits of the real diffused state.
const BIT = 14;
const GAP = 3;
const gridW = 64 * (BIT + GAP) - GAP;
const gridX = Math.round((W - gridW) / 2);
const gridY = 360;
const DIM = [26, 36, 54];

for (let word = 0; word < 5; word += 1) {
  const onColor = word < 2 ? RATE : CAPACITY;
  for (let b = 63; b >= 0; b -= 1) {
    const on = ((state[word] >> BigInt(b)) & 1n) === 1n;
    const cx = gridX + (63 - b) * (BIT + GAP);
    const cy = gridY + word * (BIT + GAP * 2);
    rect(cx, cy, BIT, BIT, on ? onColor : DIM);
  }
}

const tag = '320 REAL BITS OF SPONGE STATE';
drawText(tag, Math.round((W - textWidth(tag, 3)) / 2), 480, 3, [157, 176, 205]);

// --- PNG encoding -----------------------------------------------------------

const CRC_TABLE = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k += 1) {
    c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  return c >>> 0;
});

function crc32(bytes) {
  let c = 0xffffffff;
  for (const byte of bytes) {
    c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, 'ascii');
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
}

const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(W, 0);
ihdr.writeUInt32BE(H, 4);
ihdr[8] = 8;  // bit depth
ihdr[9] = 2;  // color type: truecolor RGB

const raw = Buffer.alloc(H * (1 + W * 3));
for (let y = 0; y < H; y += 1) {
  const rowStart = y * (1 + W * 3);
  raw[rowStart] = 0; // filter: none
  Buffer.from(px.buffer, y * W * 3, W * 3).copy(raw, rowStart + 1);
}

const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk('IHDR', ihdr),
  chunk('IDAT', deflateSync(raw, { level: 9 })),
  chunk('IEND', Buffer.alloc(0)),
]);

const outPath = resolve(join(dirname(fileURLToPath(import.meta.url)), '..', 'public', 'og-image.png'));
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, png);
console.log(`Wrote ${outPath} (${png.length} bytes, ${W}x${H})`);
