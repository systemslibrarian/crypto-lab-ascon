import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { bytesToHex, hexToBytes, utf8ToBytes } from '../src/bytes';
import { asconXof128 } from '../src/xof';

interface XofVector {
  count: number;
  msg: string;
  md: string;
}

function parseXofVectors(): XofVector[] {
  const data = readFileSync(resolve('test/vectors/LWC_XOF_KAT_128_512.txt'), 'utf8');
  const chunks = data.split(/\n\s*\n/g);
  const vectors: XofVector[] = [];

  for (const chunk of chunks) {
    const count = /^Count\s*=\s*(\d+)$/m.exec(chunk);
    const msg = /^Msg\s*=\s*([0-9A-Fa-f]*)$/m.exec(chunk);
    const md = /^MD\s*=\s*([0-9A-Fa-f]*)$/m.exec(chunk);

    if (count && msg && md) {
      vectors.push({
        count: Number.parseInt(count[1], 10),
        msg: msg[1],
        md: md[1],
      });
    }
  }

  return vectors;
}

describe('Ascon-XOF128', () => {
  // 1025 vectors squeezing 64 bytes each takes >5s on a cold run; the default
  // vitest timeout is what fails, not the vectors.
  it('passes all official XOF KAT vectors (512-bit output)', { timeout: 60_000 }, () => {
    const vectors = parseXofVectors();
    expect(vectors.length).toBeGreaterThan(0);

    for (const vector of vectors) {
      const msg = hexToBytes(vector.msg);
      const out = asconXof128(msg, 64);
      expect(bytesToHex(out), `XOF vector Count=${vector.count}`).toBe(vector.md.toLowerCase());
    }
  });

  it('shorter outputs are prefixes of longer outputs (XOF property)', () => {
    const msg = utf8ToBytes('lightweight-crypto');
    const long = asconXof128(msg, 64);
    for (const len of [0, 1, 7, 8, 9, 16, 32, 63]) {
      expect(bytesToHex(asconXof128(msg, len))).toBe(bytesToHex(long.subarray(0, len)));
    }
  });

  it('rejects invalid output lengths', () => {
    expect(() => asconXof128(new Uint8Array(0), -1)).toThrow();
    expect(() => asconXof128(new Uint8Array(0), 1.5)).toThrow();
  });
});
