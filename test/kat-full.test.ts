import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { asconDecrypt, asconEncrypt } from '../src/aead';
import { bytesToHex, concatBytes, hexToBytes } from '../src/bytes';
import { asconHash256 } from '../src/hash';

interface AeadVector {
  count: number;
  key: string;
  nonce: string;
  pt: string;
  ad: string;
  ct: string;
}

interface HashVector {
  count: number;
  msg: string;
  md: string;
}

function parseAeadVectors(): AeadVector[] {
  const data = readFileSync(resolve('test/vectors/LWC_AEAD_KAT_128_128.txt'), 'utf8');
  const chunks = data.split(/\n\s*\n/g);
  const vectors: AeadVector[] = [];

  for (const chunk of chunks) {
    const count = /^Count\s*=\s*(\d+)$/m.exec(chunk);
    const key = /^Key\s*=\s*([0-9A-Fa-f]*)$/m.exec(chunk);
    const nonce = /^Nonce\s*=\s*([0-9A-Fa-f]*)$/m.exec(chunk);
    const pt = /^PT\s*=\s*([0-9A-Fa-f]*)$/m.exec(chunk);
    const ad = /^AD\s*=\s*([0-9A-Fa-f]*)$/m.exec(chunk);
    const ct = /^CT\s*=\s*([0-9A-Fa-f]*)$/m.exec(chunk);

    if (count && key && nonce && pt && ad && ct) {
      vectors.push({
        count: Number.parseInt(count[1], 10),
        key: key[1],
        nonce: nonce[1],
        pt: pt[1],
        ad: ad[1],
        ct: ct[1],
      });
    }
  }

  return vectors;
}

function parseHashVectors(): HashVector[] {
  const data = readFileSync(resolve('test/vectors/LWC_HASH_KAT_128_256.txt'), 'utf8');
  const chunks = data.split(/\n\s*\n/g);
  const vectors: HashVector[] = [];

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

describe('Full official KAT vectors', () => {
  it('passes all Ascon-AEAD128 vectors', () => {
    const vectors = parseAeadVectors();
    expect(vectors.length).toBeGreaterThan(0);

    for (const vector of vectors) {
      const key = hexToBytes(vector.key);
      const nonce = hexToBytes(vector.nonce);
      const ad = hexToBytes(vector.ad);
      const pt = hexToBytes(vector.pt);

      const encrypted = asconEncrypt({ key, nonce, associatedData: ad, plaintext: pt });
      const joined = concatBytes(encrypted.ciphertext, encrypted.tag);
      const expected = vector.ct.toLowerCase();

      expect(bytesToHex(joined), `AEAD vector Count=${vector.count}`).toBe(expected);

      const decrypted = asconDecrypt(key, nonce, ad, encrypted.ciphertext, encrypted.tag);
      expect(decrypted, `AEAD decrypt Count=${vector.count}`).toEqual(pt);
    }
  });

  it('passes all Ascon-Hash256 vectors', () => {
    const vectors = parseHashVectors();
    expect(vectors.length).toBeGreaterThan(0);

    for (const vector of vectors) {
      const msg = hexToBytes(vector.msg);
      const digest = asconHash256(msg);
      expect(bytesToHex(digest), `Hash vector Count=${vector.count}`).toBe(vector.md.toLowerCase());
    }
  });
});
