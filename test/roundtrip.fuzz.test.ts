import { describe, expect, it } from 'vitest';

import {
  absorbAD,
  asconDecrypt,
  asconEncrypt,
  encryptPlaintext,
  finalize,
  initialize,
} from '../src/aead';
import { bytesToHex, randomBytes, secureRandomInt } from '../src/bytes';

function randomData(length: number): Uint8Array {
  return length === 0 ? new Uint8Array() : randomBytes(length);
}

describe('AEAD round-trip — randomized', () => {
  it('decrypt(encrypt(x)) === x for 200 random messages of varied length', () => {
    for (let iteration = 0; iteration < 200; iteration += 1) {
      const key = randomBytes(16);
      const nonce = randomBytes(16);
      const ad = randomData(secureRandomInt(40));
      const pt = randomData(secureRandomInt(40));

      const { ciphertext, tag } = asconEncrypt({ key, nonce, associatedData: ad, plaintext: pt });
      expect(ciphertext.length).toBe(pt.length);

      const decrypted = asconDecrypt(key, nonce, ad, ciphertext, tag);
      expect(decrypted, `round-trip iteration ${iteration}`).toEqual(pt);
    }
  });

  it('rejects any single-bit tamper of ciphertext or tag', () => {
    for (let iteration = 0; iteration < 100; iteration += 1) {
      const key = randomBytes(16);
      const nonce = randomBytes(16);
      const ad = randomData(secureRandomInt(24));
      const pt = randomData(1 + secureRandomInt(32)); // non-empty so ciphertext exists

      const { ciphertext, tag } = asconEncrypt({ key, nonce, associatedData: ad, plaintext: pt });

      const badCt = ciphertext.slice();
      badCt[secureRandomInt(badCt.length)] ^= 1 << secureRandomInt(8);
      expect(asconDecrypt(key, nonce, ad, badCt, tag)).toBeNull();

      const badTag = tag.slice();
      badTag[secureRandomInt(badTag.length)] ^= 1 << secureRandomInt(8);
      expect(asconDecrypt(key, nonce, ad, ciphertext, badTag)).toBeNull();

      // Wrong associated data must also fail authentication.
      const badAd = ad.length > 0 ? ad.slice() : new Uint8Array([0]);
      badAd[secureRandomInt(badAd.length)] ^= 0x01;
      expect(asconDecrypt(key, nonce, badAd, ciphertext, tag)).toBeNull();
    }
  });
});

describe('AEAD block-boundary edge lengths', () => {
  // RATE_BYTES is 16, so lengths around 0/15/16/17/31/32/33 exercise the
  // full-block loop, the empty tail, and partial-block padding paths.
  it('round-trips for every plaintext length 0..40 (with and without AD)', () => {
    const key = randomBytes(16);
    const nonce = randomBytes(16);

    for (let length = 0; length <= 40; length += 1) {
      const pt = randomData(length);

      for (const ad of [new Uint8Array(), randomData(length)]) {
        const { ciphertext, tag } = asconEncrypt({ key, nonce, associatedData: ad, plaintext: pt });
        const decrypted = asconDecrypt(key, nonce, ad, ciphertext, tag);
        expect(decrypted, `len=${length} adLen=${ad.length}`).toEqual(pt);
      }
    }
  });
});

describe('exported step functions compose into asconEncrypt', () => {
  it('initialize -> absorbAD -> encryptPlaintext -> finalize equals the public API', () => {
    for (let iteration = 0; iteration < 50; iteration += 1) {
      const key = randomBytes(16);
      const nonce = randomBytes(16);
      const ad = randomData(secureRandomInt(40));
      const pt = randomData(secureRandomInt(40));

      let state = initialize(key, nonce);
      state = absorbAD(state, ad);
      const enc = encryptPlaintext(state, pt);
      const fin = finalize(enc.state, key);

      const canonical = asconEncrypt({ key, nonce, associatedData: ad, plaintext: pt });

      expect(bytesToHex(enc.ciphertext)).toBe(bytesToHex(canonical.ciphertext));
      expect(bytesToHex(fin.tag)).toBe(bytesToHex(canonical.tag));
    }
  });
});
