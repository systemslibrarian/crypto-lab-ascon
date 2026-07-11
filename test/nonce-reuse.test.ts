import { describe, expect, it } from 'vitest';

import { asconEncrypt } from '../src/aead';
import { randomBytes, utf8ToBytes } from '../src/bytes';

/**
 * The nonce-reuse exhibit claims: under a reused key+nonce, C1^C2 = P1^P2
 * through the 16-byte block containing the first plaintext difference, and
 * the keystreams diverge after it (duplex feedback). Pin that down here so
 * the exhibit's teaching text can never drift from the implementation.
 */

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const n = Math.min(a.length, b.length);
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 1) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

function encryptPair(p1: Uint8Array, p2: Uint8Array): { cxor: Uint8Array; pxor: Uint8Array } {
  const key = randomBytes(16);
  const nonce = randomBytes(16);
  const none = new Uint8Array(0);
  const c1 = asconEncrypt({ key, nonce, associatedData: none, plaintext: p1 }).ciphertext;
  const c2 = asconEncrypt({ key, nonce, associatedData: none, plaintext: p2 }).ciphertext;
  return { cxor: xorBytes(c1, c2), pxor: xorBytes(p1, p2) };
}

describe('nonce reuse leak structure (duplex sponge)', () => {
  it('leaks the full XOR when messages differ only after the first block', () => {
    // Identical first 16 bytes, difference in block 2.
    const p1 = utf8ToBytes('Meter 4471: send $0100 to Alice');
    const p2 = utf8ToBytes('Meter 4471: send $9999 to Chuck');
    const { cxor, pxor } = encryptPair(p1, p2);
    expect(cxor).toEqual(pxor);
  });

  it('leaks exactly the first block, then diverges, when messages differ in block 1', () => {
    const p1 = utf8ToBytes('AAAA differs here + more trailing text to fill block two');
    const p2 = utf8ToBytes('BBBB differs here + more trailing text to fill block two');
    const { cxor, pxor } = encryptPair(p1, p2);

    // Block 1 keystream depends only on key/nonce, so the first 16 bytes leak.
    expect(cxor.subarray(0, 16)).toEqual(pxor.subarray(0, 16));
    // After the differing block the states diverge; identical trailing
    // plaintext would need identical keystreams to XOR to zero, and a match
    // across the remaining bytes is a ~2^-320 accident.
    expect(cxor.subarray(16)).not.toEqual(pxor.subarray(16));
  });
});
