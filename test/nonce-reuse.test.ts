import { describe, expect, it } from 'vitest';

import { asconEncrypt } from '../src/aead';
import { hexToBytes, utf8ToBytes } from '../src/bytes';
import { flipNoncePacketBit, nonceReusePrefixLength, verifyNoncePacket } from '../src/nonce-reuse';

const KEY = hexToBytes('000102030405060708090a0b0c0d0e0f');
const NONCE = hexToBytes('101112131415161718191a1b1c1d1e1f');
const OTHER_NONCE = hexToBytes('202122232425262728292a2b2c2d2e2f');

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
  const none = new Uint8Array(0);
  const c1 = asconEncrypt({ key: KEY, nonce: NONCE, associatedData: none, plaintext: p1 }).ciphertext;
  const c2 = asconEncrypt({ key: KEY, nonce: NONCE, associatedData: none, plaintext: p2 }).ciphertext;
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
    // This fixed fixture demonstrates divergence after the differing block.
    // Later accidental byte matches do not extend the guaranteed prefix.
    expect(cxor.subarray(16)).not.toEqual(pxor.subarray(16));
  });

  it.each([
    ['', 'message', 0],
    ['same', 'same', 4],
    ['short', 'short plus more', 5],
    ['A'.repeat(40), `B${'A'.repeat(39)}`, 16],
    ['A'.repeat(40), `${'A'.repeat(16)}B${'A'.repeat(23)}`, 32],
  ])('counts only the common guaranteed prefix for %j and %j', (first, second, expected) => {
    const p1 = utf8ToBytes(first);
    const p2 = utf8ToBytes(second);
    const { cxor, pxor } = encryptPair(p1, p2);
    expect(nonceReusePrefixLength(p1, p2)).toBe(expected);
    expect(cxor.subarray(0, expected)).toEqual(pxor.subarray(0, expected));
  });
});

describe('measured recipient checks in the nonce-reuse lesson', () => {
  it.each([NONCE, OTHER_NONCE])('verifies both honest packets, with either repeated or fresh nonces', (secondNonce) => {
    for (const [nonce, message] of [
      [NONCE, 'Meter 4471: send $0100 to Alice'],
      [secondNonce, 'Meter 4471: send $9999 to Chuck 🔐'],
    ] as const) {
      const plaintext = utf8ToBytes(message);
      const packet = asconEncrypt({ key: KEY, nonce, associatedData: new Uint8Array(0), plaintext });
      const result = verifyNoncePacket(KEY, nonce, packet, plaintext);
      expect(result).toEqual({ verified: true, matchesMessage: true, plaintext });
    }
  });

  it.each(['ciphertext', 'tag'] as const)('rejects a one-bit %s change without returning expected or unverified bytes', (target) => {
    const plaintext = utf8ToBytes('Recipient output must remain empty on failure.');
    const packet = asconEncrypt({ key: KEY, nonce: NONCE, associatedData: new Uint8Array(0), plaintext });
    const originalCiphertext = packet.ciphertext.slice();
    const originalTag = packet.tag.slice();
    const changed = flipNoncePacketBit(packet, target);
    expect(verifyNoncePacket(KEY, NONCE, changed, plaintext)).toEqual({
      verified: false, matchesMessage: false, plaintext: null,
    });
    expect(packet.ciphertext).toEqual(originalCiphertext);
    expect(packet.tag).toEqual(originalTag);
    expect(verifyNoncePacket(KEY, NONCE, packet, plaintext).matchesMessage).toBe(true);
  });

  it('treats an accepted empty message separately from rejected decryption', () => {
    const plaintext = new Uint8Array(0);
    const packet = asconEncrypt({ key: KEY, nonce: NONCE, associatedData: plaintext, plaintext });
    expect(verifyNoncePacket(KEY, NONCE, packet, plaintext)).toEqual({
      verified: true, matchesMessage: true, plaintext,
    });
    expect(verifyNoncePacket(KEY, NONCE, flipNoncePacketBit(packet, 'tag'), plaintext)).toEqual({
      verified: false, matchesMessage: false, plaintext: null,
    });
    expect(() => flipNoncePacketBit(packet, 'ciphertext')).toThrow('no ciphertext byte');
  });

  it('does not substitute the expected message for the authenticated decrypted bytes', () => {
    const plaintext = utf8ToBytes('The actual message');
    const packet = asconEncrypt({ key: KEY, nonce: NONCE, associatedData: new Uint8Array(0), plaintext });
    expect(verifyNoncePacket(KEY, NONCE, packet, utf8ToBytes('A different expected message'))).toEqual({
      verified: true, matchesMessage: false, plaintext,
    });
  });
});
