import { describe, expect, it } from 'vitest';

import { bytesToHex, hammingDistance, hexToBytes, utf8ToBytes } from '../src/bytes';
import { asconHash256 } from '../src/hash';

describe('Ascon-Hash256', () => {
  it('matches known-answer vector for empty message', () => {
    // KAT (ascon-c LWC_HASH_KAT_128_256.txt, Count = 1)
    expect(bytesToHex(asconHash256(new Uint8Array()))).toBe(
      '0b3be5850f2f6b98caf29f8fdea89b64a1fa70aa249b8f839bd53baa304d92b2',
    );
  });

  it('matches known-answer vector for 1-byte message', () => {
    // KAT (ascon-c LWC_HASH_KAT_128_256.txt, Count = 2, Msg = 00)
    expect(bytesToHex(asconHash256(hexToBytes('00')))).toBe(
      '0728621035af3ed2bca03bf6fde900f9456f5330e4b5ee23e7f6a1e70291bc80',
    );
  });

  it('shows avalanche behavior near 50% bit flips', () => {
    const h1 = asconHash256(utf8ToBytes('Hello'));
    const h2 = asconHash256(utf8ToBytes('Iello'));
    const distance = hammingDistance(h1, h2);

    expect(distance).toBeGreaterThanOrEqual(100);
    expect(distance).toBeLessThanOrEqual(156);
  });
});
