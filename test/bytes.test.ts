import { describe, expect, it } from 'vitest';

import { constantTimeEqual } from '../src/aead';
import {
  bytesToHex,
  hammingDistance,
  hexToBytes,
  load64,
  popcount64,
  secureRandomInt,
  store64,
} from '../src/bytes';

describe('byte utilities', () => {
  it('round-trips load64/store64 in little-endian order', () => {
    const bytes = hexToBytes('0123456789abcdef');
    // Ascon loads words little-endian: byte 0 is the least-significant byte.
    expect(load64(bytes, 0)).toBe(0xefcdab8967452301n);
    expect(bytesToHex(store64(load64(bytes, 0)))).toBe('0123456789abcdef');
  });

  it('store64 masks to 64 bits and ignores overflow', () => {
    expect(bytesToHex(store64((1n << 64n) | 0xffn))).toBe('ff00000000000000');
  });

  it('parses and rejects hex strings', () => {
    expect(bytesToHex(hexToBytes('0xDEADbeef'))).toBe('deadbeef');
    expect(hexToBytes('')).toEqual(new Uint8Array());
    expect(() => hexToBytes('abc')).toThrow(/Invalid hex/);
    expect(() => hexToBytes('zz')).toThrow(/Invalid hex/);
  });

  it('counts set bits with popcount64', () => {
    expect(popcount64(0n)).toBe(0);
    expect(popcount64((1n << 64n) - 1n)).toBe(64);
    expect(popcount64(0xff00n)).toBe(8);
  });

  it('measures Hamming distance between equal-length buffers', () => {
    expect(hammingDistance(hexToBytes('00'), hexToBytes('ff'))).toBe(8);
    expect(hammingDistance(hexToBytes('0f0f'), hexToBytes('0f0f'))).toBe(0);
    expect(() => hammingDistance(new Uint8Array(1), new Uint8Array(2))).toThrow();
  });

  it('constantTimeEqual reflects equality and length', () => {
    expect(constantTimeEqual(hexToBytes('aabb'), hexToBytes('aabb'))).toBe(true);
    expect(constantTimeEqual(hexToBytes('aabb'), hexToBytes('aabc'))).toBe(false);
    expect(constantTimeEqual(hexToBytes('aabb'), hexToBytes('aa'))).toBe(false);
  });

  it('secureRandomInt stays within range and rejects bad bounds', () => {
    for (let i = 0; i < 200; i += 1) {
      const n = secureRandomInt(8);
      expect(n).toBeGreaterThanOrEqual(0);
      expect(n).toBeLessThan(8);
    }
    expect(secureRandomInt(1)).toBe(0);
    expect(() => secureRandomInt(0)).toThrow();
    expect(() => secureRandomInt(-3)).toThrow();
    expect(() => secureRandomInt(2.5)).toThrow();
  });
});
