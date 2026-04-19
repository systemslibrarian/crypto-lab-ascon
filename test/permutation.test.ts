import { describe, expect, it } from 'vitest';

import { p12, p6, p8, type AsconState } from '../src/permutation';

function stateToHex(state: AsconState): string {
  return state.map((w) => w.toString(16).padStart(16, '0')).join('');
}

describe('Ascon permutation', () => {
  it('p12(zero state) matches official reference output', () => {
    const zeroState: AsconState = [0n, 0n, 0n, 0n, 0n];

    // Reference computed with the official ascon-c reference ROUND implementation.
    // Source equations: https://github.com/ascon/ascon-c/blob/main/crypto_aead/asconaead128/ref/round.h
    const expected =
      '78ea7ae5cfebb1089b9bfb8513b560f76937f83e03d11a503fe53f36f2c1178c045d648e4def12c9';

    expect(stateToHex(p12(zeroState))).toBe(expected);
  });

  it('p8 and p6 produce deterministic outputs', () => {
    const input: AsconState = [
      0x0123456789abcdefn,
      0xfedcba9876543210n,
      0x0011223344556677n,
      0x8899aabbccddeeffn,
      0x0f1e2d3c4b5a6978n,
    ];

    const p8a = p8(input);
    const p8b = p8(input);
    const p6a = p6(input);
    const p6b = p6(input);

    expect(p8a).toEqual(p8b);
    expect(p6a).toEqual(p6b);
  });
});
