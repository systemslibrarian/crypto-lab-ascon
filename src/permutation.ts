/**
 * Ascon state: 5 x 64-bit words.
 * BigInt is required because JavaScript numbers lose precision above 2^53.
 */
export type AsconState = [bigint, bigint, bigint, bigint, bigint];

export const MASK64 = (1n << 64n) - 1n;

/**
 * Round constants (FIPS SP 800-232 Table 5).
 * p12 uses indices 0..11
 * p8 uses indices 4..11
 * p6 uses indices 6..11
 */
export const ROUND_CONSTANTS: bigint[] = [
  0xf0n,
  0xe1n,
  0xd2n,
  0xc3n,
  0xb4n,
  0xa5n,
  0x96n,
  0x87n,
  0x78n,
  0x69n,
  0x5an,
  0x4bn,
];

/**
 * 64-bit circular right rotation.
 */
export function rotr64(x: bigint, n: number): bigint {
  const m = BigInt(n % 64);
  if (m === 0n) {
    return x & MASK64;
  }
  return ((x >> m) | (x << (64n - m))) & MASK64;
}

/**
 * Add round constant to x2.
 */
export function addConstant(state: AsconState, c: bigint): AsconState {
  return [state[0], state[1], (state[2] ^ c) & MASK64, state[3], state[4]];
}

/**
 * 5-bit S-box, bit-sliced across 64 parallel lanes.
 * FIPS SP 800-232 Section 3.2.
 */
export function sbox(state: AsconState): AsconState {
  let [x0, x1, x2, x3, x4] = state;

  x0 ^= x4;
  x4 ^= x3;
  x2 ^= x1;

  const t0 = x0 ^ ((~x1 & MASK64) & x2);
  const t1 = x1 ^ ((~x2 & MASK64) & x3);
  const t2 = x2 ^ ((~x3 & MASK64) & x4);
  const t3 = x3 ^ ((~x4 & MASK64) & x0);
  const t4 = x4 ^ ((~x0 & MASK64) & x1);

  x0 = t0 & MASK64;
  x1 = t1 & MASK64;
  x2 = t2 & MASK64;
  x3 = t3 & MASK64;
  x4 = t4 & MASK64;

  x1 ^= x0;
  x0 ^= x4;
  x3 ^= x2;
  x2 = (~x2) & MASK64;

  return [x0 & MASK64, x1 & MASK64, x2 & MASK64, x3 & MASK64, x4 & MASK64];
}

/**
 * Linear diffusion layer.
 */
export function diffusion(state: AsconState): AsconState {
  const [x0, x1, x2, x3, x4] = state;
  return [
    (x0 ^ rotr64(x0, 19) ^ rotr64(x0, 28)) & MASK64,
    (x1 ^ rotr64(x1, 61) ^ rotr64(x1, 39)) & MASK64,
    (x2 ^ rotr64(x2, 1) ^ rotr64(x2, 6)) & MASK64,
    (x3 ^ rotr64(x3, 10) ^ rotr64(x3, 17)) & MASK64,
    (x4 ^ rotr64(x4, 7) ^ rotr64(x4, 41)) & MASK64,
  ];
}

/**
 * One round: add constant, S-box, diffusion.
 */
export function round(state: AsconState, c: bigint): AsconState {
  return diffusion(sbox(addConstant(state, c)));
}

/**
 * p12 - 12 rounds (init and finalization).
 */
export function p12(state: AsconState): AsconState {
  let s = state;
  for (let i = 0; i < 12; i += 1) {
    s = round(s, ROUND_CONSTANTS[i]);
  }
  return s;
}

/**
 * p8 - 8 rounds (Ascon-Hash256).
 */
export function p8(state: AsconState): AsconState {
  let s = state;
  for (let i = 4; i < 12; i += 1) {
    s = round(s, ROUND_CONSTANTS[i]);
  }
  return s;
}

/**
 * p6 - 6 rounds (AEAD data absorption).
 */
export function p6(state: AsconState): AsconState {
  let s = state;
  for (let i = 6; i < 12; i += 1) {
    s = round(s, ROUND_CONSTANTS[i]);
  }
  return s;
}
