import { concatBytes, load64, stateRateToBytes, store64, withRate } from './bytes';
import { p12, p8, type AsconState } from './permutation';

/**
 * Ascon-AEAD128 (FIPS SP 800-232 Section 4).
 * Key: 128 bits. Nonce: 128 bits. Tag: 128 bits.
 * Initial value IV = 0x00001000808c0001.
 */
const IV_AEAD = 0x00001000808c0001n;
const RATE_BYTES = 16;
const KEY_BYTES = 16;
const NONCE_BYTES = 16;
const TAG_BYTES = 16;

export interface AeadInput {
  key: Uint8Array;
  nonce: Uint8Array;
  associatedData: Uint8Array;
  plaintext: Uint8Array;
}

export interface AeadOutput {
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

function validateInputSizes(key: Uint8Array, nonce: Uint8Array): void {
  if (key.length !== KEY_BYTES) {
    throw new Error('Ascon-AEAD128 key must be 16 bytes');
  }
  if (nonce.length !== NONCE_BYTES) {
    throw new Error('Ascon-AEAD128 nonce must be 16 bytes');
  }
}

/**
 * Initialize state: IV || K || N, then apply p12, then XOR K into capacity.
 */
function initialize(key: Uint8Array, nonce: Uint8Array): AsconState {
  validateInputSizes(key, nonce);
  const k0 = load64(key, 0);
  const k1 = load64(key, 8);

  let state: AsconState = [IV_AEAD, k0, k1, load64(nonce, 0), load64(nonce, 8)];
  state = p12(state);
  return [state[0], state[1], state[2], state[3] ^ k0, state[4] ^ k1];
}

function xorAndPadRate(state: AsconState, chunk: Uint8Array): AsconState {
  const rate = stateRateToBytes(state);
  for (let i = 0; i < chunk.length; i += 1) {
    rate[i] ^= chunk[i];
  }
  rate[chunk.length] ^= 0x01;
  return withRate(state, rate);
}

/**
 * Absorb associated data (domain separation via XOR into x4 at end).
 */
function absorbAD(state: AsconState, ad: Uint8Array): AsconState {
  if (ad.length === 0) {
    return [state[0], state[1], state[2], state[3], state[4] ^ 0x8000000000000000n];
  }

  let s = state;
  let offset = 0;

  while (offset + RATE_BYTES <= ad.length) {
    const block = ad.subarray(offset, offset + RATE_BYTES);
    s = [s[0] ^ load64(block, 0), s[1] ^ load64(block, 8), s[2], s[3], s[4]];
    s = p8(s);
    offset += RATE_BYTES;
  }

  s = xorAndPadRate(s, ad.subarray(offset));
  s = p8(s);
  return [s[0], s[1], s[2], s[3], s[4] ^ 0x8000000000000000n];
}

/**
 * Encrypt plaintext and return ciphertext + updated state.
 */
function encryptPlaintext(state: AsconState, pt: Uint8Array): {
  state: AsconState;
  ciphertext: Uint8Array;
} {
  let s = state;
  const ciphertext = new Uint8Array(pt.length);
  let offset = 0;

  while (offset + RATE_BYTES <= pt.length) {
    const block = pt.subarray(offset, offset + RATE_BYTES);
    s = [s[0] ^ load64(block, 0), s[1] ^ load64(block, 8), s[2], s[3], s[4]];
    ciphertext.set(store64(s[0]), offset);
    ciphertext.set(store64(s[1]), offset + 8);
    s = p8(s);
    offset += RATE_BYTES;
  }

  const tail = pt.subarray(offset);
  const rate = stateRateToBytes(s);
  for (let i = 0; i < tail.length; i += 1) {
    rate[i] ^= tail[i];
    ciphertext[offset + i] = rate[i];
  }
  rate[tail.length] ^= 0x01;
  s = withRate(s, rate);

  return { state: s, ciphertext };
}

/**
 * Finalize: XOR K into capacity, apply p12, extract tag from x3||x4.
 */
function finalize(state: AsconState, key: Uint8Array): {
  state: AsconState;
  tag: Uint8Array;
} {
  const k0 = load64(key, 0);
  const k1 = load64(key, 8);

  let s: AsconState = [state[0], state[1], state[2] ^ k0, state[3] ^ k1, state[4]];
  s = p12(s);
  s = [s[0], s[1], s[2], s[3] ^ k0, s[4] ^ k1];
  const tag = concatBytes(store64(s[3]), store64(s[4]));
  return { state: s, tag };
}

/**
 * Main API.
 */
export function asconEncrypt(input: AeadInput): AeadOutput {
  const state0 = initialize(input.key, input.nonce);
  const state1 = absorbAD(state0, input.associatedData);
  const { state: state2, ciphertext } = encryptPlaintext(state1, input.plaintext);
  const { tag } = finalize(state2, input.key);
  return { ciphertext, tag };
}

function decryptCiphertext(state: AsconState, ciphertext: Uint8Array): {
  state: AsconState;
  plaintext: Uint8Array;
} {
  let s = state;
  const plaintext = new Uint8Array(ciphertext.length);
  let offset = 0;

  while (offset + RATE_BYTES <= ciphertext.length) {
    const c0 = load64(ciphertext, offset);
    const c1 = load64(ciphertext, offset + 8);
    const p0 = s[0] ^ c0;
    const p1 = s[1] ^ c1;
    plaintext.set(store64(p0), offset);
    plaintext.set(store64(p1), offset + 8);
    s = [c0, c1, s[2], s[3], s[4]];
    s = p8(s);
    offset += RATE_BYTES;
  }

  const tail = ciphertext.subarray(offset);
  const rate = stateRateToBytes(s);
  for (let i = 0; i < tail.length; i += 1) {
    plaintext[offset + i] = rate[i] ^ tail[i];
    rate[i] = tail[i];
  }
  rate[tail.length] ^= 0x01;
  s = withRate(s, rate);

  return { state: s, plaintext };
}

/**
 * Constant-time byte array comparison.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Decrypt and verify. Returns null on tag mismatch.
 */
export function asconDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  associatedData: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
): Uint8Array | null {
  if (tag.length !== TAG_BYTES) {
    return null;
  }
  validateInputSizes(key, nonce);

  const state0 = initialize(key, nonce);
  const state1 = absorbAD(state0, associatedData);
  const { state: state2, plaintext } = decryptCiphertext(state1, ciphertext);
  const { tag: expectedTag } = finalize(state2, key);

  if (!constantTimeEqual(expectedTag, tag)) {
    return null;
  }
  return plaintext;
}
