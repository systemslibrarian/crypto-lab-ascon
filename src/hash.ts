import { stateRateToBytes, withRate } from './bytes';
import { p12, type AsconState } from './permutation';

/**
 * Ascon-Hash256 (FIPS SP 800-232 Section 5).
 * Output: 256 bits = 32 bytes.
 * IV for Hash256 = 0x0000080100cc0002.
 * Uses p12 for init, absorption, and squeezing.
 */
const IV_HASH = 0x0000080100cc0002n;
const RATE_BYTES_HASH = 8;
const OUTPUT_BYTES = 32;

export function asconHash256(message: Uint8Array): Uint8Array {
  let state: AsconState = [IV_HASH, 0n, 0n, 0n, 0n];
  state = p12(state);

  let offset = 0;
  while (offset + RATE_BYTES_HASH <= message.length) {
    const block = message.subarray(offset, offset + RATE_BYTES_HASH);
    const rate = stateRateToBytes(state);
    for (let i = 0; i < RATE_BYTES_HASH; i += 1) {
      rate[i] ^= block[i];
    }
    state = withRate(state, rate);
    state = p12(state);
    offset += RATE_BYTES_HASH;
  }

  const tail = message.subarray(offset);
  {
    const rate = stateRateToBytes(state);
    for (let i = 0; i < tail.length; i += 1) {
      rate[i] ^= tail[i];
    }
    rate[tail.length] ^= 0x01;
    state = withRate(state, rate);
  }
  state = p12(state);

  const output = new Uint8Array(OUTPUT_BYTES);
  let outOffset = 0;
  while (outOffset < OUTPUT_BYTES) {
    const rate = stateRateToBytes(state);
    const take = Math.min(RATE_BYTES_HASH, OUTPUT_BYTES - outOffset);
    output.set(rate.subarray(0, take), outOffset);
    outOffset += take;
    if (outOffset < OUTPUT_BYTES) {
      state = p12(state);
    }
  }

  return output;
}
