import { stateRateToBytes, withRate } from './bytes';
import { p12, type AsconState } from './permutation';

/**
 * Ascon-XOF128 (FIPS SP 800-232 Section 5.2).
 * An extendable-output function: same sponge as Ascon-Hash256, but the
 * squeeze phase runs for as many blocks as the caller asks — the output
 * length is chosen at call time, not fixed by the algorithm.
 * IV for XOF128 = 0x0000080000cc0003 (the hash IV encodes its fixed
 * 256-bit output length; the XOF IV encodes 0 because output is unbounded).
 * Uses p12 for init, absorption, and squeezing.
 */
const IV_XOF = 0x0000080000cc0003n;
const RATE_BYTES_XOF = 8;

export function asconXof128(message: Uint8Array, outputBytes: number): Uint8Array {
  if (!Number.isInteger(outputBytes) || outputBytes < 0) {
    throw new Error('outputBytes must be a non-negative integer');
  }

  let state: AsconState = [IV_XOF, 0n, 0n, 0n, 0n];
  state = p12(state);

  let offset = 0;
  while (offset + RATE_BYTES_XOF <= message.length) {
    const block = message.subarray(offset, offset + RATE_BYTES_XOF);
    const rate = stateRateToBytes(state);
    for (let i = 0; i < RATE_BYTES_XOF; i += 1) {
      rate[i] ^= block[i];
    }
    state = withRate(state, rate);
    state = p12(state);
    offset += RATE_BYTES_XOF;
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

  const output = new Uint8Array(outputBytes);
  let outOffset = 0;
  while (outOffset < outputBytes) {
    const rate = stateRateToBytes(state);
    const take = Math.min(RATE_BYTES_XOF, outputBytes - outOffset);
    output.set(rate.subarray(0, take), outOffset);
    outOffset += take;
    if (outOffset < outputBytes) {
      state = p12(state);
    }
  }

  return output;
}
