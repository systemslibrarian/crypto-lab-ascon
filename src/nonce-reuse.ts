import { asconDecrypt, type AeadOutput } from './aead';

/** Recipient checks for the nonce-reuse lesson, whose associated data is empty. */
export type NoncePacketCheck =
  | { verified: false; matchesMessage: false; plaintext: null }
  | { verified: true; matchesMessage: boolean; plaintext: Uint8Array };

export function verifyNoncePacket(
  key: Uint8Array,
  nonce: Uint8Array,
  packet: AeadOutput,
  expectedMessage: Uint8Array,
): NoncePacketCheck {
  const plaintext = asconDecrypt(key, nonce, new Uint8Array(0), packet.ciphertext, packet.tag);
  if (plaintext === null) {
    return { verified: false, matchesMessage: false, plaintext: null };
  }
  const matchesMessage =
    plaintext.length === expectedMessage.length &&
    plaintext.every((byte, index) => byte === expectedMessage[index]);
  return { verified: true, matchesMessage, plaintext };
}

/** Alter a copy, so each control starts from the same honestly generated packet. */
export function flipNoncePacketBit(packet: AeadOutput, target: 'ciphertext' | 'tag'): AeadOutput {
  const changed = { ciphertext: packet.ciphertext.slice(), tag: packet.tag.slice() };
  if (changed[target].length === 0) {
    throw new Error(`This packet has no ${target} byte to change.`);
  }
  changed[target][0] ^= 0x01;
  return changed;
}

/**
 * Known-message comparison for this teaching run, not an attacker oracle.
 * Equal key, nonce and AD give equal rate states through the block containing
 * the first message difference. Later accidental byte matches are not counted
 * as an extension of that guaranteed prefix.
 */
export function nonceReusePrefixLength(first: Uint8Array, second: Uint8Array): number {
  const shared = Math.min(first.length, second.length);
  let difference = 0;
  while (difference < shared && first[difference] === second[difference]) difference += 1;
  return difference === shared ? shared : Math.min(shared, 16 * (Math.floor(difference / 16) + 1));
}
