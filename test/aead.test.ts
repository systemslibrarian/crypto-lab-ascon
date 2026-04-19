import { describe, expect, it } from 'vitest';

import { asconDecrypt, asconEncrypt } from '../src/aead';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../src/bytes';

describe('Ascon-AEAD128', () => {
  it('matches known-answer vector for empty PT and AD', () => {
    const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
    const nonce = hexToBytes('101112131415161718191a1b1c1d1e1f');

    const result = asconEncrypt({
      key,
      nonce,
      associatedData: new Uint8Array(),
      plaintext: new Uint8Array(),
    });

    // KAT (ascon-c LWC_AEAD_KAT_128_128.txt, Count = 1)
    expect(bytesToHex(result.ciphertext)).toBe('');
    expect(bytesToHex(result.tag)).toBe('4f9c278211bec9316bf68f46ee8b2ec6');
  });

  it('round-trips and rejects tampering', () => {
    const key = hexToBytes('00112233445566778899aabbccddeeff');
    const nonce = hexToBytes('102132435465768798a9bacbdcedfe0f');
    const ad = utf8ToBytes('header');
    const pt = utf8ToBytes('Ascon authenticated encryption test message.');

    const encrypted = asconEncrypt({ key, nonce, associatedData: ad, plaintext: pt });
    const decrypted = asconDecrypt(key, nonce, ad, encrypted.ciphertext, encrypted.tag);

    expect(decrypted).not.toBeNull();
    expect(decrypted).toEqual(pt);

    const tamperedCiphertext = encrypted.ciphertext.slice();
    if (tamperedCiphertext.length > 0) {
      tamperedCiphertext[0] ^= 0x01;
    }
    expect(asconDecrypt(key, nonce, ad, tamperedCiphertext, encrypted.tag)).toBeNull();

    const tamperedTag = encrypted.tag.slice();
    tamperedTag[tamperedTag.length - 1] ^= 0x01;
    expect(asconDecrypt(key, nonce, ad, encrypted.ciphertext, tamperedTag)).toBeNull();
  });
});
