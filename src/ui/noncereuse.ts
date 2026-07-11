import { asconEncrypt } from '../aead';
import { bytesToHex, bytesToUtf8, randomBytes, utf8ToBytes } from '../bytes';

/**
 * Exhibit: break AEAD yourself by reusing a nonce.
 *
 * Ascon encrypts by XORing each plaintext block into the rate, so two
 * messages sealed under the same key AND nonce start from the same
 * keystream:  C1 ^ C2 = P1 ^ P2  ... as long as the keystreams agree.
 *
 * Ascon is a DUPLEX sponge — the plaintext itself feeds back into the
 * state — so the keystreams stay identical only until the 16-byte block
 * where the two messages first differ. Everything through that block
 * leaks; after it, the states diverge. (A pure stream cipher like CTR or
 * ChaCha20 leaks the XOR of the ENTIRE message — Ascon's feedback limits
 * the damage, but the leak through the first differing block is already
 * fatal.) The tags stay perfectly valid either way: integrity survives,
 * confidentiality is gone.
 */

export function sectionHtml(num: number): string {
  return `
    <section class="panel" id="exhibit-nonce">
      <h2><span class="ex-num" aria-hidden="true">${num}</span> Break It Yourself — Nonce Reuse</h2>
      <p>Every warning label says <em>never encrypt two messages with the same nonce</em>. Don't take the label's word for it — do it, and watch the secret fall out. No key required.</p>
      <label>Message 1
        <input id="nr-pt1" type="text" value="Meter 4471: send $0100 to Alice" />
      </label>
      <label>Message 2
        <input id="nr-pt2" type="text" value="Meter 4471: send $9999 to Chuck" />
      </label>
      <div class="controls">
        <button id="nr-same" type="button">Encrypt Both — SAME Nonce</button>
        <button id="nr-fresh" type="button">Encrypt Both — Fresh Nonces</button>
      </div>
      <label>Ciphertext 1
        <textarea id="nr-c1" rows="2" readonly spellcheck="false"></textarea>
      </label>
      <label>Ciphertext 2
        <textarea id="nr-c2" rows="2" readonly spellcheck="false"></textarea>
      </label>
      <label>C1 ⊕ C2
        <textarea id="nr-cxor" rows="2" readonly spellcheck="false"></textarea>
      </label>
      <label>P1 ⊕ P2 (computed from the plaintexts, no crypto involved)
        <textarea id="nr-pxor" rows="2" readonly spellcheck="false"></textarea>
      </label>
      <p id="nr-verdict" class="status" role="status" aria-live="polite"></p>
      <label>Attacker's recovery of Message 2, given only C1, C2 and Message 1
        <textarea id="nr-recovered" rows="2" readonly spellcheck="false"></textarea>
      </label>
      <p class="legend">Both tags verify either way — authentication is intact while confidentiality collapses. Because Ascon is a duplex sponge (plaintext feeds back into the state), the leak runs through the first 16-byte block where the messages differ, then the keystreams diverge — a pure stream cipher would leak the whole message. Edit Message 1 so the two differ early and watch the leak shrink.</p>
    </section>
  `;
}

export function wire(byId: <T extends HTMLElement>(id: string) => T): void {
  const pt1Input = byId<HTMLInputElement>('nr-pt1');
  const pt2Input = byId<HTMLInputElement>('nr-pt2');
  const c1Out = byId<HTMLTextAreaElement>('nr-c1');
  const c2Out = byId<HTMLTextAreaElement>('nr-c2');
  const cxorOut = byId<HTMLTextAreaElement>('nr-cxor');
  const pxorOut = byId<HTMLTextAreaElement>('nr-pxor');
  const verdict = byId<HTMLParagraphElement>('nr-verdict');
  const recovered = byId<HTMLTextAreaElement>('nr-recovered');

  function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
    const n = Math.min(a.length, b.length);
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i += 1) {
      out[i] = a[i] ^ b[i];
    }
    return out;
  }

  function run(reuseNonce: boolean): void {
    const p1 = utf8ToBytes(pt1Input.value);
    const p2 = utf8ToBytes(pt2Input.value);
    const key = randomBytes(16);
    const nonce1 = randomBytes(16);
    const nonce2 = reuseNonce ? nonce1 : randomBytes(16);

    const enc1 = asconEncrypt({ key, nonce: nonce1, associatedData: new Uint8Array(0), plaintext: p1 });
    const enc2 = asconEncrypt({ key, nonce: nonce2, associatedData: new Uint8Array(0), plaintext: p2 });

    const cxor = xorBytes(enc1.ciphertext, enc2.ciphertext);
    const pxor = xorBytes(p1, p2);

    c1Out.value = bytesToHex(enc1.ciphertext);
    c2Out.value = bytesToHex(enc2.ciphertext);
    cxorOut.value = bytesToHex(cxor);
    pxorOut.value = bytesToHex(pxor);

    // The attacker's move: P2 = C1 ^ C2 ^ P1 over the leaked prefix.
    recovered.value = bytesToUtf8(xorBytes(cxor, p1));

    let leakedBytes = 0;
    while (leakedBytes < cxor.length && cxor[leakedBytes] === pxor[leakedBytes]) {
      leakedBytes += 1;
    }
    const lengthNote =
      p1.length === p2.length ? '' : ' Message lengths differ — length itself leaks too.';

    if (reuseNonce && leakedBytes === cxor.length) {
      verdict.textContent = `✗ LEAKED: C1 ⊕ C2 equals P1 ⊕ P2 for all ${cxor.length} shared bytes — the keystream cancelled out, and Message 2 is recovered below without ever touching the key.${lengthNote}`;
      verdict.className = 'status bad';
    } else if (reuseNonce) {
      verdict.textContent = `✗ LEAKED (first ${leakedBytes} bytes): C1 ⊕ C2 equals P1 ⊕ P2 through the block containing the first difference. Ascon's duplex feedback then diverges the keystreams — the recovery below is correct for ${leakedBytes} bytes, then turns to garbage.${lengthNote}`;
      verdict.className = 'status bad';
    } else {
      verdict.textContent = `✓ Safe: with fresh nonces the keystreams are unrelated from byte 0, so C1 ⊕ C2 says nothing about P1 ⊕ P2 and the "recovery" below is garbage.${lengthNote}`;
      verdict.className = 'status good';
    }
  }

  byId<HTMLButtonElement>('nr-same').addEventListener('click', () => run(true));
  byId<HTMLButtonElement>('nr-fresh').addEventListener('click', () => run(false));
}
