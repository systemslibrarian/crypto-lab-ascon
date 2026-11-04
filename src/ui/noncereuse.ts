import { asconEncrypt, type AeadOutput } from '../aead';
import { bytesToHex, bytesToUtf8, randomBytes, utf8ToBytes } from '../bytes';
import { flipNoncePacketBit, nonceReusePrefixLength, verifyNoncePacket } from '../nonce-reuse';

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
 * fatal.) Honest-packet verification and a chosen tamper rejection are measured
 * separately. Neither establishes general forgery resistance under nonce reuse.
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
      <p class="legend">Because Ascon is a duplex sponge (plaintext feeds back into the state), the reused-keystream leak runs through the first 16-byte block where the messages differ, then the states diverge. Later coincidental byte matches do not extend that guaranteed prefix. Edit Message 1 so the two differ early and watch the prefix shrink.</p>
      <h3>Check what the recipient accepts</h3>
      <p>The recipient verifies each original packet with its key and nonce. A valid tag on an honestly generated packet can coexist with the confidentiality leak above.</p>
      <p id="nr-honest-checks" class="status neutral" role="status" aria-live="polite">Encrypt both messages to run their recipient checks.</p>
      <div class="controls">
        <button id="nr-tamper-ciphertext" type="button" disabled>Flip Message 2 Ciphertext Bit</button>
        <button id="nr-tamper-tag" type="button" disabled>Flip Message 2 Tag Bit</button>
      </div>
      <p id="nr-tamper-help" class="legend">Each button changes one bit in a copy of the current Message 2 packet and runs authenticated decryption again.</p>
      <p id="nr-tamper-status" class="status neutral" role="status" aria-live="polite">No modified packet tested.</p>
      <label>Plaintext released by the recipient after the tamper check
        <textarea id="nr-recipient-output" rows="2" readonly spellcheck="false" aria-describedby="nr-tamper-status"></textarea>
      </label>
      <p class="legend">These checks report the packets tested in this run. Honest tag acceptance and rejection of these one-bit changes do not prove general forgery resistance under nonce reuse. Keep nonces unique and release plaintext only after successful verification. The XOR recovery above is the attacker's separate calculation, not plaintext released by this recipient.</p>
      <p class="legend">Further reading: <a href="https://doi.org/10.46586/tosc.v2025.i1.138-210">Lefevre and Mennink, <cite>SoK: Security of the Ascon Modes</cite></a>, distinguishes confidentiality, authenticity and different misuse models. Its ideal-permutation analyses are not a security proof of this browser build.</p>
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
  const honestChecks = byId<HTMLParagraphElement>('nr-honest-checks');
  const tamperCiphertext = byId<HTMLButtonElement>('nr-tamper-ciphertext');
  const tamperTag = byId<HTMLButtonElement>('nr-tamper-tag');
  const tamperHelp = byId<HTMLParagraphElement>('nr-tamper-help');
  const tamperStatus = byId<HTMLParagraphElement>('nr-tamper-status');
  const recipientOutput = byId<HTMLTextAreaElement>('nr-recipient-output');
  let currentPacket: { key: Uint8Array; nonce: Uint8Array; packet: AeadOutput; message: Uint8Array } | null = null;

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
    const checked1 = verifyNoncePacket(key, nonce1, enc1, p1);
    const checked2 = verifyNoncePacket(key, nonce2, enc2, p2);
    const describeCheck = (label: string, check: typeof checked1): string =>
      !check.verified
        ? `${label}: REJECTED; no plaintext released.`
        : check.matchesMessage
          ? `${label}: tag verified; recovered bytes match the message.`
          : `${label}: tag verified, but recovered bytes DO NOT match the message.`;
    honestChecks.textContent = `${describeCheck('Message 1', checked1)} ${describeCheck('Message 2', checked2)}`;
    honestChecks.className =
      checked1.matchesMessage && checked2.matchesMessage ? 'status good' : 'status bad';
    currentPacket = { key, nonce: nonce2, packet: enc2, message: p2 };
    tamperCiphertext.disabled = enc2.ciphertext.length === 0;
    tamperTag.disabled = false;
    tamperHelp.textContent = enc2.ciphertext.length === 0
      ? 'Message 2 is empty, so it has no ciphertext bit to change. Its authentication tag can still be tested.'
      : 'Each button changes one bit in a copy of the current Message 2 packet and runs authenticated decryption again.';
    tamperStatus.textContent = 'No modified packet tested for this run.';
    tamperStatus.className = 'status neutral';
    recipientOutput.value = '';

    const cxor = xorBytes(enc1.ciphertext, enc2.ciphertext);
    const pxor = xorBytes(p1, p2);

    c1Out.value = bytesToHex(enc1.ciphertext);
    c2Out.value = bytesToHex(enc2.ciphertext);
    cxorOut.value = bytesToHex(cxor);
    pxorOut.value = bytesToHex(pxor);

    // The attacker's move: P2 = C1 ^ C2 ^ P1 over the leaked prefix.
    recovered.value = bytesToUtf8(xorBytes(cxor, p1));

    const leakedBytes = nonceReusePrefixLength(p1, p2);
    const lengthNote =
      p1.length === p2.length ? '' : ' Message lengths differ — length itself leaks too.';

    if (cxor.length === 0) {
      verdict.textContent = 'No shared message bytes: there is no XOR recovery to show. Recipient and tag checks still run, including for empty messages.';
      verdict.className = 'status neutral';
    } else if (reuseNonce && leakedBytes === cxor.length) {
      const recoveryNote = p2.length > p1.length
        ? `Only the first ${cxor.length} bytes of Message 2 are recovered; the rest has no matching Message 1 bytes.`
        : 'Message 2 is recovered below without the key.';
      verdict.textContent = `✗ LEAKED: C1 ⊕ C2 equals P1 ⊕ P2 for all ${cxor.length} shared bytes — the keystream cancelled out. ${recoveryNote}${lengthNote}`;
      verdict.className = 'status bad';
    } else if (reuseNonce) {
      verdict.textContent = `✗ LEAKED (first ${leakedBytes} bytes): C1 ⊕ C2 equals P1 ⊕ P2 through the block containing the first difference. Ascon's duplex feedback then diverges the keystreams — the recovery below is correct for ${leakedBytes} bytes, then turns to garbage.${lengthNote}`;
      verdict.className = 'status bad';
    } else {
      verdict.textContent = `No reused-keystream recovery: these fresh nonces do not force C1 ⊕ C2 to equal P1 ⊕ P2. The XOR guess below is not a recovered message; accidental byte matches can occur.${lengthNote}`;
      verdict.className = 'status good';
    }
  }

  byId<HTMLButtonElement>('nr-same').addEventListener('click', () => run(true));
  byId<HTMLButtonElement>('nr-fresh').addEventListener('click', () => run(false));
  function checkTamper(target: 'ciphertext' | 'tag'): void {
    if (!currentPacket) return;
    recipientOutput.value = '';
    const { key, nonce, packet, message } = currentPacket;
    const changed = flipNoncePacketBit(packet, target);
    const result = verifyNoncePacket(key, nonce, changed, message);
    if (!result.verified) {
      tamperStatus.textContent = `REJECTED: Message 2 ${target} bit changed; tag verification failed. No plaintext released.`;
      tamperStatus.className = 'status good';
    } else {
      recipientOutput.value = bytesToUtf8(result.plaintext);
      tamperStatus.textContent = `UNEXPECTED ACCEPTANCE: the modified ${target} passed verification. The recipient released the bytes shown below; this control did not reject the modification.`;
      tamperStatus.className = 'status bad';
    }
  }
  tamperCiphertext.addEventListener('click', () => checkTamper('ciphertext'));
  tamperTag.addEventListener('click', () => checkTamper('tag'));

  function invalidateRun(): void {
    currentPacket = null;
    for (const output of [c1Out, c2Out, cxorOut, pxorOut, recovered, recipientOutput]) output.value = '';
    verdict.textContent = 'Messages changed. Encrypt both again to update the results.';
    verdict.className = 'status neutral';
    honestChecks.textContent = 'Messages changed. Encrypt both again to run their recipient checks.';
    honestChecks.className = 'status neutral';
    tamperStatus.textContent = 'No modified packet tested for these messages.';
    tamperStatus.className = 'status neutral';
    tamperHelp.textContent = 'Encrypt both messages before changing a packet bit.';
    tamperCiphertext.disabled = true;
    tamperTag.disabled = true;
  }
  pt1Input.addEventListener('input', invalidateRun);
  pt2Input.addEventListener('input', invalidateRun);
}
