import { bytesToHex, utf8ToBytes } from '../bytes';
import { asconHash256 } from '../hash';
import { asconXof128 } from '../xof';

/**
 * Exhibit: Ascon-XOF128, the third algorithm in FIPS SP 800-232.
 * Same sponge as Ascon-Hash256, but the squeeze phase runs as long as the
 * caller wants — drag the slider and watch the output grow while the bytes
 * already squeezed stay put (the prefix property).
 */

export function sectionHtml(num: number): string {
  return `
    <section class="panel" id="exhibit-xof">
      <h2><span class="ex-num" aria-hidden="true">${num}</span> Ascon-XOF128 — A Hash With a Volume Knob</h2>
      <p>FIPS SP 800-232 standardizes three algorithms; this is the third. An <strong>extendable-output function</strong> is a sponge you keep squeezing: you choose the output length at call time. Drag the slider — earlier bytes never change, because longer output just means more squeeze steps of the same state.</p>
      <label>Input Text
        <input id="xof-input" type="text" value="Hello" />
      </label>
      <label>Output length: <span id="xof-len-readout">32</span> bytes
        <input id="xof-len" type="range" min="1" max="64" value="32" />
      </label>
      <label>Output (hex)
        <textarea id="xof-output" rows="3" readonly spellcheck="false"></textarea>
      </label>
      <div class="controls">
        <button id="xof-vs-hash" type="button">Compare With Ascon-Hash256</button>
        <button id="copy-xof" class="copy-btn" type="button">Copy output</button>
      </div>
      <pre id="xof-note" class="mono" role="status" aria-live="polite"></pre>
    </section>
  `;
}

export function wire(
  byId: <T extends HTMLElement>(id: string) => T,
  wireCopy: (buttonId: string, source: HTMLInputElement | HTMLTextAreaElement) => void,
): void {
  const input = byId<HTMLInputElement>('xof-input');
  const lenSlider = byId<HTMLInputElement>('xof-len');
  const lenReadout = byId<HTMLSpanElement>('xof-len-readout');
  const output = byId<HTMLTextAreaElement>('xof-output');
  const note = byId<HTMLPreElement>('xof-note');

  function render(): void {
    const len = Number.parseInt(lenSlider.value, 10);
    lenReadout.textContent = String(len);
    output.value = bytesToHex(asconXof128(utf8ToBytes(input.value), len));
  }

  input.addEventListener('input', render);
  lenSlider.addEventListener('input', render);

  byId<HTMLButtonElement>('xof-vs-hash').addEventListener('click', () => {
    const msg = utf8ToBytes(input.value);
    const hash = bytesToHex(asconHash256(msg));
    const xof32 = bytesToHex(asconXof128(msg, 32));
    note.textContent =
      `Ascon-Hash256: ${hash}\n` +
      `XOF128[0:32]:  ${xof32}\n` +
      `Same input, same 32-byte length — completely different digests. The two\n` +
      `algorithms use different IVs on purpose (domain separation), so a value\n` +
      `computed with one can never be confused with the other.`;
  });

  wireCopy('copy-xof', output);
  render();
}
