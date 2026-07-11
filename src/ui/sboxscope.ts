import { sbox, type AsconState } from '../permutation';
import { highlightColumn } from './bitgrid';

/**
 * Exhibit fragment: the S-box microscope.
 *
 * Two connected views of the same idea:
 *  - a column inspector that highlights the 5 vertically-aligned bits (one
 *    per word) that enter a single S-box together, straight off the live
 *    state grid above it;
 *  - a 5-bit widget where you toggle inputs and the output is computed by
 *    the production `sbox()` function itself, run on a state whose words
 *    are just those 5 bits. Because the S-box is bitsliced, lane 0 of the
 *    real code IS the 5-bit S-box — no lookup table exists to consult.
 */

export function fragmentHtml(): string {
  const toggles = [0, 1, 2, 3, 4]
    .map(
      (i) => `
        <span class="sbox-lane">
          <button id="sb-in-${i}" class="sbox-toggle" type="button" aria-pressed="false" aria-label="S-box input bit x${i}">0</button>
          <span class="sbox-lane-label" aria-hidden="true">x${i}</span>
          <output id="sb-out-${i}" class="sbox-lamp" aria-label="S-box output bit x${i}">0</output>
        </span>`,
    )
    .join('');

  return `
    <p class="phase-label">S-box microscope <span class="tagline">— one column of the grid, under glass</span></p>
    <p>The S-box never sees a whole word. It eats one <strong>vertical column</strong> — bit <em>i</em> of x0, x1, x2, x3, x4 — and all 64 columns are transformed at once. Slide to light up a real column above, or toggle the 5 inputs yourself; the outputs come from the same <code>sbox()</code> code the cipher runs.</p>
    <label>Inspect bit column (0–63)
      <input id="sb-col" type="range" min="0" max="63" value="32" />
    </label>
    <p id="sb-col-readout" class="density" aria-live="polite"></p>
    <div class="sbox-widget" role="group" aria-label="Interactive 5-bit S-box">
      <span class="sbox-col-head" aria-hidden="true"><em>in</em><em></em><em>out</em></span>
      ${toggles}
      <span class="sbox-values" id="sb-values"></span>
    </div>
    <p class="legend">Toggle inputs on the left; outputs on the right are computed live by AND/XOR/NOT only — no lookup table, no data-dependent branch, which is why Ascon is constant-time by construction.</p>
  `;
}

export interface SboxScopeHooks {
  /** Re-apply the column highlight after the grid is re-rendered. */
  afterGridRender: () => void;
}

export function wire(
  byId: <T extends HTMLElement>(id: string) => T,
  bars: HTMLElement,
  getState: () => AsconState,
): SboxScopeHooks {
  const slider = byId<HTMLInputElement>('sb-col');
  const readout = byId<HTMLParagraphElement>('sb-col-readout');
  const values = byId<HTMLSpanElement>('sb-values');
  const inputs = [0, 1, 2, 3, 4].map((i) => byId<HTMLButtonElement>(`sb-in-${i}`));
  const outputs = [0, 1, 2, 3, 4].map((i) => byId<HTMLOutputElement>(`sb-out-${i}`));

  let bits: [bigint, bigint, bigint, bigint, bigint] = [0n, 0n, 0n, 0n, 0n];

  function renderWidget(): void {
    // Bitsliced S-box on a state holding one bit per word: lane 0 of the
    // production code is exactly the 5-bit S-box.
    const out = sbox(bits);
    let inVal = 0;
    let outVal = 0;
    for (let i = 0; i < 5; i += 1) {
      const inBit = bits[i] === 1n;
      const outBit = (out[i] & 1n) === 1n;
      // x0 is the most-significant bit of the 5-bit value, per the spec.
      inVal = (inVal << 1) | (inBit ? 1 : 0);
      outVal = (outVal << 1) | (outBit ? 1 : 0);
      inputs[i].textContent = inBit ? '1' : '0';
      inputs[i].setAttribute('aria-pressed', inBit ? 'true' : 'false');
      inputs[i].classList.toggle('lit', inBit);
      outputs[i].textContent = outBit ? '1' : '0';
      outputs[i].classList.toggle('lit', outBit);
    }
    values.textContent = `S(${inVal}) = ${outVal}   (0b${inVal.toString(2).padStart(5, '0')} → 0b${outVal.toString(2).padStart(5, '0')})`;
  }

  function loadColumn(bitIndex: number): void {
    const state = getState();
    bits = [0n, 0n, 0n, 0n, 0n];
    for (let i = 0; i < 5; i += 1) {
      bits[i] = (state[i] >> BigInt(bitIndex)) & 1n;
    }
    readout.textContent = `Column ${bitIndex}: reading bit ${bitIndex} of each live word above into the S-box inputs below.`;
    renderWidget();
  }

  function applyHighlight(): void {
    highlightColumn(bars, Number.parseInt(slider.value, 10));
  }

  slider.addEventListener('input', () => {
    applyHighlight();
    loadColumn(Number.parseInt(slider.value, 10));
  });

  for (const btn of inputs) {
    btn.addEventListener('click', () => {
      const i = inputs.indexOf(btn);
      bits[i] ^= 1n;
      readout.textContent = 'Manual inputs — slide the column inspector to reload bits from the live state.';
      renderWidget();
    });
  }

  // Hovering a bit in the live grid snaps the inspector to that column.
  bars.addEventListener('mouseover', (event) => {
    const cell = (event.target as HTMLElement).closest('i.bit');
    if (!cell || !cell.parentElement) {
      return;
    }
    const index = Array.prototype.indexOf.call(cell.parentElement.children, cell);
    if (index < 0) {
      return;
    }
    const bitIndex = 63 - index;
    slider.value = String(bitIndex);
    applyHighlight();
    loadColumn(bitIndex);
  });

  applyHighlight();
  loadColumn(Number.parseInt(slider.value, 10));

  return { afterGridRender: applyHighlight };
}
