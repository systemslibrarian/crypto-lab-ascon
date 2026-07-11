import { popcount64 } from '../bytes';
import type { AsconState } from '../permutation';

export interface BitGridStats {
  setBits: number;
  flipped: number;
}

/**
 * Render 320 bits of an Ascon state as a 5x64 grid, one <i> per real bit.
 * When `prev` is given, bits that differ from it get a `flip` class so a
 * step of the permutation visibly shows *which* bits it touched, not just
 * that the pattern changed.
 */
export function renderBitGrid(
  container: HTMLElement,
  state: AsconState,
  prev: AsconState | null,
  countLabel: 'set' | 'differ' = 'set',
): BitGridStats {
  let setBits = 0;
  let flipped = 0;
  let html = '';

  for (let i = 0; i < 5; i += 1) {
    const w = state[i];
    const diff = prev ? w ^ prev[i] : 0n;
    const set = popcount64(w);
    setBits += set;
    flipped += popcount64(diff);

    let cells = '';
    for (let b = 63; b >= 0; b -= 1) {
      const on = ((w >> BigInt(b)) & 1n) === 1n;
      const fl = ((diff >> BigInt(b)) & 1n) === 1n;
      cells += `<i class="bit${on ? ' on' : ''}${fl ? ' flip' : ''}"></i>`;
    }
    const role = i < 2 ? 'rate' : 'capacity';
    html += `<div class="word word-${i}"><span class="word-label">x${i} <em>${role}</em> · ${set}/64 ${countLabel}</span><div class="bitgrid">${cells}</div></div>`;
  }

  container.innerHTML = html;
  return { setBits, flipped };
}

/**
 * Highlight one vertical bit-column (the 5 bits, one per word, that enter a
 * single S-box together). `bitIndex` is the bit position 0-63; pass null to
 * clear. Grids render bit 63 leftmost, so cell index = 63 - bitIndex.
 */
export function highlightColumn(container: HTMLElement, bitIndex: number | null): void {
  for (const el of container.querySelectorAll('.bit.col-hl')) {
    el.classList.remove('col-hl');
  }
  if (bitIndex === null) {
    return;
  }
  const cellIndex = 63 - bitIndex;
  for (const grid of container.querySelectorAll('.bitgrid')) {
    grid.children[cellIndex]?.classList.add('col-hl');
  }
}
