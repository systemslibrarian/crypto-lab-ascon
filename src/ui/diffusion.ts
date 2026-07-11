import { randomBytes, load64, secureRandomInt } from '../bytes';
import { ROUND_CONSTANTS, round, type AsconState } from '../permutation';
import { renderBitGrid } from './bitgrid';

/**
 * Exhibit: single-bit avalanche tracer.
 *
 * We run TWO copies of the permutation whose inputs differ in exactly one
 * bit, and paint every bit where they disagree (their XOR). This is the
 * honest way to show diffusion: the round constants and the base state
 * cancel in the XOR, so every lit square traces back to that one seed bit.
 * A single-state view would conflate the avalanche with the constants.
 */

export function sectionHtml(num: number): string {
  return `
    <section class="panel" id="exhibit-diffusion">
      <h2><span class="ex-num" aria-hidden="true">${num}</span> The Avalanche — One Bit Becomes Half the State</h2>
      <p>Two copies of the sponge run side by side, their inputs differing in <strong>exactly one bit</strong>. Each gold square below is a bit where they now disagree. Step the real <code>round()</code> function and watch one bit of difference cascade to ~160 of 320 bits in 3–4 rounds — this is why Ascon needs so few rounds to be secure.</p>
      <div class="grid2">
        <label>Seed bit (0–319)
          <input id="diff-seed" type="number" min="0" max="319" value="160" />
        </label>
        <button id="diff-random" type="button">Random Seed Bit</button>
      </div>
      <div class="controls">
        <button id="diff-reset" type="button">Plant the Seed</button>
        <button id="diff-step" type="button" disabled>Step One Round</button>
        <button id="diff-run" type="button" disabled>Run All 12 Rounds</button>
      </div>
      <div id="diff-bars" class="state-bars" aria-hidden="true"></div>
      <p id="diff-density" class="density" role="status" aria-live="polite"></p>
      <pre id="diff-log" class="mono" role="log" aria-live="off" aria-label="Per-round avalanche log"></pre>
    </section>
  `;
}

export function wire(byId: <T extends HTMLElement>(id: string) => T, reducedMotion: () => boolean): void {
  const seedInput = byId<HTMLInputElement>('diff-seed');
  const resetBtn = byId<HTMLButtonElement>('diff-reset');
  const stepBtn = byId<HTMLButtonElement>('diff-step');
  const runBtn = byId<HTMLButtonElement>('diff-run');
  const bars = byId<HTMLDivElement>('diff-bars');
  const density = byId<HTMLParagraphElement>('diff-density');
  const log = byId<HTMLPreElement>('diff-log');

  let stateA: AsconState | null = null;
  let stateB: AsconState | null = null;
  let prevDiff: AsconState | null = null;
  let roundIndex = 0;
  let runTimer: number | null = null;

  function xorStates(a: AsconState, b: AsconState): AsconState {
    return [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3], a[4] ^ b[4]];
  }

  function stopRun(): void {
    if (runTimer !== null) {
      window.clearInterval(runTimer);
      runTimer = null;
    }
    const done = roundIndex >= 12;
    stepBtn.disabled = done || stateA === null;
    runBtn.disabled = done || stateA === null;
  }

  function render(): void {
    if (!stateA || !stateB) {
      return;
    }
    const diff = xorStates(stateA, stateB);
    const stats = renderBitGrid(bars, diff, prevDiff, 'differ');
    prevDiff = diff;
    const percent = ((stats.setBits / 320) * 100).toFixed(1);
    density.textContent =
      roundIndex === 0
        ? `Difference planted: ${stats.setBits} / 320 bits differ (${percent}%).`
        : `After round ${roundIndex}: ${stats.setBits} / 320 bits differ (${percent}%) — full avalanche sits near 50%.`;
    if (roundIndex > 0) {
      log.textContent = `${log.textContent ?? ''}round ${String(roundIndex).padStart(2)} · ${String(stats.setBits).padStart(3)}/320 differ (${percent.padStart(4)}%)\n`;
    }
  }

  function plantSeed(): void {
    stopRun();
    const bit = Number.parseInt(seedInput.value, 10);
    if (!Number.isInteger(bit) || bit < 0 || bit > 319) {
      density.textContent = 'Seed bit must be between 0 and 319.';
      return;
    }
    // Random base state: S-box differentials depend on the state they pass
    // through, so a random base is representative where all-zeros is not.
    const base = randomBytes(40);
    stateA = [load64(base, 0), load64(base, 8), load64(base, 16), load64(base, 24), load64(base, 32)];
    const word = Math.floor(bit / 64);
    const pos = BigInt(bit % 64);
    stateB = [...stateA] as AsconState;
    stateB[word] = stateB[word] ^ (1n << pos);
    roundIndex = 0;
    prevDiff = null;
    log.textContent = `seed: bit ${bit % 64} of x${word} flipped in copy B (random base state)\n`;
    render();
    stepBtn.disabled = false;
    runBtn.disabled = false;
  }

  function stepRound(): void {
    if (!stateA || !stateB || roundIndex >= 12) {
      return;
    }
    const c = ROUND_CONSTANTS[roundIndex];
    stateA = round(stateA, c);
    stateB = round(stateB, c);
    roundIndex += 1;
    render();
    if (roundIndex >= 12) {
      stopRun();
      density.textContent = `${density.textContent ?? ''} Fully diffused — plant a new seed to run again.`;
    }
  }

  resetBtn.addEventListener('click', plantSeed);
  byId<HTMLButtonElement>('diff-random').addEventListener('click', () => {
    seedInput.value = String(secureRandomInt(320));
    plantSeed();
  });
  stepBtn.addEventListener('click', () => {
    stopRun();
    stepRound();
  });
  runBtn.addEventListener('click', () => {
    stopRun();
    if (reducedMotion()) {
      while (roundIndex < 12 && stateA) {
        stepRound();
      }
      return;
    }
    stepBtn.disabled = true;
    runBtn.disabled = true;
    runTimer = window.setInterval(() => {
      stepRound();
      if (roundIndex >= 12) {
        stopRun();
      }
    }, 300);
  });
}
