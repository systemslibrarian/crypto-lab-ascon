import { asconEncrypt } from '../aead';
import { asconHash256 } from '../hash';
import { randomBytes } from '../bytes';

/**
 * Exhibit: honest, on-your-machine benchmark.
 *
 * This teaching build uses BigInt for every 64-bit word, so it loses to
 * hardware AES-GCM by orders of magnitude — and showing that, live, on the
 * visitor's own device, is the point: Ascon's win is small code and state
 * on constrained chips, not desktop throughput.
 */

const MIB = 1024 * 1024;
const PAYLOAD_BYTES = 512 * 1024;
const SUBTLE_ITERATIONS = 32;

export function sectionHtml(num: number): string {
  return `
    <section class="panel" id="exhibit-bench">
      <h2><span class="ex-num" aria-hidden="true">${num}</span> Benchmark — On Your Machine, Honestly</h2>
      <p>This demo implements Ascon with <code>BigInt</code> so every 64-bit operation is legible — and slow. Your browser's <code>crypto.subtle</code> AES-GCM runs on native code with hardware AES instructions. Race them on ${PAYLOAD_BYTES / 1024} KiB and see the gap for yourself; then remember the smart water meter, where AES needs hardware Ascon doesn't have.</p>
      <div class="controls">
        <button id="bench-run" type="button">Run Benchmark</button>
      </div>
      <p id="bench-status" class="status neutral" role="status" aria-live="polite"></p>
      <div class="table-wrap">
        <table id="bench-table" hidden>
          <caption>Throughput measured just now in this browser tab (single run, indicative only).</caption>
          <thead>
            <tr><th scope="col">Algorithm</th><th scope="col">Implementation</th><th scope="col">Throughput</th></tr>
          </thead>
          <tbody id="bench-body"></tbody>
        </table>
      </div>
      <p id="bench-verdict" class="legend"></p>
    </section>
  `;
}

export function wire(byId: <T extends HTMLElement>(id: string) => T): void {
  const runBtn = byId<HTMLButtonElement>('bench-run');
  const status = byId<HTMLParagraphElement>('bench-status');
  const table = byId<HTMLTableElement>('bench-table');
  const body = byId<HTMLTableSectionElement>('bench-body');
  const verdict = byId<HTMLParagraphElement>('bench-verdict');

  const nextFrame = (): Promise<void> =>
    new Promise((resolve) => {
      requestAnimationFrame(() => resolve());
    });

  function mibPerSecond(bytes: number, ms: number): number {
    return bytes / MIB / (ms / 1000);
  }

  function addRow(algorithm: string, impl: string, mibps: number): void {
    const row = document.createElement('tr');
    const cells = [algorithm, impl, `${mibps.toFixed(1)} MiB/s`];
    for (const text of cells) {
      const td = document.createElement('td');
      td.textContent = text;
      row.appendChild(td);
    }
    body.appendChild(row);
  }

  async function run(): Promise<void> {
    runBtn.disabled = true;
    body.textContent = '';
    verdict.textContent = '';
    table.hidden = true;

    const data = new Uint8Array(PAYLOAD_BYTES);
    for (let i = 0; i < data.length; i += 1) {
      data[i] = i & 0xff;
    }
    const key16 = randomBytes(16);
    const nonce = randomBytes(16);
    const none = new Uint8Array(0);

    try {
      status.textContent = 'Running Ascon-AEAD128 (BigInt)…';
      await nextFrame();
      let t0 = performance.now();
      asconEncrypt({ key: key16, nonce, associatedData: none, plaintext: data });
      const asconAeadMibps = mibPerSecond(PAYLOAD_BYTES, performance.now() - t0);

      status.textContent = 'Running Ascon-Hash256 (BigInt)…';
      await nextFrame();
      t0 = performance.now();
      asconHash256(data);
      const asconHashMibps = mibPerSecond(PAYLOAD_BYTES, performance.now() - t0);

      status.textContent = 'Running AES-256-GCM (crypto.subtle, native)…';
      await nextFrame();
      const aesKey = await crypto.subtle.importKey('raw', randomBytes(32), 'AES-GCM', false, ['encrypt']);
      const iv = randomBytes(12);
      t0 = performance.now();
      for (let i = 0; i < SUBTLE_ITERATIONS; i += 1) {
        await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, data);
      }
      const aesMibps = mibPerSecond(PAYLOAD_BYTES * SUBTLE_ITERATIONS, performance.now() - t0);

      status.textContent = 'Running SHA-256 (crypto.subtle, native)…';
      await nextFrame();
      t0 = performance.now();
      for (let i = 0; i < SUBTLE_ITERATIONS; i += 1) {
        await crypto.subtle.digest('SHA-256', data);
      }
      const shaMibps = mibPerSecond(PAYLOAD_BYTES * SUBTLE_ITERATIONS, performance.now() - t0);

      addRow('Ascon-AEAD128', 'this demo, BigInt, single thread', asconAeadMibps);
      addRow('AES-256-GCM', 'crypto.subtle, native + AES-NI', aesMibps);
      addRow('Ascon-Hash256', 'this demo, BigInt, single thread', asconHashMibps);
      addRow('SHA-256', 'crypto.subtle, native', shaMibps);
      table.hidden = false;

      const ratio = aesMibps / asconAeadMibps;
      status.textContent = 'Done.';
      status.className = 'status good';
      verdict.textContent =
        `Native AES-GCM just beat this BigInt Ascon by ~${ratio >= 100 ? Math.round(ratio) : ratio.toFixed(1)}× on your machine. ` +
        'That is the correct outcome: a desktop CPU has hardware AES and fast 64-bit words. ' +
        'Flip the scenario to an 8-bit microcontroller with 2 KB of RAM and no AES hardware, and the ranking inverts — ' +
        'which is exactly the niche NIST standardized Ascon for. (A native C/Rust Ascon also runs orders of magnitude faster than this teaching build.)';
    } catch (error) {
      status.textContent = `Benchmark failed: ${(error as Error).message}`;
      status.className = 'status bad';
    } finally {
      runBtn.disabled = false;
    }
  }

  runBtn.addEventListener('click', () => {
    void run();
  });
}
