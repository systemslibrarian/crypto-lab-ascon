import './style.css';

import {
  absorbAD,
  asconDecrypt,
  asconEncrypt,
  encryptPlaintext,
  finalize,
  initialize,
} from './aead';
import {
  bytesToHex,
  bytesToUtf8,
  hexToBytes,
  hammingDistance,
  randomBytes,
  secureRandomInt,
  utf8ToBytes,
} from './bytes';
import { asconHash256 } from './hash';
import {
  addConstant,
  diffusion,
  p12,
  round,
  ROUND_CONSTANTS,
  sbox,
  type AsconState,
} from './permutation';
import { renderBitGrid } from './ui/bitgrid';
import * as benchExhibit from './ui/benchmark';
import * as diffusionExhibit from './ui/diffusion';
import * as nonceExhibit from './ui/noncereuse';
import * as quizExhibit from './ui/quiz';
import * as sboxScope from './ui/sboxscope';
import { applyParamsFromUrl, buildShareUrl } from './ui/share';
import * as xofExhibit from './ui/xofexhibit';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing #app container');
}

const reducedMotion = (): boolean => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

app.innerHTML = `
  <a class="skip-link" href="#main-content">Skip to main content</a>
  <div class="hero">
    <p class="eyebrow">NIST Lightweight Cryptography · FIPS SP 800-232</p>
    <h1>Ascon</h1>
    <p class="subtitle">Permutation-based sponge AEAD, hashing &amp; XOF for constrained devices — built from the spec, with zero crypto dependencies.</p>
    <ul class="badges" aria-label="At a glance">
      <li>320-bit state</li>
      <li>128-bit key &amp; tag</li>
      <li>AEAD · Hash · XOF</li>
      <li class="badge-ok">Verified against official NIST KATs</li>
    </ul>
    <button id="theme-toggle" class="ghost" type="button" aria-label="Toggle dark and light theme">Toggle Theme</button>
  </div>

  <main id="main-content" class="layout">
    <section class="panel" id="exhibit-sponge">
      <h2><span class="ex-num" aria-hidden="true">1</span> The Sponge Construction</h2>
      <p>State = 5 x 64-bit words (320 bits). Words <strong>x0–x1</strong> are the rate (public); <strong>x2–x4</strong> are the capacity (secret). Each square below is one real bit of the live state — watch the permutation scramble it toward ~50% density (diffusion). Bits changed by the latest step flash gold.</p>
      <div id="state-bars" class="state-bars" aria-hidden="true"></div>
      <p id="state-density" class="density"></p>
      <pre id="state-hex" class="mono" aria-live="polite" aria-label="Ascon state words in hexadecimal"></pre>

      <p class="phase-label">Inspect the permutation</p>
      <div class="controls">
        <button id="btn-p12" type="button">Apply p12</button>
        <button id="btn-step" type="button">Step through p12 (round by round)</button>
        <button id="btn-layer" type="button">Step one layer (constant → S-box → diffusion)</button>
      </div>

      <p class="phase-label">Walk the real AEAD pipeline <span class="tagline">— same functions as Exhibit 3</span></p>
      <div class="controls">
        <button id="btn-init" type="button">1 · Initialize</button>
        <button id="btn-absorb-ad" type="button">2 · Absorb AD</button>
        <button id="btn-absorb-pt" type="button">3 · Encrypt PT → CT</button>
        <button id="btn-finalize" type="button">4 · Finalize → tag</button>
        <button id="btn-verify" type="button">Verify vs asconEncrypt()</button>
      </div>
      <p id="sponge-verify" class="status" role="status" aria-live="polite"></p>
      <pre id="trace" class="mono"></pre>

      <details class="explainer">
        <summary>How one round of the permutation works</summary>
        <p>Each round transforms the 320-bit state in three steps (use the <em>Step one layer</em> button above to watch each one flip bits individually):</p>
        <ol>
          <li><strong>Add round constant</strong> — XOR a per-round constant into word x2, so the 12 (or 8) rounds are not identical.</li>
          <li><strong>Substitution layer</strong> — a 5-bit S-box applied in parallel to all 64 bit-columns (one bit from each of x0…x4). It is <em>bitsliced</em> with AND/XOR/NOT only — no lookup tables — which is why Ascon is naturally constant-time.</li>
          <li><strong>Linear diffusion</strong> — each word is XORed with two rotated copies of itself, spreading every bit across the word:</li>
        </ol>
        <pre class="mono small codeblock">x0 ^= (x0 &gt;&gt;&gt; 19) ^ (x0 &gt;&gt;&gt; 28)
x1 ^= (x1 &gt;&gt;&gt; 61) ^ (x1 &gt;&gt;&gt; 39)
x2 ^= (x2 &gt;&gt;&gt;  1) ^ (x2 &gt;&gt;&gt;  6)
x3 ^= (x3 &gt;&gt;&gt; 10) ^ (x3 &gt;&gt;&gt; 17)
x4 ^= (x4 &gt;&gt;&gt;  7) ^ (x4 &gt;&gt;&gt; 41)</pre>
        <p><code>p12</code> runs 12 rounds (initialization &amp; finalization); the data phase uses 8. The AD and message phases are kept apart by <em>domain separation</em> — a single bit is flipped (XOR <code>0x80…00</code> into x4) between them so the two can never be confused.</p>
      </details>

      ${sboxScope.fragmentHtml()}
    </section>

    ${diffusionExhibit.sectionHtml(2)}

    <section class="panel" id="exhibit-aead">
      <h2><span class="ex-num" aria-hidden="true">3</span> AEAD Encryption — Live</h2>
      <div class="grid2">
        <label>Key (16-byte hex)
          <input id="aead-key" type="text" inputmode="text" spellcheck="false" autocomplete="off" aria-describedby="aead-key-help" />
        </label>
        <span id="aead-key-help" class="sr-only">Enter exactly 32 hexadecimal characters for a 16-byte key.</span>
        <button id="gen-key" type="button">Generate Random Key</button>
        <label>Nonce (16-byte hex)
          <input id="aead-nonce" type="text" inputmode="text" spellcheck="false" autocomplete="off" aria-describedby="aead-nonce-help" />
        </label>
        <span id="aead-nonce-help" class="sr-only">Enter exactly 32 hexadecimal characters for a 16-byte nonce.</span>
        <button id="gen-nonce" type="button">Generate Random Nonce</button>
      </div>
      <label>Associated Data
        <input id="aead-ad" type="text" placeholder="optional header" />
      </label>
      <label>Plaintext
        <textarea id="aead-pt" rows="4"></textarea>
      </label>
      <div class="controls">
        <button id="btn-encrypt" type="button">Encrypt</button>
        <button id="btn-decrypt" type="button">Decrypt</button>
        <button id="btn-tamper" type="button">Tamper One Bit</button>
      </div>
      <label>Ciphertext (hex)
        <textarea id="aead-ct" rows="3" readonly spellcheck="false"></textarea>
      </label>
      <label>Tag (16 bytes hex)
        <input id="aead-tag" type="text" readonly spellcheck="false" />
      </label>
      <div class="controls">
        <button id="copy-ct" class="copy-btn" type="button">Copy ciphertext</button>
        <button id="copy-tag" class="copy-btn" type="button">Copy tag</button>
        <button id="copy-link" class="copy-btn" type="button">Copy lesson link</button>
      </div>
      <p id="aead-status" class="status" role="status" aria-live="polite"></p>
      <p class="legend">The lesson link freezes these inputs (and the hash input) into a URL you can hand to a class. Never put real keys in URLs — these are classroom values.</p>
    </section>

    ${nonceExhibit.sectionHtml(4)}

    <section class="panel" id="exhibit-hash">
      <h2><span class="ex-num" aria-hidden="true">5</span> Ascon-Hash256</h2>
      <label>Input Text
        <input id="hash-input" type="text" value="Hello" />
      </label>
      <div class="controls">
        <button id="btn-hash" type="button">Hash</button>
        <button id="btn-avalanche" type="button">Run Avalanche Test</button>
      </div>
      <label>Output (64 hex chars)
        <textarea id="hash-output" rows="2" readonly></textarea>
      </label>
      <div class="controls">
        <button id="copy-hash" class="copy-btn" type="button">Copy digest</button>
      </div>
      <pre id="avalanche-out" class="mono" role="status" aria-live="polite"></pre>
      <div id="avalanche-grid" class="avalanche-grid" aria-hidden="true"></div>
      <p class="legend" aria-hidden="true">
        <span class="swatch flip"></span> changed bit
        <span class="swatch on"></span> set, unchanged
        <span class="swatch off"></span> clear, unchanged
      </p>
    </section>

    ${xofExhibit.sectionHtml(6)}

    <section class="panel" id="exhibit-compare">
      <h2><span class="ex-num" aria-hidden="true">7</span> Ascon vs AES-GCM vs ChaCha20-Poly1305</h2>
      <div class="table-wrap">
      <table>
        <caption>Comparison of cryptographic properties for constrained-device use.</caption>
        <thead>
          <tr><th>Property</th><th>Ascon-AEAD128</th><th>AES-256-GCM</th><th>ChaCha20-Poly1305</th></tr>
        </thead>
        <tbody>
          <tr><td>Key size</td><td>128 bits</td><td>256 bits</td><td>256 bits</td></tr>
          <tr><td>State size</td><td>320 bits</td><td>~2200 bits (128-bit block + 1920-bit key schedule + GHASH)</td><td>512 bits</td></tr>
          <tr><td>Code size</td><td><strong>Smallest</strong></td><td>Medium</td><td>Small</td></tr>
          <tr><td>Hardware deps</td><td>None</td><td>AES-NI for speed</td><td>None</td></tr>
          <tr><td>Side-channel</td><td><strong>Strong</strong> (constant-time natural)</td><td>Needs AES-NI or masking</td><td>Strong</td></tr>
          <tr><td>NIST standard</td><td>FIPS SP 800-232</td><td>FIPS 197 + 800-38D</td><td>RFC 8439</td></tr>
          <tr><td>Target</td><td>IoT / embedded</td><td>General-purpose</td><td>General-purpose</td></tr>
        </tbody>
      </table>
      </div>
    </section>

    <section class="panel" id="exhibit-iot">
      <h2><span class="ex-num" aria-hidden="true">8</span> Why Ascon for IoT?</h2>
      <pre class="mono codeblock">SCENARIO: Smart water meter, 8-bit MCU, 2KB RAM, battery-powered.

AES-256-GCM:
  ROM: ~2KB code
  RAM: 128-bit block + 1920-bit key schedule
  Side-channel: needs masking, adds 3-4x overhead
  Power: higher per byte

Ascon-AEAD128:
  ROM: ~500 bytes code
  RAM: 320-bit state
  Side-channel: naturally constant-time
  Power: lower per byte

-> Ascon chosen as NIST Lightweight Standard.</pre>
      <ul>
        <li>Automotive CAN bus encryption</li>
        <li>RFID tag authentication</li>
        <li>Industrial IoT sensors</li>
        <li>Smart card communications</li>
        <li>Embedded firmware update signing via Ascon-Hash256</li>
      </ul>
    </section>

    ${benchExhibit.sectionHtml(9)}

    ${quizExhibit.sectionHtml(10)}
  </main>

  <footer class="footer">
    <p class="footer-links">Related demos: <a href="https://systemslibrarian.github.io/crypto-lab-aes-modes/" target="_blank" rel="noopener noreferrer">AES modes and AEAD for comparison with lightweight crypto</a> · <a href="https://systemslibrarian.github.io/crypto-lab-aegis-gate/" target="_blank" rel="noopener noreferrer">high-performance AES-based AEAD</a> · <a href="https://systemslibrarian.github.io/crypto-lab-chacha20-stream/" target="_blank" rel="noopener noreferrer">ARX stream cipher used in lightweight contexts</a> · <a href="https://systemslibrarian.github.io/crypto-lab-babel-hash/" target="_blank" rel="noopener noreferrer">modern hash functions including sponge-based SHA3</a> · <a href="https://systemslibrarian.github.io/crypto-lab-hash-zoo/" target="_blank" rel="noopener noreferrer">hash constructions including Merkle-Damgård and sponge</a></p>
    <p>"Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."</p>
    <p>1 Corinthians 10:31</p>
  </footer>
`;

function byId<T extends HTMLElement>(id: string): T {
  const node = document.getElementById(id) as T | null;
  if (!node) {
    throw new Error(`Missing element #${id}`);
  }
  return node;
}

function parseExactHex(input: string, expectedBytes: number): Uint8Array {
  const out = hexToBytes(input.trim());
  if (out.length !== expectedBytes) {
    throw new Error(`Expected ${expectedBytes} bytes of hex`);
  }
  return out;
}

function toWordHex(word: bigint): string {
  return word.toString(16).padStart(16, '0');
}

let spongeState: AsconState = [0n, 0n, 0n, 0n, 0n];
const demoKey = randomBytes(16);
const demoNonce = randomBytes(16);
const demoAD = utf8ToBytes('ascon-demo'); // 10 bytes — one partial AD block
const demoPT = utf8ToBytes('lightweight-crypto'); // 18 bytes — one full + one partial block

const trace = byId<HTMLPreElement>('trace');
const stateHex = byId<HTMLPreElement>('state-hex');
const bars = byId<HTMLDivElement>('state-bars');
const density = byId<HTMLParagraphElement>('state-density');
const spongeVerify = byId<HTMLParagraphElement>('sponge-verify');

let scopeHooks: sboxScope.SboxScopeHooks | null = null;
let prevRendered: AsconState | null = null;

function renderState(label: string): void {
  trace.textContent = `${trace.textContent ?? ''}${label}\n`;
  stateHex.textContent = spongeState
    .map((w, i) => `x${i}: ${toWordHex(w)}`)
    .join('\n');

  // Render the actual 320 bits of state. Each square is one real bit, and
  // bits touched by the latest step carry a `flip` marker, so the S-box and
  // linear layer visibly scramble the state toward ~50% density.
  const stats = renderBitGrid(bars, spongeState, prevRendered);
  prevRendered = spongeState;
  scopeHooks?.afterGridRender();

  const percent = ((stats.setBits / 320) * 100).toFixed(1);
  const flippedNote = stats.flipped > 0 ? ` · ${stats.flipped} bits flipped by this step` : '';
  density.textContent = `State density: ${stats.setBits} / 320 bits set (${percent}%)${flippedNote} — well-diffused state sits near 50%.`;
}

// ---------------------------------------------------------------------------
// Walkthrough stage machine. The four pipeline buttons only make sense in
// order; an out-of-order click gets a teaching hint instead of silently
// producing a state that no longer matches the algorithm.
// ---------------------------------------------------------------------------
type Stage = 'fresh' | 'initialized' | 'ad-absorbed' | 'encrypted' | 'finalized';
let stage: Stage = 'fresh';

function hint(message: string): void {
  spongeVerify.textContent = message;
  spongeVerify.className = 'status neutral';
}

function clearHint(): void {
  spongeVerify.textContent = '';
  spongeVerify.className = 'status';
}

/**
 * Manually stepping the permutation mid-walkthrough desynchronizes the state
 * from the AEAD pipeline. Allowed — inspecting is the point — but say so.
 */
function markOffScript(): void {
  if (stage !== 'fresh') {
    stage = 'fresh';
    hint('You stepped the permutation by hand, so the AEAD walkthrough is now off-script. Click 1 · Initialize to restart it.');
  }
}

// The step-through animation runs on an interval. Track it so a second click —
// or any other state-changing button — cannot leave two timers mutating the
// state concurrently. `stepBtn` is disabled while an animation is in flight.
let stepTimer: number | null = null;
const stepBtn = byId<HTMLButtonElement>('btn-step');

// Round/layer counters for the two manual stepping modes.
let manualRound = 0;
let layerRound = 0;
let layerPhase = 0; // 0 = add constant next, 1 = S-box next, 2 = diffusion next

function resetStepCounters(): void {
  manualRound = 0;
  layerRound = 0;
  layerPhase = 0;
}

function stopStepping(): void {
  if (stepTimer !== null) {
    window.clearInterval(stepTimer);
    stepTimer = null;
    stepBtn.disabled = false;
  }
}

byId<HTMLButtonElement>('btn-init').addEventListener('click', () => {
  stopStepping();
  resetStepCounters();
  trace.textContent = '';
  clearHint();
  prevRendered = null;
  spongeState = initialize(demoKey, demoNonce);
  stage = 'initialized';
  renderState('1 · initialize(): state = p12(IV ‖ K ‖ N), then K XORed into the capacity');
});

byId<HTMLButtonElement>('btn-p12').addEventListener('click', () => {
  stopStepping();
  resetStepCounters();
  spongeState = p12(spongeState);
  renderState('Applied p12 (12 rounds)');
  markOffScript();
});

stepBtn.addEventListener('click', () => {
  stopStepping();
  if (reducedMotion()) {
    // No auto-advancing animation for reduced-motion users: each click steps
    // exactly one round, same math, no timer.
    spongeState = round(spongeState, ROUND_CONSTANTS[manualRound]);
    renderState(`Round ${manualRound + 1}/12 — add constant 0x${ROUND_CONSTANTS[manualRound].toString(16)}, S-box, linear diffusion`);
    manualRound = (manualRound + 1) % 12;
    markOffScript();
    return;
  }
  let index = 0;
  stepBtn.disabled = true;
  stepTimer = window.setInterval(() => {
    spongeState = round(spongeState, ROUND_CONSTANTS[index]);
    renderState(`Round ${index + 1}/12 — add constant 0x${ROUND_CONSTANTS[index].toString(16)}, S-box, linear diffusion`);
    index += 1;
    if (index === 12) {
      stopStepping();
    }
  }, 300);
  markOffScript();
});

byId<HTMLButtonElement>('btn-layer').addEventListener('click', () => {
  stopStepping();
  const c = ROUND_CONSTANTS[layerRound];
  if (layerPhase === 0) {
    spongeState = addConstant(spongeState, c);
    renderState(`Round ${layerRound + 1}/12 · layer 1/3 — add constant 0x${c.toString(16)}: XORs into x2 only (watch how few bits flip)`);
  } else if (layerPhase === 1) {
    spongeState = sbox(spongeState);
    renderState(`Round ${layerRound + 1}/12 · layer 2/3 — S-box: every one of the 64 bit-columns through the 5-bit S-box at once`);
  } else {
    spongeState = diffusion(spongeState);
    renderState(`Round ${layerRound + 1}/12 · layer 3/3 — linear diffusion: each word XORed with two rotations of itself`);
    layerRound = (layerRound + 1) % 12;
  }
  layerPhase = (layerPhase + 1) % 3;
  markOffScript();
});

byId<HTMLButtonElement>('btn-absorb-ad').addEventListener('click', () => {
  stopStepping();
  if (stage !== 'initialized') {
    hint(
      stage === 'fresh'
        ? 'Not yet — the sponge must be keyed first. Click 1 · Initialize, which runs p12 over IV ‖ K ‖ N.'
        : stage === 'ad-absorbed'
          ? 'The AD is already absorbed and domain-separated. Next: 3 · Encrypt PT → CT.'
          : 'This run has moved past the AD phase. Click 1 · Initialize to start a fresh walkthrough.',
    );
    return;
  }
  clearHint();
  spongeState = absorbAD(spongeState, demoAD);
  stage = 'ad-absorbed';
  renderState(`2 · absorbAD(): XOR "${bytesToUtf8(demoAD)}" into the rate, p8, then domain-separate (flip 1 bit of x4)`);
});

byId<HTMLButtonElement>('btn-absorb-pt').addEventListener('click', () => {
  stopStepping();
  if (stage !== 'ad-absorbed') {
    hint(
      stage === 'fresh' || stage === 'initialized'
        ? 'Not yet — associated data comes before plaintext. Run 1 · Initialize, then 2 · Absorb AD.'
        : stage === 'encrypted'
          ? 'The plaintext is already encrypted. Next: 4 · Finalize → tag.'
          : 'This run is finalized. Click 1 · Initialize to start a fresh walkthrough.',
    );
    return;
  }
  clearHint();
  const result = encryptPlaintext(spongeState, demoPT);
  spongeState = result.state;
  stage = 'encrypted';
  renderState(`3 · encryptPlaintext("${bytesToUtf8(demoPT)}"): CT = ${bytesToHex(result.ciphertext)}`);
});

byId<HTMLButtonElement>('btn-finalize').addEventListener('click', () => {
  stopStepping();
  if (stage !== 'encrypted') {
    hint(
      stage === 'finalized'
        ? 'Already finalized — the tag is in the trace above. Click 1 · Initialize to run it again.'
        : 'Not yet — finalization computes the tag over everything that came before. Run steps 1, 2 and 3 first.',
    );
    return;
  }
  clearHint();
  const result = finalize(spongeState, demoKey);
  spongeState = result.state;
  stage = 'finalized';
  renderState(`4 · finalize(): XOR K into capacity, p12, extract tag = ${bytesToHex(result.tag)}`);
});

byId<HTMLButtonElement>('btn-verify').addEventListener('click', () => {
  stopStepping();
  // Compose the exact production step functions, then check the result equals
  // the public asconEncrypt() API — proof the on-screen walkthrough is faithful.
  let s = initialize(demoKey, demoNonce);
  s = absorbAD(s, demoAD);
  const enc = encryptPlaintext(s, demoPT);
  const fin = finalize(enc.state, demoKey);

  const canonical = asconEncrypt({
    key: demoKey,
    nonce: demoNonce,
    associatedData: demoAD,
    plaintext: demoPT,
  });
  const roundTrip = asconDecrypt(demoKey, demoNonce, demoAD, canonical.ciphertext, canonical.tag);

  const ctMatch = bytesToHex(enc.ciphertext) === bytesToHex(canonical.ciphertext);
  const tagMatch = bytesToHex(fin.tag) === bytesToHex(canonical.tag);
  const decrypts = roundTrip !== null && bytesToUtf8(roundTrip) === bytesToUtf8(demoPT);

  if (ctMatch && tagMatch && decrypts) {
    spongeVerify.textContent = `✓ The four steps reproduce asconEncrypt() exactly — CT ${bytesToHex(enc.ciphertext)} and tag ${bytesToHex(fin.tag)} match, and decrypt round-trips. This walkthrough is the production algorithm, itself KAT-verified.`;
    spongeVerify.className = 'status good';
  } else {
    spongeVerify.textContent = '✗ Walkthrough diverged from asconEncrypt() — this should never happen.';
    spongeVerify.className = 'status bad';
  }
});

const aeadKeyInput = byId<HTMLInputElement>('aead-key');
const aeadNonceInput = byId<HTMLInputElement>('aead-nonce');
const aeadADInput = byId<HTMLInputElement>('aead-ad');
const aeadPTInput = byId<HTMLTextAreaElement>('aead-pt');
const aeadCTInput = byId<HTMLTextAreaElement>('aead-ct');
const aeadTagInput = byId<HTMLInputElement>('aead-tag');
const aeadStatus = byId<HTMLParagraphElement>('aead-status');

function writeRandomHex(node: HTMLInputElement, bytes: number): void {
  node.value = bytesToHex(randomBytes(bytes));
}

writeRandomHex(aeadKeyInput, 16);
writeRandomHex(aeadNonceInput, 16);
aeadADInput.value = 'sensor-header';
aeadPTInput.value = 'Meter reading: 29418 L';

byId<HTMLButtonElement>('gen-key').addEventListener('click', () => writeRandomHex(aeadKeyInput, 16));
byId<HTMLButtonElement>('gen-nonce').addEventListener('click', () => writeRandomHex(aeadNonceInput, 16));

byId<HTMLButtonElement>('btn-encrypt').addEventListener('click', () => {
  try {
    const key = parseExactHex(aeadKeyInput.value, 16);
    const nonce = parseExactHex(aeadNonceInput.value, 16);
    const ad = utf8ToBytes(aeadADInput.value);
    const pt = utf8ToBytes(aeadPTInput.value);

    const out = asconEncrypt({ key, nonce, associatedData: ad, plaintext: pt });
    aeadCTInput.value = bytesToHex(out.ciphertext);
    aeadTagInput.value = bytesToHex(out.tag);
    aeadStatus.textContent = 'Encryption complete.';
    aeadStatus.className = 'status neutral';
  } catch (error) {
    aeadStatus.textContent = (error as Error).message;
    aeadStatus.className = 'status bad';
  }
});

byId<HTMLButtonElement>('btn-decrypt').addEventListener('click', () => {
  try {
    const key = parseExactHex(aeadKeyInput.value, 16);
    const nonce = parseExactHex(aeadNonceInput.value, 16);
    const ad = utf8ToBytes(aeadADInput.value);
    const ct = hexToBytes(aeadCTInput.value.trim());
    const tag = parseExactHex(aeadTagInput.value, 16);

    const pt = asconDecrypt(key, nonce, ad, ct, tag);
    if (pt) {
      aeadStatus.textContent = `Decryption valid ✓: ${bytesToUtf8(pt)}`;
      aeadStatus.className = 'status good';
    } else {
      aeadStatus.textContent = 'TAMPER DETECTED ✗';
      aeadStatus.className = 'status bad';
    }
  } catch (error) {
    aeadStatus.textContent = (error as Error).message;
    aeadStatus.className = 'status bad';
  }
});

byId<HTMLButtonElement>('btn-tamper').addEventListener('click', () => {
  try {
    const ct = hexToBytes(aeadCTInput.value.trim());
    if (ct.length === 0) {
      throw new Error('Ciphertext is empty. Encrypt first.');
    }
    const byteIndex = secureRandomInt(ct.length);
    const bitIndex = secureRandomInt(8);
    ct[byteIndex] ^= 1 << bitIndex;
    aeadCTInput.value = bytesToHex(ct);
    aeadStatus.textContent = `Tampered byte ${byteIndex}, bit ${bitIndex}.`;
    aeadStatus.className = 'status bad';
  } catch (error) {
    aeadStatus.textContent = (error as Error).message;
    aeadStatus.className = 'status bad';
  }
});

async function copyFrom(source: HTMLInputElement | HTMLTextAreaElement, button: HTMLButtonElement): Promise<void> {
  const text = source.value.trim();
  if (!text) {
    button.textContent = 'Nothing to copy';
    window.setTimeout(() => { button.textContent = button.dataset.label ?? 'Copy'; }, 1200);
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = 'Copied ✓';
  } catch {
    button.textContent = 'Copy failed';
  }
  window.setTimeout(() => { button.textContent = button.dataset.label ?? 'Copy'; }, 1200);
}

function wireCopy(buttonId: string, source: HTMLInputElement | HTMLTextAreaElement): void {
  const button = byId<HTMLButtonElement>(buttonId);
  button.dataset.label = button.textContent ?? 'Copy';
  button.addEventListener('click', () => { void copyFrom(source, button); });
}

wireCopy('copy-ct', aeadCTInput);
wireCopy('copy-tag', aeadTagInput);

const hashInput = byId<HTMLInputElement>('hash-input');
const hashOutput = byId<HTMLTextAreaElement>('hash-output');
const avalancheOut = byId<HTMLPreElement>('avalanche-out');
const avalancheGrid = byId<HTMLDivElement>('avalanche-grid');

wireCopy('copy-hash', hashOutput);

function renderAvalancheGrid(a: Uint8Array, b: Uint8Array): void {
  let html = '';
  for (let i = 0; i < a.length; i += 1) {
    for (let bit = 7; bit >= 0; bit -= 1) {
      const aOn = (a[i] >> bit) & 1;
      const bOn = (b[i] >> bit) & 1;
      const cls = aOn !== bOn ? 'flip' : aOn ? 'on' : 'off';
      html += `<i class="${cls}"></i>`;
    }
  }
  avalancheGrid.innerHTML = html;
}

byId<HTMLButtonElement>('btn-hash').addEventListener('click', () => {
  const digest = asconHash256(utf8ToBytes(hashInput.value));
  hashOutput.value = bytesToHex(digest);
});

byId<HTMLButtonElement>('btn-avalanche').addEventListener('click', () => {
  const input = hashInput.value;
  const second = input.length > 0 ? String.fromCharCode(input.charCodeAt(0) ^ 1) + input.slice(1) : '\u0001';
  const h1 = asconHash256(utf8ToBytes(input));
  const h2 = asconHash256(utf8ToBytes(second));
  const distance = hammingDistance(h1, h2);
  const percent = ((distance / 256) * 100).toFixed(1);

  avalancheOut.textContent =
    `Input 1: ${JSON.stringify(input)}\n` +
    `Input 2: ${JSON.stringify(second)} (one bit flipped)\n` +
    `Hamming distance: ${distance} / 256 bits (${percent}%) — a single input bit cascades into ~half the digest.`;
  renderAvalancheGrid(h1, h2);
});

// ---------------------------------------------------------------------------
// New exhibits and cross-cutting features.
// ---------------------------------------------------------------------------

scopeHooks = sboxScope.wire(byId, bars, () => spongeState);
diffusionExhibit.wire(byId, reducedMotion);
nonceExhibit.wire(byId);
xofExhibit.wire(byId, wireCopy);
benchExhibit.wire(byId);
quizExhibit.wire(byId);

// Shareable lesson links: restore ?key=&nonce=&ad=&pt=&msg= on load, and let
// the AEAD panel mint a link that freezes the current scenario.
const shareRefs = {
  key: aeadKeyInput,
  nonce: aeadNonceInput,
  ad: aeadADInput,
  pt: aeadPTInput,
  hashMsg: hashInput,
};
if (applyParamsFromUrl(shareRefs)) {
  aeadStatus.textContent = 'Loaded shared lesson scenario from the link.';
  aeadStatus.className = 'status neutral';
}
byId<HTMLButtonElement>('copy-link').addEventListener('click', () => {
  void navigator.clipboard
    .writeText(buildShareUrl(shareRefs))
    .then(() => {
      aeadStatus.textContent = 'Lesson link copied — it reproduces these exact inputs.';
      aeadStatus.className = 'status good';
    })
    .catch(() => {
      aeadStatus.textContent = 'Could not copy the link (clipboard blocked).';
      aeadStatus.className = 'status bad';
    });
});

const themeToggle = byId<HTMLButtonElement>('theme-toggle');
function applyTheme(mode: 'dark' | 'light'): void {
  document.documentElement.setAttribute('data-theme', mode);
  localStorage.setItem('theme', mode);
  themeToggle.setAttribute('aria-pressed', mode === 'dark' ? 'true' : 'false');
}

themeToggle.addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  applyTheme(current === 'light' ? 'dark' : 'light');
});

applyTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark');
renderState('Ready. Click initialize to begin.');
