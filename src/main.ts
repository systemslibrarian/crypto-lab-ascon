import './style.css';

import { asconDecrypt, asconEncrypt } from './aead';
import {
  bytesToHex,
  bytesToUtf8,
  hexToBytes,
  hammingDistance,
  load64,
  randomBytes,
  secureRandomInt,
  stateRateToBytes,
  utf8ToBytes,
  withRate,
} from './bytes';
import { asconHash256 } from './hash';
import { p12, p8, round, ROUND_CONSTANTS, type AsconState } from './permutation';

const IV_AEAD = 0x00001000808c0001n;

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing #app container');
}

app.innerHTML = `
  <a class="skip-link" href="#main-content">Skip to main content</a>
  <header class="hero">
    <p class="eyebrow">NIST Lightweight AEAD Standard</p>
    <h1>crypto-lab-ascon</h1>
    <p class="subtitle">Permutation-based sponge cryptography for constrained devices.</p>
    <button id="theme-toggle" class="ghost" type="button" aria-label="Toggle dark and light theme">Toggle Theme</button>
  </header>

  <main id="main-content" class="layout">
    <section class="panel" id="exhibit-sponge">
      <h2>Exhibit 1: The Sponge Construction</h2>
      <p>State = 5 x 64-bit words. Top two words are rate/public. Bottom three words are capacity/secret.</p>
      <div id="state-bars" class="state-bars" aria-label="Ascon five-word state bars"></div>
      <pre id="state-hex" class="mono" aria-live="polite"></pre>
      <div class="controls">
        <button id="btn-init" type="button">Initialize with IV || K || N</button>
        <button id="btn-p12" type="button">Apply p12</button>
        <button id="btn-step" type="button">Step Through p12</button>
        <button id="btn-absorb-ad" type="button">Absorb AD block</button>
        <button id="btn-absorb-pt" type="button">Absorb PT block, extract CT block</button>
        <button id="btn-finalize" type="button">Finalize (tag)</button>
      </div>
      <pre id="trace" class="mono"></pre>
    </section>

    <section class="panel" id="exhibit-aead">
      <h2>Exhibit 2: AEAD Encryption Live Demo</h2>
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
      <p id="aead-status" class="status" role="status" aria-live="polite"></p>
    </section>

    <section class="panel" id="exhibit-compare">
      <h2>Exhibit 3: Ascon vs AES-GCM vs ChaCha20-Poly1305</h2>
      <div class="table-wrap">
      <table>
        <caption>Comparison of cryptographic properties for constrained-device use.</caption>
        <thead>
          <tr><th>Property</th><th>Ascon-AEAD128</th><th>AES-256-GCM</th><th>ChaCha20-Poly1305</th></tr>
        </thead>
        <tbody>
          <tr><td>Key size</td><td>128 bits</td><td>256 bits</td><td>256 bits</td></tr>
          <tr><td>State size</td><td>320 bits</td><td>~1600 bits (AES + GCM)</td><td>512 bits</td></tr>
          <tr><td>Code size</td><td><strong>Smallest</strong></td><td>Medium</td><td>Small</td></tr>
          <tr><td>Hardware deps</td><td>None</td><td>AES-NI for speed</td><td>None</td></tr>
          <tr><td>Side-channel</td><td><strong>Strong</strong> (constant-time natural)</td><td>Needs AES-NI or masking</td><td>Strong</td></tr>
          <tr><td>NIST standard</td><td>FIPS SP 800-232</td><td>FIPS 197 + 800-38D</td><td>RFC 8439</td></tr>
          <tr><td>Target</td><td>IoT / embedded</td><td>General-purpose</td><td>General-purpose</td></tr>
        </tbody>
      </table>
      </div>
    </section>

    <section class="panel" id="exhibit-hash">
      <h2>Exhibit 4: Ascon-Hash256</h2>
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
      <pre id="avalanche-out" class="mono" role="status" aria-live="polite"></pre>
    </section>

    <section class="panel" id="exhibit-iot">
      <h2>Exhibit 5: Why Ascon for IoT?</h2>
      <pre class="mono">SCENARIO: Smart water meter, 8-bit MCU, 2KB RAM, battery-powered.

AES-256-GCM:
  ROM: ~2KB code
  RAM: 1600-bit state
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
  </main>

  <footer class="footer">
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
const demoK0 = load64(demoKey, 0);
const demoK1 = load64(demoKey, 8);
const demoAD = utf8ToBytes('demo-associated-data').subarray(0, 16);
const demoPT = utf8ToBytes('demo-plaintext-data').subarray(0, 16);

const trace = byId<HTMLPreElement>('trace');
const stateHex = byId<HTMLPreElement>('state-hex');
const bars = byId<HTMLDivElement>('state-bars');

function renderState(label: string): void {
  trace.textContent = `${trace.textContent ?? ''}${label}\n`;
  stateHex.textContent = spongeState
    .map((w, i) => `x${i}: ${toWordHex(w)}`)
    .join('\n');

  bars.innerHTML = '';
  for (let i = 0; i < 5; i += 1) {
    const w = spongeState[i];
    const ratio = Number((w & 0xffff_ffffn) % 100n);
    const line = document.createElement('div');
    line.className = `word word-${i}`;
    line.innerHTML = `<span>x${i} (${i < 2 ? 'rate' : 'capacity'})</span><div class="bar"><div style="width:${ratio}%"></div></div>`;
    bars.appendChild(line);
  }
}

function absorbSingleRateBlock(state: AsconState, block: Uint8Array): AsconState {
  const rate = stateRateToBytes(state);
  for (let i = 0; i < block.length; i += 1) {
    rate[i] ^= block[i];
  }
  return withRate(state, rate);
}

function initializeSponge(): void {
  spongeState = [IV_AEAD, demoK0, demoK1, load64(demoNonce, 0), load64(demoNonce, 8)];
  renderState('Initialized with IV || K || N');
}

byId<HTMLButtonElement>('btn-init').addEventListener('click', () => {
  trace.textContent = '';
  initializeSponge();
});

byId<HTMLButtonElement>('btn-p12').addEventListener('click', () => {
  spongeState = p12(spongeState);
  renderState('Applied p12');
});

byId<HTMLButtonElement>('btn-step').addEventListener('click', () => {
  let index = 0;
  const timer = window.setInterval(() => {
    spongeState = round(spongeState, ROUND_CONSTANTS[index]);
    renderState(`Round ${index + 1}/12 with c=${ROUND_CONSTANTS[index].toString(16)}`);
    index += 1;
    if (index === 12) {
      window.clearInterval(timer);
    }
  }, 300);
});

byId<HTMLButtonElement>('btn-absorb-ad').addEventListener('click', () => {
  spongeState = absorbSingleRateBlock(spongeState, demoAD);
  spongeState = p8(spongeState);
  renderState('Absorbed AD block and applied p8');
});

byId<HTMLButtonElement>('btn-absorb-pt').addEventListener('click', () => {
  spongeState = absorbSingleRateBlock(spongeState, demoPT);
  const ct = stateRateToBytes(spongeState).subarray(0, 16);
  spongeState = p8(spongeState);
  renderState(`Absorbed PT block, extracted CT ${bytesToHex(ct)}`);
});

byId<HTMLButtonElement>('btn-finalize').addEventListener('click', () => {
  spongeState = [spongeState[0], spongeState[1], spongeState[2] ^ demoK0, spongeState[3] ^ demoK1, spongeState[4]];
  spongeState = p12(spongeState);
  const tagState: AsconState = [
    spongeState[0],
    spongeState[1],
    spongeState[2],
    spongeState[3] ^ demoK0,
    spongeState[4] ^ demoK1,
  ];
  const tag = stateRateToBytes([tagState[3], tagState[4], 0n, 0n, 0n]);
  renderState(`Finalize: XOR K, p12, extract tag ${bytesToHex(tag)}`);
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

const hashInput = byId<HTMLInputElement>('hash-input');
const hashOutput = byId<HTMLTextAreaElement>('hash-output');
const avalancheOut = byId<HTMLPreElement>('avalanche-out');

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

  avalancheOut.textContent = `Input 1: ${JSON.stringify(input)}\nInput 2: ${JSON.stringify(second)}\nHamming distance: ${distance} / 256 bits (${percent}%)`;
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
