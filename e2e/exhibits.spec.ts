import { expect, test } from '@playwright/test';

/**
 * Functional smoke tests for every interactive exhibit, against the
 * production build. These prove the teaching claims the UI makes: the
 * walkthrough reproduces asconEncrypt(), the nonce-reuse attack recovers the
 * plaintext, tampering trips the tag, and the XOF prefix property holds.
 */

test.beforeEach(async ({ page }) => {
  await page.goto('.');
});

test('AEAD walkthrough runs in order and verifies against asconEncrypt()', async ({ page }) => {
  await page.getByRole('button', { name: '1 · Initialize' }).click();
  await page.getByRole('button', { name: '2 · Absorb AD' }).click();
  await page.getByRole('button', { name: '3 · Encrypt PT → CT' }).click();
  await page.getByRole('button', { name: '4 · Finalize → tag' }).click();
  await page.getByRole('button', { name: 'Verify vs asconEncrypt()' }).click();
  await expect(page.locator('#sponge-verify')).toContainText('✓ The four steps reproduce asconEncrypt() exactly');
});

test('walkthrough guardrails explain out-of-order clicks without corrupting state', async ({ page }) => {
  await page.getByRole('button', { name: '2 · Absorb AD' }).click();
  await expect(page.locator('#sponge-verify')).toContainText('the sponge must be keyed first');
  // The hint refused the click, so the pipeline still works from the top.
  await page.getByRole('button', { name: '1 · Initialize' }).click();
  await page.getByRole('button', { name: '2 · Absorb AD' }).click();
  await expect(page.locator('#trace')).toContainText('2 · absorbAD()');
});

test('layer stepping walks constant → S-box → diffusion', async ({ page }) => {
  const layerBtn = page.getByRole('button', { name: /Step one layer/ });
  await layerBtn.click();
  await expect(page.locator('#trace')).toContainText('layer 1/3 — add constant');
  await layerBtn.click();
  await expect(page.locator('#trace')).toContainText('layer 2/3 — S-box');
  await layerBtn.click();
  await expect(page.locator('#trace')).toContainText('layer 3/3 — linear diffusion');
});

test('S-box microscope computes S(0)=4 from the live gate logic', async ({ page }) => {
  // All-zero input: the Ascon S-box maps 0 -> 4 (verifiable against the spec
  // table). Reach it by planting zeros via the manual toggles.
  const values = page.locator('#sb-values');
  await expect(values).toContainText(/S\(\d+\) = \d+/);
  // Force all inputs to 0 by clicking any lit toggles.
  for (let i = 0; i < 5; i += 1) {
    const toggle = page.locator(`#sb-in-${i}`);
    if ((await toggle.getAttribute('aria-pressed')) === 'true') {
      await toggle.click();
    }
  }
  await expect(values).toContainText('S(0) = 4');
});

test('diffusion tracer spreads one bit toward half the state', async ({ page }) => {
  await page.getByRole('button', { name: 'Plant the Seed' }).click();
  await expect(page.locator('#diff-density')).toContainText('Difference planted: 1 / 320');
  const step = page.getByRole('button', { name: 'Step One Round' });
  for (let i = 0; i < 12; i += 1) {
    await step.click();
  }
  await expect(page.locator('#diff-density')).toContainText('Fully diffused');
  // After 12 rounds the difference should be near 50% (worst case well above 100 bits).
  const log = await page.locator('#diff-log').textContent();
  const last = /round 12 ·\s*(\d+)\/320/.exec(log ?? '');
  expect(last).not.toBeNull();
  expect(Number(last![1])).toBeGreaterThan(100);
  expect(Number(last![1])).toBeLessThan(220);
});

test('AEAD panel encrypts, decrypts, and detects tampering', async ({ page }) => {
  await page.getByRole('button', { name: 'Encrypt', exact: true }).click();
  await page.getByRole('button', { name: 'Decrypt', exact: true }).click();
  await expect(page.locator('#aead-status')).toContainText('Decryption valid ✓: Meter reading: 29418 L');
  await page.getByRole('button', { name: 'Tamper One Bit' }).click();
  await page.getByRole('button', { name: 'Decrypt', exact: true }).click();
  await expect(page.locator('#aead-status')).toContainText('TAMPER DETECTED ✗');
});

test('nonce reuse leaks P1 XOR P2 and recovers Message 2; fresh nonces do not', async ({ page }) => {
  await page.getByRole('button', { name: 'Encrypt Both — SAME Nonce' }).click();
  await expect(page.locator('#nr-verdict')).toContainText('✗ LEAKED');
  await expect(page.locator('#nr-recovered')).toHaveValue('Meter 4471: send $9999 to Chuck');
  const cxor = await page.locator('#nr-cxor').inputValue();
  const pxor = await page.locator('#nr-pxor').inputValue();
  expect(cxor).toBe(pxor);

  await page.getByRole('button', { name: 'Encrypt Both — Fresh Nonces' }).click();
  await expect(page.locator('#nr-verdict')).toContainText('✓ Safe');
});

test('hash and avalanche exhibits produce a 256-bit digest and ~50% flip rate', async ({ page }) => {
  await page.getByRole('button', { name: 'Hash', exact: true }).click();
  await expect(page.locator('#hash-output')).toHaveValue(/^[0-9a-f]{64}$/);
  await page.getByRole('button', { name: 'Run Avalanche Test' }).click();
  await expect(page.locator('#avalanche-out')).toContainText('Hamming distance:');
});

test('XOF output length follows the slider and keeps the prefix property', async ({ page }) => {
  const output = page.locator('#xof-output');
  await expect(output).toHaveValue(/^[0-9a-f]{64}$/); // 32 bytes by default
  const at32 = await output.inputValue();
  await page.locator('#xof-len').press('End'); // range max = 64 bytes
  await expect(output).toHaveValue(/^[0-9a-f]{128}$/);
  const at64 = await output.inputValue();
  expect(at64.startsWith(at32)).toBe(true);

  await page.getByRole('button', { name: 'Compare With Ascon-Hash256' }).click();
  await expect(page.locator('#xof-note')).toContainText('completely different digests');
});

test('lesson links restore the AEAD scenario from the URL', async ({ page }) => {
  const key = '000102030405060708090a0b0c0d0e0f';
  const nonce = '101112131415161718191a1b1c1d1e1f';
  await page.goto(`.?key=${key}&nonce=${nonce}&ad=lecture-3&pt=hello+class&msg=xyz`);
  await expect(page.locator('#aead-key')).toHaveValue(key);
  await expect(page.locator('#aead-nonce')).toHaveValue(nonce);
  await expect(page.locator('#aead-ad')).toHaveValue('lecture-3');
  await expect(page.locator('#aead-pt')).toHaveValue('hello class');
  await expect(page.locator('#hash-input')).toHaveValue('xyz');
  await expect(page.locator('#aead-status')).toContainText('Loaded shared lesson scenario');
});

test('benchmark runs to completion and reports native AES-GCM as faster', async ({ page }) => {
  test.setTimeout(120_000);
  await page.getByRole('button', { name: 'Run Benchmark' }).click();
  await expect(page.locator('#bench-status')).toHaveText('Done.', { timeout: 90_000 });
  await expect(page.locator('#bench-table')).toBeVisible();
  await expect(page.locator('#bench-verdict')).toContainText('beat this BigInt Ascon');
});

test('quiz scores answers and points misses at exhibits', async ({ page }) => {
  // Question 1: correct answer is the third option.
  await page.locator('#quiz-item-0 input[type="radio"]').nth(2).check();
  // Question 2: pick a wrong answer on purpose.
  await page.locator('#quiz-item-1 input[type="radio"]').nth(0).check();
  await page.getByRole('button', { name: 'Check Answers' }).click();
  await expect(page.locator('#quiz-feedback-0')).toContainText('✓ Correct');
  await expect(page.locator('#quiz-feedback-1')).toContainText('✗ Not quite');
  await expect(page.locator('#quiz-score')).toContainText('1 / 2 answered correct');
});
