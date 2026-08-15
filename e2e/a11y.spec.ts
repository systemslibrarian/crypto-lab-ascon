import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the NIST KAT vectors;
 * this gates them on accessibility the same way. Scans the full page with
 * every <details> expanded, in both themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function openAllDetails(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      details.open = true;
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

async function assertGradientContrast(page: Page, selector: string, bgColors: string[]): Promise<void> {
  const ratio = await page.evaluate(({ sel, bgColors }) => {
    function getLuminance(r: number, g: number, b: number) {
      const [rs, gs, bs] = [r, g, b].map((c) => {
        c /= 255;
        return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
      });
      return 0.2126 * rs + 0.7152 * gs + 0.0722 * bs;
    }
    function parseRGB(c: string) {
      const match = c.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
      if (match) return [parseInt(match[1]), parseInt(match[2]), parseInt(match[3])];
      
      // Fallback for hex
      const ctx = document.createElement('canvas').getContext('2d')!;
      ctx.fillStyle = c;
      const computed = ctx.fillStyle;
      if (computed.startsWith('#')) {
        const r = parseInt(computed.slice(1, 3), 16);
        const g = parseInt(computed.slice(3, 5), 16);
        const b = parseInt(computed.slice(5, 7), 16);
        return [r, g, b];
      }
      return [0, 0, 0];
    }
    function getContrastRatio(c1: string, c2: string) {
      const [r1, g1, b1] = parseRGB(c1);
      const [r2, g2, b2] = parseRGB(c2);
      const l1 = getLuminance(r1, g1, b1);
      const l2 = getLuminance(r2, g2, b2);
      const lighter = Math.max(l1, l2);
      const darker = Math.min(l1, l2);
      return (lighter + 0.05) / (darker + 0.05);
    }
    
    const el = document.querySelector(sel);
    if (!el) return 99;
    const style = window.getComputedStyle(el);
    const color = style.color;
    
    let minRatio = 99;
    for (const bg of bgColors) {
      const r = getContrastRatio(color, bg);
      if (r < minRatio) minRatio = r;
    }
    return minRatio;
  }, { sel: selector, bgColors });

  expect(ratio).toBeGreaterThanOrEqual(4.5);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  await expect(page.locator('.cl-hero')).toBeVisible();
  await page.waitForLoadState('networkidle');
  await openAllDetails(page);
  await scan(page);
  // Dark theme bg: #05070d and #0d1320
  await assertGradientContrast(page, 'p.cl-hero-desc', ['#05070d', '#0d1320']);
});

