import { expect, test } from '@playwright/test';
test('avalanche is a diffusion illustration, not a security proof', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#exhibit-diffusion')).toContainText('does not prove security');
  await expect(page.locator('#exhibit-diffusion')).not.toContainText('why Ascon needs so few rounds');
});
