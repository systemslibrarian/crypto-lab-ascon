import { defineConfig } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-ascon/',
  // Scope vitest to unit tests; e2e/*.spec.ts belongs to Playwright, which
  // would otherwise be swept up by vitest's default include glob.
  test: {
    include: ['test/**/*.test.ts'],
  },
});
