import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests', testMatch: '*.spec.ts', workers: 1,
  reporter: 'list', outputDir: '.verification/browser-results',
  use: {
    baseURL: 'http://127.0.0.1:3031',
    launchOptions: { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH },
    screenshot: 'only-on-failure',
  },
  webServer: { command: 'node tests/browser-server.mjs', url: 'http://127.0.0.1:3031', reuseExistingServer: false, timeout: 15000 },
});
