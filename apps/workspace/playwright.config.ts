import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests', testIgnore: ['**/unit/**', '**/headless/**'], fullyParallel: false, workers: 1, timeout: 30000,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: { baseURL: 'http://127.0.0.1:4319', browserName: 'chromium', launchOptions: { executablePath: process.env.CHROMIUM_PATH ?? '/usr/bin/chromium', args: ['--no-sandbox'] }, screenshot: 'only-on-failure', trace: 'retain-on-failure' },
  webServer: { command:'npm run dev', url:'http://127.0.0.1:4319', reuseExistingServer: !process.env.CI, timeout:30000 },
});
