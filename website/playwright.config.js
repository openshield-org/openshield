import { defineConfig } from '@playwright/test';

export default defineConfig({
    testDir: './tests',
    testMatch: '**/*.spec.js',
    fullyParallel: true,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 1 : 0,
    reporter: process.env.CI ? 'list' : 'html',
    use: {
        baseURL: 'http://127.0.0.1:4173',
        trace: 'retain-on-failure',
    },
    webServer: {
        // Applies vercel.json's real headers (including CSP), unlike plain
        // `python3 -m http.server` - see tests/csp_server.py. Every test in
        // this suite now runs against production-representative headers,
        // not just the ones in security.spec.js that assert on them.
        command: 'python3 tests/csp_server.py 4173',
        url: 'http://127.0.0.1:4173/index.html',
        reuseExistingServer: !process.env.CI,
        timeout: 15000,
    },
});
