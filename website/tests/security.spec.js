import { test, expect } from '@playwright/test';
import { gotoAndInit } from './helpers.js';

// Issue #297 required CSP-violation coverage, not just a CSP header sitting
// unused in vercel.json. tests/csp_server.py (wired into playwright.config.js)
// is what makes this possible: it actually applies vercel.json's headers,
// unlike the plain `python3 -m http.server` this suite used to run against -
// every other spec in this suite runs through the real header now too, this
// file is just the one that asserts on it directly.

test.describe('Content-Security-Policy', () => {
    test('the real production header is present on the served page', async ({ request }) => {
        const response = await request.get('/index.html');
        const csp = response.headers()['content-security-policy'];

        expect(csp, 'no CSP header at all - the test server is not applying vercel.json').toBeTruthy();
        // Assert on the specific directives this PR's fix depends on, not
        // just "a CSP header exists" - a header with the wrong content
        // would pass a bare-existence check just as easily.
        expect(csp).toContain("default-src 'self'");
        expect(csp).toContain("object-src 'none'");
        expect(csp).toContain("frame-ancestors 'self'");
        // script-src must not carry 'unsafe-inline' (this PR's fix) - assert
        // against the exact script-src directive, not the whole header
        // string, since style-src legitimately keeps 'unsafe-inline'.
        const scriptSrc = csp.split(';').find((directive) => directive.trim().startsWith('script-src'));
        expect(scriptSrc, 'no script-src directive in the CSP header').toBeTruthy();
        expect(scriptSrc).not.toContain('unsafe-inline');
    });

    test('an inline script injected outside the sanitized-content path is blocked, not silently allowed', async ({
        page,
    }) => {
        // This does not go through setSafeHTML()/DOMPurify - it simulates
        // the failure mode CSP exists to catch as a fallback if sanitization
        // were ever bypassed, distinct from xss-regression.spec.js's corpus
        // (which proves DOMPurify itself neutralizes real injection paths).
        const violations = [];
        await page.exposeFunction('__recordCspViolation', (violatedDirective) => violations.push(violatedDirective));
        await page.addInitScript(() => {
            window.__inlineScriptRan = false;
            document.addEventListener('securitypolicyviolation', (e) => {
                window.__recordCspViolation(e.violatedDirective);
            });
        });

        await gotoAndInit(page);
        await page.evaluate(() => {
            const script = document.createElement('script');
            script.textContent = 'window.__inlineScriptRan = true;';
            document.body.appendChild(script);
        });
        // securitypolicyviolation dispatch is async relative to the blocked
        // action - give it a turn before asserting.
        await page.waitForTimeout(50);

        const ran = await page.evaluate(() => window.__inlineScriptRan);
        expect(ran, 'CSP did not block the inline script - script-src still permits inline execution').toBe(false);
        expect(violations.some((d) => d.startsWith('script-src'))).toBe(true);
    });

    test('the page\'s own same-origin scripts still run normally under the real header', async ({ page }) => {
        // The positive case: removing 'unsafe-inline' must not be so
        // restrictive it breaks the site's actual functionality, which now
        // depends entirely on same-origin external scripts (theme-init.js,
        // tailwind-config.js, script.js) plus the explicitly allow-listed
        // third-party CDN script-src origins.
        await gotoAndInit(page);
        // theme-init.js (an external same-origin script) ran and set
        // tailwind.config via tailwind-config.js (another one) before
        // script.js's own load handler ran - proven together by
        // showSection() existing and actually working end to end. If CSP
        // had blocked any of these external scripts, the page would be
        // non-interactive and this would time out instead of passing.
        const themeInitRan = await page.evaluate(() => typeof showSection === 'function');
        expect(themeInitRan, 'script.js did not load/execute under the real CSP header').toBe(true);

        await page.evaluate(() => showSection('rules'));
        await expect(page.locator('#rules.section.active')).toBeVisible();
    });
});
