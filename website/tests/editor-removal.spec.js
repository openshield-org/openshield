import { test, expect } from '@playwright/test';
import { gotoAndInit, goToSection } from './helpers.js';

// Regression coverage for issue #297: the browser-based classic GitHub PAT
// flow must be completely gone, not just hidden - a page that can request a
// repo-scoped credential is a real risk on its own even before considering
// what it's vulnerable to.

test.describe('The browser-based GitHub token flow is removed', () => {
    test('no token input exists anywhere in the DOM', async ({ page }) => {
        await gotoAndInit(page);
        await expect(page.locator('#github-token')).toHaveCount(0);
        await expect(page.locator('input[type="password"]')).toHaveCount(0);
    });

    test('submitToGithub is not defined', async ({ page }) => {
        await gotoAndInit(page);
        const type = await page.evaluate(() => typeof window.submitToGithub);
        expect(type).toBe('undefined');
    });

    test('the client never calls the GitHub API', async ({ page }) => {
        const apiCalls = [];
        page.on('request', (req) => {
            // Parse the actual host rather than a substring match on the
            // full URL - a plain .includes('api.github.com') would also
            // match a spoofed host like "api.github.com.evil.com" and
            // silently stop catching the one thing this test exists to
            // catch (flagged by CodeQL - fixing it for real, not just to
            // clear the check).
            let host;
            try {
                host = new URL(req.url()).hostname;
            } catch {
                return;
            }
            if (host === 'api.github.com') apiCalls.push(req.url());
        });
        await gotoAndInit(page);
        await goToSection(page, 'blog-editor');
        await page.selectOption('#edit-type', 'blog');
        await page.fill('#edit-id', 'test-post');
        await page.fill('#edit-title', 'Test Post');
        await page.fill('#edit-content', 'Some content.');
        await page.locator('#export-entry-btn').click();
        expect(apiCalls).toEqual([]);
    });

    test('exporting an entry shows the formatted snippet and PR instructions instead', async ({ page }) => {
        await gotoAndInit(page);
        await goToSection(page, 'blog-editor');
        await page.selectOption('#edit-type', 'blog');
        await page.fill('#edit-id', 'my-post');
        await page.fill('#edit-title', 'My Post');
        await page.fill('#edit-content', 'Hello world.');
        await page.locator('#export-entry-btn').click();

        // Checks the class token exportEntry() controls directly - see the
        // mobile-menu test in navigation.spec.js for why toBeVisible() isn't used.
        const output = page.locator('#export-entry-output');
        expect(await output.evaluate((el) => el.classList.contains('hidden'))).toBe(false);
        await expect(output).toHaveValue(/"title": "My Post"/);
        await expect(page.locator('#export-entry-note')).toContainText('website/content.js');
        await expect(page.getByRole('link', { name: /Open a Pull Request/i })).toHaveAttribute(
            'href',
            'https://github.com/openshield-org/openshield/edit/dev/website/content.js'
        );
    });

    test('exporting with required fields missing shows an error, not a silent export', async ({ page }) => {
        await gotoAndInit(page);
        await goToSection(page, 'blog-editor');
        await page.selectOption('#edit-type', 'blog');
        await page.locator('#export-entry-btn').click();
        expect(await page.locator('#export-entry-output').evaluate((el) => el.classList.contains('hidden'))).toBe(true);
        await expect(page.locator('#export-entry-note')).toContainText('required');
    });
});
