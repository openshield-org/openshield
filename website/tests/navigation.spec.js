import { test, expect } from '@playwright/test';
import { gotoAndInit } from './helpers.js';

test.describe('Navigation and routing', () => {
    test('clicking a nav link shows the target section and updates the hash', async ({ page }) => {
        await gotoAndInit(page);
        await page.locator('button[data-nav-section="blog"]').first().click();
        await expect(page).toHaveURL(/#blog$/);
        await expect(page.locator('#blog.section.active')).toBeVisible();
    });

    test('a direct #docs/<id> URL opens that doc page', async ({ page }) => {
        await gotoAndInit(page);
        const docId = await page.evaluate(() => siteContent.docs[1].id);
        await page.goto(`/index.html#docs/${docId}`);
        await page.waitForFunction(() => document.getElementById('docs-nav')?.children.length > 0);
        await expect(page.locator('#docs-content-container')).not.toBeEmpty();
    });

    test('a direct #blog/<id> URL opens that post', async ({ page }) => {
        await gotoAndInit(page);
        const postId = await page.evaluate(() => siteContent.blog[0].id);
        await page.goto(`/index.html#blog/${postId}`);
        await page.waitForFunction(() => document.getElementById('post-content')?.querySelector('h1'));
        await expect(page.locator('#post-content h1')).toBeVisible();
    });

    test('the mobile menu toggles', async ({ page }) => {
        // Checks the actual class token toggleMobileMenu() controls, not
        // Tailwind's rendered visibility for it - the Tailwind Play CDN
        // fails to load under Playwright's fetch/SRI handling (a pre-existing,
        // unrelated issue: see helpers.js), so .hidden's CSS never actually
        // applies here even though the class itself is correctly toggled.
        await gotoAndInit(page);
        const isHidden = () => page.locator('#mobile-menu').evaluate((el) => el.classList.contains('hidden'));
        expect(await isHidden()).toBe(true);
        await page.locator('#mobile-menu-btn').click();
        expect(await isHidden()).toBe(false);
    });
});
