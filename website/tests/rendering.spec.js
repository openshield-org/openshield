import { test, expect } from '@playwright/test';
import { gotoAndInit, goToSection, trackConsoleErrors } from './helpers.js';

// Regression coverage for the specific breakage introduced by an earlier,
// incomplete fix attempt (blanket innerHTML -> textContent) that this PR
// replaces with real sanitized rendering. Every one of these sections used
// to display raw, literal <div class="..."> markup instead of parsed HTML.

test.describe('Dynamic content renders as real DOM, not literal markup', () => {
    test('home sections render without console errors', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await gotoAndInit(page);
        expect(errors, `unexpected console errors: ${errors.join('; ')}`).toEqual([]);
    });

    test('ecosystem cards render as elements', async ({ page }) => {
        await gotoAndInit(page);
        const container = page.locator('#ecosystem-container');
        await expect(container.locator('h3').first()).toBeVisible();
        await expect(container).not.toContainText('<div class=');
    });

    test('the reactive terminal builds a real .command-text element and types into it', async ({ page }) => {
        await gotoAndInit(page);
        const commandText = page.locator('#terminal-content .command-text');
        await expect(commandText).toBeAttached();
        await expect(commandText).not.toHaveText('', { timeout: 3000 });
        await expect(page.locator('#terminal-content')).not.toContainText('<span class=');
    });

    test('rules render as cards with visible text, not escaped markup', async ({ page }) => {
        await gotoAndInit(page);
        await goToSection(page, 'rules');
        const container = page.locator('#rules-container');
        await expect(container.locator('h3').first()).toBeVisible();
        await expect(container).not.toContainText('<div class=');
    });

    test('a blog post renders its markdown content as real HTML', async ({ page }) => {
        await gotoAndInit(page);
        await page.evaluate(() => showBlogPost(siteContent.blog[0].id));
        const postContent = page.locator('#post-content');
        await expect(postContent.locator('h1')).toBeVisible();
        await expect(postContent.locator('.prose')).toBeVisible();
        await expect(postContent).not.toContainText('<header class=');
    });

    test('docs page renders markdown content and the sidebar nav works', async ({ page }) => {
        await gotoAndInit(page);
        await goToSection(page, 'docs');
        const container = page.locator('#docs-content-container');
        await expect(container).not.toContainText('<div class=');
        const secondNavBtn = page.locator('#docs-nav [data-doc-id]').nth(1);
        await secondNavBtn.click();
        await expect(container).not.toContainText('<div class=');
    });

    test('FAQ entries toggle open and closed via a real click handler, not inline onclick', async ({ page }) => {
        // Checks the class token toggleFAQ() controls directly, not rendered
        // visibility - see the mobile-menu test in navigation.spec.js for why.
        await gotoAndInit(page);
        await goToSection(page, 'faq');
        const firstButton = page.locator('#faq-container [data-faq-idx]').first();
        await expect(firstButton).not.toHaveAttribute('onclick');
        const answer = page.locator('#faq-answer-0');
        const isHidden = () => answer.evaluate((el) => el.classList.contains('hidden'));
        expect(await isHidden()).toBe(true);
        await firstButton.click();
        expect(await isHidden()).toBe(false);
    });

    test('the playground mock scan renders finding cards as real elements', async ({ page }) => {
        await gotoAndInit(page);
        await goToSection(page, 'playground');
        await page.locator('#btn-run-mock').click();
        const firstCard = page.locator('#pg-findings-feed > div').first();
        await expect(firstCard).toBeVisible({ timeout: 5000 });
        await expect(firstCard.locator('h5')).toBeVisible();
    });
});
