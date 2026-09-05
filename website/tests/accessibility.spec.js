import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { gotoAndInit, goToSection } from './helpers.js';

// axe-core scans against the sections a visitor actually reaches by
// navigating the page, run after the same dynamic rendering this PR fixes
// (a scan against the pre-fix escaped-markup state would find far fewer
// real issues, since most content wasn't reachable as actual DOM at all).

const SECTIONS = ['home', 'rules', 'docs', 'blog', 'faq', 'community'];

for (const section of SECTIONS) {
    test(`${section} section has no critical/serious axe violations`, async ({ page }) => {
        await gotoAndInit(page);
        await goToSection(page, section);
        await page.waitForTimeout(200);

        const results = await new AxeBuilder({ page })
            .include(`#${section}`)
            .withTags(['wcag2a', 'wcag2aa'])
            .analyze();

        const blocking = results.violations.filter((v) => v.impact === 'critical' || v.impact === 'serious');
        expect(blocking, JSON.stringify(blocking, null, 2)).toEqual([]);
    });
}

test('keyboard navigation reaches and activates the FAQ toggle', async ({ page }) => {
    await gotoAndInit(page);
    await goToSection(page, 'faq');
    const firstButton = page.locator('#faq-container [data-faq-idx]').first();
    await firstButton.focus();
    await expect(firstButton).toBeFocused();
    await page.keyboard.press('Enter');
    // Checks the class token toggleFAQ() controls directly - see the
    // mobile-menu test in navigation.spec.js for why toBeVisible() isn't used.
    const isHidden = await page.locator('#faq-answer-0').evaluate((el) => el.classList.contains('hidden'));
    expect(isHidden).toBe(false);
});
