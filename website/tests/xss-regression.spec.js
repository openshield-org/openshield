import { test, expect } from '@playwright/test';
import { gotoAndInit, goToSection } from './helpers.js';

// XSS regression corpus for issue #297. Each payload targets a different
// injection technique DOMPurify is responsible for neutralizing once
// markdown/editor content reaches innerHTML through renderMarkdown() /
// setSafeHTML(). A page-level "did script execute" flag (rather than just
// inspecting the resulting HTML string) proves the payload is inert, not
// just re-encoded.

const PAYLOADS = [
    { name: 'script tag', markdown: '<script>window.__xssHit = "script"</script>' },
    { name: 'img onerror', markdown: '<img src="x" onerror="window.__xssHit = \'onerror\'">' },
    { name: 'svg onload', markdown: '<svg onload="window.__xssHit = \'onload\'"></svg>' },
    {
        // hit staying undefined alone wouldn't prove much here - nothing in
        // this test clicks the link, so a survived javascript: href would
        // pass that check regardless. Verified directly (not guessed) that
        // DOMPurify drops the href attribute entirely rather than leaving a
        // neutered one: the tag survives as a bare <a>click me</a>.
        name: 'javascript: link',
        markdown: '[click me](javascript:window.__xssHit="jsurl")',
        assertOutput: (html) => expect(html).not.toMatch(/<a\s[^>]*href/i),
    },
    { name: 'iframe srcdoc', markdown: '<iframe srcdoc="<script>parent.__xssHit=\'srcdoc\'</script>"></iframe>' },
    {
        // DOMPurify allows the style attribute through (its URI allowlist
        // only governs attributes actually interpreted as a URI, e.g.
        // href/src) - the literal text "javascript:" can legitimately
        // survive inside a style attribute's CSS. That's not a bypass: no
        // current browser executes url(javascript:...) in CSS, which is
        // exactly what `hit` staying undefined above already proves.
        name: 'style expression',
        markdown: '<div style="background:url(javascript:window.__xssHit=\'style\')">x</div>',
    },
    { name: 'event handler on real tag', markdown: '<p onmouseover="window.__xssHit=\'onmouseover\'">hover me</p>' },
    {
        // Same reasoning as the javascript: link case above - verified
        // directly that the href is dropped entirely, not neutered.
        name: 'data: URL script',
        markdown: '<a href="data:text/html,<script>window.__xssHit=\'data\'</script>">link</a>',
        assertOutput: (html) => expect(html).not.toMatch(/<a\s[^>]*href/i),
    },
];

test.describe('XSS regression corpus', () => {
    for (const { name, markdown, assertOutput } of PAYLOADS) {
        test(`${name} payload does not execute in the live editor preview`, async ({ page }) => {
            await gotoAndInit(page);
            await page.addInitScript(() => { window.__xssHit = undefined; });
            await goToSection(page, 'blog-editor');
            await page.selectOption('#edit-type', 'blog');
            await page.fill('#edit-title', 'XSS Test');
            await page.fill('#edit-content', markdown);
            await page.waitForTimeout(150); // debounce the input-driven preview render

            const hit = await page.evaluate(() => window.__xssHit);
            expect(hit, `payload executed: ${name}`).toBeUndefined();

            // The load-bearing assertion is `hit` above (proves nothing
            // executed) - these are structural sanity checks on top of it,
            // not a substitute. Deliberately not asserting the sanitized
            // output never contains the literal text "javascript:" anywhere:
            // DOMPurify allows a style attribute's CSS text through (its
            // ALLOWED_URI_REGEXP only blocks javascript: in an attribute
            // that's actually interpreted as a URI, e.g. href/src), and no
            // current browser executes url(javascript:...) inside CSS - a
            // real payload text surviving there is inert, not a bypass.
            const previewHTML = await page.locator('#editor-preview').innerHTML();
            expect(previewHTML).not.toMatch(/<script/i);
            expect(previewHTML).not.toMatch(/\son\w+\s*=/i);
            assertOutput?.(previewHTML);
        });
    }

    test('a published blog post cannot execute script even if content.js were compromised', async ({ page }) => {
        await gotoAndInit(page);
        await page.addInitScript(() => { window.__xssHit = undefined; });
        await page.evaluate(() => {
            siteContent.blog.unshift({
                id: 'malicious-test-post',
                title: 'Malicious Post',
                date: '2026-01-01',
                author: 'attacker',
                excerpt: '...',
                content: '<script>window.__xssHit = "blog-post"</script>Also has <img src=x onerror="window.__xssHit=\'blog-post-img\'">',
            });
            showBlogPost('malicious-test-post');
        });
        const hit = await page.evaluate(() => window.__xssHit);
        expect(hit).toBeUndefined();
    });

    test('the docs page sanitizes the same way', async ({ page }) => {
        await gotoAndInit(page);
        await page.addInitScript(() => { window.__xssHit = undefined; });
        await page.evaluate(() => {
            siteContent.docs.unshift({
                id: 'malicious-doc',
                title: 'Malicious Doc',
                content: '<img src=x onerror="window.__xssHit=\'docs\'">',
            });
            showDocPage('malicious-doc');
        });
        const hit = await page.evaluate(() => window.__xssHit);
        expect(hit).toBeUndefined();
    });
});
