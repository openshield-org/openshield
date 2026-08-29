// Shared Playwright helpers for the website test suite.

// These two messages are pre-existing, unrelated to issue #297, and verified
// (against the byte-identical file already on `dev`) to predate this fix:
//   - cdn.tailwindcss.com's SRI+CORS combination fails in some headless/CI
//     browser environments even though the CDN itself is unmodified.
//   - lucide@1.24.0 has no "github" icon under that name; renderReleases()
//     already used it before this PR touched the file.
// Filtering them here keeps assertions meaningful for *this* fix without
// either silently ignoring genuinely new errors or failing CI on issues this
// PR did not introduce and is not fixing.
const KNOWN_PREEXISTING_MESSAGES = [
    /cdn\.tailwindcss\.com/,
    /tailwind is not defined/,
    /icon name was not found in the provided icons object/,
    // The generic browser-level companion to the cdn.tailwindcss.com CORS
    // failure above (Chrome logs both). This page has exactly one external
    // resource that fails to load - if that changes, this pattern would
    // start masking a genuinely new failure, so keep it narrowly paired with
    // the CORS message rather than trusting it alone.
    /Failed to load resource: net::ERR_FAILED/,
];

function isKnownPreexisting(text) {
    return KNOWN_PREEXISTING_MESSAGES.some((pattern) => pattern.test(text));
}

// Attaches console/page-error listeners before navigation so nothing is
// missed, and returns an accessor for the errors collected so far.
export function trackConsoleErrors(page) {
    const errors = [];
    page.on('console', (msg) => {
        if (msg.type() === 'error' && !isKnownPreexisting(msg.text())) {
            errors.push(msg.text());
        }
    });
    page.on('pageerror', (err) => {
        if (!isKnownPreexisting(String(err))) {
            errors.push(String(err));
        }
    });
    return errors;
}

// Navigates to the site and waits for the synchronous render*() calls in
// window.addEventListener('load', ...) to have run.
export async function gotoAndInit(page) {
    await page.goto('/index.html');
    await page.waitForFunction(() => document.getElementById('ecosystem-container')?.children.length > 0);
}

// Several static nav buttons share the same visible label and overlapping
// onclick text (e.g. "Add Contributor" also calls showSection('blog-editor')
// as a first step), which makes them ambiguous or genuinely not-yet-visible
// targets for a real click in a test that only needs to *arrive* at a
// section, as opposed to a test that is specifically exercising a button's
// own click behavior. Those tests call page.locator(...).click() directly
// instead of this helper.
export async function goToSection(page, sectionId) {
    await page.evaluate((id) => showSection(id), sectionId);
    // Wait for DOM state (the active class plus the element's own inline
    // display), not Playwright's rendered-visibility check. showSection()
    // races a 300ms setTimeout (which inlines display:none on any section
    // still lacking .active once it fires) against a requestAnimationFrame
    // (which adds .active to the section being activated) - under CPU
    // contention the rAF callback can land more than 300ms late, so the
    // timeout's hide check can momentarily apply display:none to the very
    // section this call is trying to activate. A rendered-visibility wait
    // can get stuck observing that transient state; checking this element's
    // own class/style directly does not depend on it resolving before the
    // next paint. Same pattern already used for the mobile-menu and FAQ
    // tests in this suite.
    await page.waitForFunction((id) => {
        const el = document.getElementById(id);
        return Boolean(el) && el.classList.contains('active') && el.style.display !== 'none';
    }, sectionId);
}
