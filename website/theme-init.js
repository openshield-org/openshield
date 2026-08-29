// Blocking theme script: sets the 'dark' class on <html> before first paint
// to prevent a flash of the wrong theme. Must stay a plain, unblocked,
// non-deferred <script src> in the exact position the inline version used
// to occupy in index.html's <head> - execution order for scripts without
// defer/async is document order, so moving this to an external same-origin
// file (required by CSP's script-src no longer allowing 'unsafe-inline',
// see #297) preserves the same blocking-before-paint behavior.
if (
    localStorage.getItem('color-theme') === 'dark' ||
    (!('color-theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)
) {
    document.documentElement.classList.add('dark');
} else {
    document.documentElement.classList.remove('dark');
}
