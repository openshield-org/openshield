// Tailwind CDN runtime configuration. Must load immediately after the
// Tailwind CDN <script> tag and before any content it needs to process -
// scripts without defer/async execute in document order, so this external
// same-origin file (required by CSP's script-src no longer allowing
// 'unsafe-inline', see #297) stays in the exact position the inline version
// used to occupy in index.html's <head>.
tailwind.config = {
    darkMode: 'class',
    theme: {
        extend: {
            fontFamily: {
                sans: ['Inter', 'system-ui', 'sans-serif'],
                mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
            },
            colors: {
                brand: {
                    50: '#eff6ff',
                    100: '#dbeafe',
                    200: '#bfdbfe',
                    300: '#93c5fd',
                    400: '#60a5fa',
                    500: '#3b82f6',
                    600: '#2563eb',
                    700: '#1d4ed8',
                },
                dark: {
                    800: '#1e293b',
                    900: '#0f172a',
                    950: '#020617',
                },
            },
        },
    },
};
