/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cream: '#EDE9E6',
        tan: '#C9996B',
        'dark-brown': '#5C4F4A',
        sage: '#5C766D',
        'text-gray': '#282828',  // ← ADD THIS
        critical: '#D64545',
        high: '#E67E22',
        success: '#27AE60',
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}