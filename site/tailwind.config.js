/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#0A0F1E',
        panel: '#131B2E',
        mint: '#34D399',
        mintlight: '#5EEAD4',
        bone: '#EAF6F0',
        paper: '#F8FAFC',
        slate2: '#64748B',
        amber2: '#FBBF24',
        hot: '#FB923C',
        crit: '#F87171',
        body: '#CBD5E1',
      },
      fontFamily: {
        display: ['"Space Grotesk"', 'system-ui', '-apple-system', '"Segoe UI"', 'sans-serif'],
        sans: ['Inter', 'system-ui', '-apple-system', '"Segoe UI"', 'sans-serif'],
        mono: ['ui-monospace', '"SF Mono"', '"Cascadia Code"', 'Menlo', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
};
