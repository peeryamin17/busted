/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Black & white system — mostly black. The old accent token names
        // remain, but every value is now monochrome: white is the accent.
        ink: '#050505',
        panel: '#101010',
        mint: '#FFFFFF',
        mintlight: '#E8E8E8',
        bone: '#FFFFFF',
        paper: '#FAFAFA',
        body: '#CFCFCF',
        slate2: '#8B8B8B',
        // Faintly desaturated DATA tones — used only for severity coding
        // inside the scan demo / score ring, never as theme accents.
        amber2: '#B8AE94',
        hot: '#C0A08C',
        crit: '#C08F8F',
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
