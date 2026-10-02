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
        // Vivid DATA tones — reserved for scan findings and scores so the
        // evidence pops against the monochrome interface around it.
        amber2: '#FFD60A',
        hot: '#FF9F1C',
        crit: '#FF5A4E',
        signal: '#2EEA8C',
        sky2: '#4CC9FF',
        violet2: '#C084FC',
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
