import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Same trick as the production rewrite (see vercel.json): the
      // backend is reached through the site's own origin, so the
      // bs_session cookie stays same-site in the browser.
      '/api': {
        target: 'https://bugseek-backend.onrender.com',
        changeOrigin: true,
      },
    },
  },
})
