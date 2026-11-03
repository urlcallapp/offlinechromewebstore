import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The built assets are served by cwsstore under /app/ (mounted from
// app/static/app/). They are committed so the Docker image and air-gapped
// installs never need npm at build or run time.
export default defineConfig({
  plugins: [react()],
  base: '/app/',
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/test-setup.js',
  },
  build: {
    outDir: '../app/static/app',
    emptyOutDir: true,
  },
})
