import react from '@vitejs/plugin-react';
// vitest/config re-exports Vite's defineConfig with the `test` section typed.
import { defineConfig } from 'vitest/config';

// Everything is bundled and served from our own origin: no CDN, no remote font,
// no runtime fetch to a third party (CLAUDE.md -> Hard Rules -> No CDNs).
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    sourcemap: true,
    target: 'es2023',
  },
  server: {
    port: 5173,
    // Dev only: the API runs on its own port until the production build is
    // served by the same nginx that serves these assets.
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: false,
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/test/**', 'src/main.tsx'],
    },
  },
});
