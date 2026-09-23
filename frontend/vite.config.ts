import { readFileSync } from 'node:fs';

import react from '@vitejs/plugin-react';
// vitest/config re-exports Vite's defineConfig with the `test` section typed.
import { defineConfig } from 'vitest/config';

// The status bar shows the bundle's own version (mockups 02–11); one source: package.json.
const { version } = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as {
  version: string;
};

// Everything is bundled and served from our own origin: no CDN, no remote font,
// no runtime fetch to a third party (CLAUDE.md -> Hard Rules -> No CDNs).
export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(version),
  },
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
    // Pin a POSITIVE UTC offset. Date code that builds an ISO day through
    // `toISOString()` is correct at a negative offset and wrong at a positive
    // one, so a machine in the Americas cannot fail it — the calendar picker's
    // "ISO from local calendar parts" claim was unfalsifiable until this line.
    env: { TZ: 'Europe/Madrid' },
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
