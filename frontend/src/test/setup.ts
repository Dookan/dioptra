import '@testing-library/jest-dom/vitest';

import { afterEach, vi } from 'vitest';

import i18n from '../i18n';

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
  document.documentElement.removeAttribute('data-theme');
  void i18n.changeLanguage('es');
});

// jsdom ships no matchMedia; the theme hook asks for the system preference.
Object.defineProperty(globalThis, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }),
});
