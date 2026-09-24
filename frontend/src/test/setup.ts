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

// jsdom ships <dialog> without showModal/close. The polyfill toggles `open`,
// which is what the accessibility tree reads; focus trapping is the browser's.
if (typeof HTMLDialogElement.prototype.showModal !== 'function') {
  HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
    this.setAttribute('open', '');
  };
  HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
    this.removeAttribute('open');
    this.dispatchEvent(new Event('close'));
  };
}
