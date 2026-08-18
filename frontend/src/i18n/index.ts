/**
 * i18n setup. Both locale files are imported statically so they end up in the
 * bundle: nothing is fetched at runtime (CLAUDE.md -> Hard Rules -> No CDNs).
 */
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

import en from '../locales/en.json';
import es from '../locales/es.json';

export const SUPPORTED_LANGUAGES = ['es', 'en'] as const;
export type Language = (typeof SUPPORTED_LANGUAGES)[number];

export const DEFAULT_LANGUAGE: Language = 'es';
const STORAGE_KEY = 'dioptra.language';

export function readStoredLanguage(): Language {
  const stored = globalThis.localStorage?.getItem(STORAGE_KEY);
  return SUPPORTED_LANGUAGES.includes(stored as Language) ? (stored as Language) : DEFAULT_LANGUAGE;
}

export function storeLanguage(language: Language): void {
  globalThis.localStorage?.setItem(STORAGE_KEY, language);
}

void i18n.use(initReactI18next).init({
  resources: {
    es: { translation: es },
    en: { translation: en },
  },
  lng: readStoredLanguage(),
  fallbackLng: DEFAULT_LANGUAGE,
  interpolation: { escapeValue: false }, // React escapes on render already
  returnNull: false,
});

export default i18n;
