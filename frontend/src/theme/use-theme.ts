/**
 * Theme selection. Three states: an explicit light or dark choice, or the
 * system preference when the user has never chosen (nothing stamped on <html>).
 */
import { useCallback, useEffect, useState } from 'react';

export type Theme = 'light' | 'dark';

const STORAGE_KEY = 'dioptra.theme';

function systemTheme(): Theme {
  return globalThis.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function readStoredTheme(): Theme {
  const stored = globalThis.localStorage?.getItem(STORAGE_KEY);
  return stored === 'light' || stored === 'dark' ? stored : systemTheme();
}

export function useTheme(): { theme: Theme; toggleTheme: () => void } {
  const [theme, setTheme] = useState<Theme>(readStoredTheme);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    globalThis.localStorage?.setItem(STORAGE_KEY, theme);
  }, [theme]);

  const toggleTheme = useCallback(() => {
    setTheme((current) => (current === 'dark' ? 'light' : 'dark'));
  }, []);

  return { theme, toggleTheme };
}
