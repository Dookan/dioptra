import { useTranslation } from 'react-i18next';

import type { Theme } from '../theme/use-theme';

interface Props {
  theme: Theme;
  onToggle: () => void;
}

export function ThemeToggle({ theme, onToggle }: Props): React.ReactNode {
  const { t } = useTranslation();
  // Names the state the click leads to. It rides on `title` (accessible
  // DESCRIPTION) rather than `aria-label`: overriding the name would leave a
  // voice-control user unable to activate the button by the words it displays
  // (WCAG 2.5.3, Label in Name).
  const nextState = theme === 'dark' ? t('theme.light') : t('theme.dark');

  return (
    <button type="button" className="btn ghost" onClick={onToggle} title={nextState}>
      <span aria-hidden="true">◐</span> {t('theme.toggle')}
    </button>
  );
}
