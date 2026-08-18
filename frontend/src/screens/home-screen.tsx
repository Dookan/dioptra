/**
 * Placeholder home. Phase 0 only proves the session works end to end; the real
 * home (mockup 02, with projects and progress) belongs to phase 2.
 */
import { useTranslation } from 'react-i18next';

import { useAuth } from '../auth/auth-context';
import { LanguageToggle } from '../components/language-toggle';
import { ThemeToggle } from '../components/theme-toggle';
import { useTheme } from '../theme/use-theme';

function initials(displayName: string): string {
  return displayName
    .split(' ')
    .slice(0, 2)
    .map((part) => part.charAt(0).toUpperCase())
    .join('');
}

export function HomeScreen(): React.ReactNode {
  const { t } = useTranslation();
  const { user, signOut } = useAuth();
  const { theme, toggleTheme } = useTheme();

  if (user === null) return null;

  return (
    <>
      <header className="appbar">
        <div className="brand">
          <div className="brandmark" aria-hidden="true">
            {t('app.brandInitials')}
          </div>
          {t('app.name')}
        </div>
        <div className="right">
          <LanguageToggle />
          <ThemeToggle theme={theme} onToggle={toggleTheme} />
          <span className="avatar" aria-hidden="true">
            {initials(user.display_name)}
          </span>
          <span>{user.username}</span>
          <span>{t(`roles.${user.role}`)}</span>
          <button type="button" className="btn ghost" onClick={() => void signOut()}>
            {t('home.signOut')}
          </button>
        </div>
      </header>

      <main className="content">
        <div className="pagehead">
          <h2>{t('home.greeting', { name: user.display_name })}</h2>
          <p className="sub">{t('home.subtitle')}</p>
        </div>
        <section className="nextstep">
          <div>
            <b>{t('home.nextStepTitle')}</b>
            <div>{t('home.nextStepBody')}</div>
          </div>
        </section>
      </main>
    </>
  );
}
