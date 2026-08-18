/** Sign-in screen. Visual anchor: docs/mockups/index.html screen 01. */
import { useId, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError } from '../api/client';
import { useAuth } from '../auth/auth-context';
import { LanguageToggle } from '../components/language-toggle';
import { ThemeToggle } from '../components/theme-toggle';
import { useTheme } from '../theme/use-theme';

export function LoginScreen(): React.ReactNode {
  const { t } = useTranslation();
  const { signIn } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const usernameId = useId();
  const passwordId = useId();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [errorKey, setErrorKey] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setErrorKey(null);
    setSubmitting(true);
    try {
      await signIn(username, password);
    } catch (error) {
      // The server sends a key, never a sentence: the UI owns the wording.
      setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
      setPassword('');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="login-wrap">
      <form className="login" onSubmit={(event) => void handleSubmit(event)} noValidate>
        <div className="brandrow">
          <div className="brandmark" aria-hidden="true">
            {t('app.brandInitials')}
          </div>
          <h1>{t('app.name')}</h1>
        </div>
        <p className="sub">{t('login.greeting')}</p>

        {errorKey !== null && (
          <p className="alert" role="alert">
            {t(errorKey)}
          </p>
        )}

        <div className="field">
          <label htmlFor={usernameId}>{t('login.username')}</label>
          <input
            id={usernameId}
            className="input"
            name="username"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            required
            value={username}
            onChange={(event) => {
              setUsername(event.target.value);
            }}
          />
        </div>

        <div className="field">
          <label htmlFor={passwordId}>{t('login.password')}</label>
          <input
            id={passwordId}
            className="input"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
            }}
          />
        </div>

        <button type="submit" className="btn primary" disabled={submitting}>
          {submitting ? t('login.submitting') : t('login.submit')}
        </button>

        <p className="hint">{t('login.noAccount')}</p>

        <div className="foot">
          <LanguageToggle />
          <ThemeToggle theme={theme} onToggle={toggleTheme} />
          <span className="mono">{t('app.version')}</span>
        </div>
      </form>
    </div>
  );
}
