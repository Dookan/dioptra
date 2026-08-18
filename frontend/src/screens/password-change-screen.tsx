/**
 * Forced password change. Seeded accounts land here before anything else; the
 * gate itself lives on the server, this screen only lets the user satisfy it.
 */
import { useId, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError } from '../api/client';
import { useAuth } from '../auth/auth-context';

export function PasswordChangeScreen(): React.ReactNode {
  const { t } = useTranslation();
  const { changePassword } = useAuth();
  const currentId = useId();
  const newId = useId();

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [errorKey, setErrorKey] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setErrorKey(null);
    setSubmitting(true);
    try {
      await changePassword(currentPassword, newPassword);
    } catch (error) {
      setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
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
          <h1>{t('passwordChange.title')}</h1>
        </div>
        <p className="sub">{t('passwordChange.reason')}</p>

        {errorKey !== null && (
          <p className="alert" role="alert">
            {t(errorKey)}
          </p>
        )}

        <div className="field">
          <label htmlFor={currentId}>{t('passwordChange.current')}</label>
          <input
            id={currentId}
            className="input"
            type="password"
            autoComplete="current-password"
            required
            value={currentPassword}
            onChange={(event) => {
              setCurrentPassword(event.target.value);
            }}
          />
        </div>

        <div className="field">
          <label htmlFor={newId}>{t('passwordChange.new')}</label>
          <input
            id={newId}
            className="input"
            type="password"
            autoComplete="new-password"
            required
            value={newPassword}
            onChange={(event) => {
              setNewPassword(event.target.value);
            }}
          />
          <p className="hint">{t('passwordChange.hint')}</p>
        </div>

        <button type="submit" className="btn primary" disabled={submitting}>
          {submitting ? t('passwordChange.submitting') : t('passwordChange.submit')}
        </button>
      </form>
    </div>
  );
}
