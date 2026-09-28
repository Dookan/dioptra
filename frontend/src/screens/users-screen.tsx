/**
 * Account administration (phase 6). Mockup anchor: screen 10 "Usuarios y
 * bitácora", its Usuarios half — here a tab and a route of its own, admin only
 * (navigation/access.ts); the server refuses every other role regardless.
 *
 * Recorded deviations (docs/ui-model.md → Usuarios): "+ Invitar" becomes
 * "Crear cuenta" and the pending-invitation row becomes "debe cambiar la
 * contraseña" — the account is created outright with a password the admin
 * hands over; the per-user activity counts and the status-bar totals are not
 * drawn (no such aggregate exists; Bitácora answers "what did this person do").
 *
 * Every change but creation asks for a written reason first and disables its
 * button below ten characters. That mirrors the server's floor, which is the
 * enforcement; a refusal keeps the form and the reason as typed.
 */
import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import type { Role } from '../api/auth';
import { ApiError } from '../api/client';
import * as api from '../api/users';
import type { Account } from '../api/users';
import { useAuth } from '../auth/auth-context';
import { AppShell } from '../components/app-shell';
import { initials } from '../components/initials';
import { PasswordInput } from '../components/password-input';
import type { Route } from '../navigation/use-route';

interface Props {
  route: Extract<Route, { kind: 'users' }>;
  onNavigate: (route: Route) => void;
}

const ROLES: Role[] = ['admin', 'analyst', 'developer'];
const BADGE: Record<Role, string> = { admin: 'badge info', analyst: 'badge ok', developer: 'badge warn' };
const MIN_REASON = 10;

function errorKeyOf(error: unknown): string {
  return error instanceof ApiError ? error.messageKey : 'errors.internal';
}

function AccountRow({
  account,
  selected,
  onSelect,
}: {
  account: Account;
  selected: boolean;
  onSelect: () => void;
}): React.ReactNode {
  const { t, i18n } = useTranslation();
  const date = (iso: string): string =>
    new Date(iso).toLocaleDateString(i18n.resolvedLanguage, { dateStyle: 'medium' });
  const state = [
    t(`roles.${account.role}`),
    account.disabled ? t('users.state.disabled') : t('users.state.active'),
  ];
  if (account.must_change_password) state.push(t('users.state.mustChange'));
  const access =
    account.last_login_at === null
      ? t('users.neverLoggedIn')
      : t('users.lastLogin', { date: date(account.last_login_at) });
  const locked =
    account.locked_until !== null && new Date(account.locked_until) > new Date()
      ? t('users.lockedUntil', { date: date(account.locked_until) })
      : null;
  return (
    <li className={['rowline', selected ? 'sel' : '', account.disabled ? 'off' : ''].filter(Boolean).join(' ')}>
      <span className="avatar" aria-hidden="true">
        {initials(account.display_name)}
      </span>
      <button type="button" className="grow linklike" onClick={onSelect} aria-pressed={selected}>
        <b>{account.username}</b>
        <span className="sub">{state.join(' · ')}</span>
        <span className="sub">
          {access}
          {locked !== null && ` · ${locked}`}
        </span>
      </button>
      <span className={BADGE[account.role]}>{t(`roles.${account.role}`)}</span>
    </li>
  );
}

function CreateForm({
  onCreated,
  onCancel,
}: {
  onCreated: (account: Account) => void;
  onCancel: () => void;
}): React.ReactNode {
  const { t } = useTranslation();
  const { accessToken } = useAuth();
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<Role>('developer');
  const [password, setPassword] = useState('');
  const [mask, setMask] = useState(0);
  const [busy, setBusy] = useState(false);
  const [errorKey, setErrorKey] = useState<string | null>(null);

  const submit = async (): Promise<void> => {
    setBusy(true);
    setErrorKey(null);
    setMask((value) => value + 1);
    try {
      const created = await api.createAccount(accessToken ?? '', {
        username,
        display_name: displayName,
        email: email.trim() === '' ? null : email,
        role,
        password,
      });
      onCreated(created);
    } catch (error) {
      setErrorKey(errorKeyOf(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <h4>{t('users.create.title')}</h4>
      <p className="note">{t('users.create.note')}</p>
      <div className="field">
        <label htmlFor="user-username">{t('users.create.username')}</label>
        <input
          id="user-username"
          className="input"
          autoComplete="off"
          value={username}
          onChange={(event) => {
            setUsername(event.target.value);
          }}
        />
        <p className="hint">{t('users.create.usernameHint')}</p>
      </div>
      <div className="field">
        <label htmlFor="user-name">{t('users.create.displayName')}</label>
        <input
          id="user-name"
          className="input"
          maxLength={120}
          value={displayName}
          onChange={(event) => {
            setDisplayName(event.target.value);
          }}
        />
      </div>
      <div className="field">
        <label htmlFor="user-email">{t('users.create.email')}</label>
        <input
          id="user-email"
          className="input"
          type="email"
          maxLength={254}
          value={email}
          onChange={(event) => {
            setEmail(event.target.value);
          }}
        />
      </div>
      <div className="field">
        <label htmlFor="user-role">{t('users.create.role')}</label>
        <select
          id="user-role"
          className="input"
          value={role}
          onChange={(event) => {
            setRole(event.target.value as Role);
          }}
        >
          {ROLES.map((option) => (
            <option key={option} value={option}>
              {t(`roles.${option}`)}
            </option>
          ))}
        </select>
      </div>
      <div className="field">
        <label htmlFor="user-password">{t('users.create.password')}</label>
        <PasswordInput
          id="user-password"
          autoComplete="new-password"
          value={password}
          onChange={setPassword}
          maskSignal={mask}
        />
      </div>
      {errorKey !== null && (
        <p className="alert inline" role="alert">
          {t(errorKey)}
        </p>
      )}
      <div className="actions">
        <button
          type="submit"
          className="btn primary"
          disabled={busy || username.trim() === '' || displayName.trim() === '' || password === ''}
        >
          {t('users.create.submit')}
        </button>
        <button type="button" className="btn ghost" onClick={onCancel}>
          {t('users.create.cancel')}
        </button>
      </div>
    </form>
  );
}

function AccountActions({
  account,
  onChanged,
}: {
  account: Account;
  onChanged: (account: Account, noticeKey: string) => void;
}): React.ReactNode {
  const { t } = useTranslation();
  const { accessToken } = useAuth();
  const [reason, setReason] = useState('');
  const [role, setRole] = useState<Role>(account.role);
  const [password, setPassword] = useState('');
  const [mask, setMask] = useState(0);
  const [busy, setBusy] = useState(false);
  const [errorKey, setErrorKey] = useState<string | null>(null);
  const token = accessToken ?? '';
  const reasonReady = reason.trim().length >= MIN_REASON;

  const act = async (call: () => Promise<Account>, noticeKey: string): Promise<void> => {
    setBusy(true);
    setErrorKey(null);
    setMask((value) => value + 1);
    try {
      const updated = await call();
      setReason('');
      setPassword('');
      onChanged(updated, noticeKey);
    } catch (error) {
      // The form and the reason stay as typed: only the server's sentence changes.
      setErrorKey(errorKeyOf(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h4>{t('users.actions.title', { username: account.username })}</h4>
      <div className="field">
        <label htmlFor="user-reason">{t('users.actions.reasonLabel')}</label>
        <textarea
          id="user-reason"
          className="input textarea"
          value={reason}
          onChange={(event) => {
            setReason(event.target.value);
          }}
        />
        <p className="hint">{t('users.actions.reasonHint')}</p>
      </div>

      <div className="field">
        <label htmlFor="user-new-role">{t('users.actions.roleLabel')}</label>
        <select
          id="user-new-role"
          className="input"
          value={role}
          onChange={(event) => {
            setRole(event.target.value as Role);
          }}
        >
          {ROLES.map((option) => (
            <option key={option} value={option}>
              {t(`roles.${option}`)}
            </option>
          ))}
        </select>
      </div>
      <div className="actions">
        <button
          type="button"
          className="btn"
          disabled={busy || !reasonReady || role === account.role}
          onClick={() => void act(() => api.changeRole(token, account.id, role, reason), 'users.notice.role')}
        >
          {t('users.actions.changeRole')}
        </button>
      </div>

      <div className="field">
        <label htmlFor="user-reset">{t('users.actions.passwordLabel')}</label>
        <PasswordInput
          id="user-reset"
          autoComplete="new-password"
          value={password}
          onChange={setPassword}
          maskSignal={mask}
        />
        <p className="note">{t('users.actions.passwordHint')}</p>
      </div>
      <div className="actions">
        <button
          type="button"
          className="btn"
          disabled={busy || !reasonReady || password === ''}
          onClick={() =>
            void act(
              () => api.resetPassword(token, account.id, password, reason),
              'users.notice.reset',
            )
          }
        >
          {t('users.actions.resetPassword')}
        </button>
      </div>

      <p className="note">
        {account.disabled ? t('users.actions.enableNote') : t('users.actions.disableNote')}
      </p>
      <div className="actions">
        <button
          type="button"
          className="btn"
          disabled={busy || !reasonReady}
          onClick={() =>
            void act(
              () => api.setDisabled(token, account.id, !account.disabled, reason),
              account.disabled ? 'users.notice.enabled' : 'users.notice.disabled',
            )
          }
        >
          {account.disabled ? t('users.actions.enable') : t('users.actions.disable')}
        </button>
      </div>

      {errorKey !== null && (
        <p className="alert inline" role="alert">
          {t(errorKey)}
        </p>
      )}
    </div>
  );
}

export function UsersScreen({ route, onNavigate }: Props): React.ReactNode {
  const { t } = useTranslation();
  const { accessToken, user } = useAuth();
  const [accounts, setAccounts] = useState<Account[] | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [errorKey, setErrorKey] = useState<string | null>(null);

  const load = useCallback(() => {
    if (accessToken === null) return;
    api
      .listAccounts(accessToken)
      .then(setAccounts)
      .catch((error: unknown) => {
        setErrorKey(errorKeyOf(error));
      });
  }, [accessToken]);

  useEffect(load, [load]);

  const current = accounts?.find((account) => account.id === selected) ?? null;
  const replace = (updated: Account): void => {
    setAccounts((list) =>
      list === null
        ? list
        : [...list.filter((account) => account.id !== updated.id), updated].sort((a, b) =>
            a.username.localeCompare(b.username),
          ),
    );
  };

  return (
    <AppShell route={route} onNavigate={onNavigate}>
      {errorKey !== null && (
        <p className="alert" role="alert">
          {t(errorKey)}
        </p>
      )}
      <div className="pagehead">
        <h2>{t('users.title')}</h2>
        <p className="sub">{t('users.subtitle')}</p>
      </div>
      <div className="cols users">
        <section className="panel">
          <div className="panelhead">
            <h4>{t('users.panel')}</h4>
            <button
              type="button"
              className="btn primary"
              onClick={() => {
                setCreating(true);
                setSelected(null);
                setNotice(null);
              }}
            >
              {t('users.create.open')}
            </button>
          </div>
          {accounts === null ? (
            <p className="hint">{t('users.loading')}</p>
          ) : (
            <ul className="caselist">
              {accounts.map((account) => (
                <AccountRow
                  key={account.id}
                  account={account}
                  selected={account.id === selected}
                  onSelect={() => {
                    setSelected(account.id);
                    setCreating(false);
                    setNotice(null);
                  }}
                />
              ))}
            </ul>
          )}
        </section>
        <section className="panel">
          {creating ? (
            <CreateForm
              onCreated={(account) => {
                replace(account);
                setCreating(false);
                setSelected(account.id);
                setNotice('users.notice.created');
              }}
              onCancel={() => {
                setCreating(false);
              }}
            />
          ) : current === null ? (
            <p className="hint">{t('users.pick')}</p>
          ) : current.id === user?.id ? (
            <p className="note">{t('users.self')}</p>
          ) : (
            <AccountActions
              key={current.id}
              account={current}
              onChanged={(account, noticeKey) => {
                replace(account);
                setNotice(noticeKey);
              }}
            />
          )}
          {notice !== null && (
            <p className="hint ok" role="status">
              {t(notice)}
            </p>
          )}
        </section>
      </div>
    </AppShell>
  );
}
