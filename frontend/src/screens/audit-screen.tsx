/**
 * The audit log. Mockup anchor: screen 10 "Usuarios y bitácora" — its
 * Bitácora half: "quién hizo qué y cuándo", one sentence per row, filterable
 * by Hoy / Semana / Todo. The Usuarios half (account management) has no
 * endpoint and is not in the plan's day table; it is not built (recorded in
 * tasks/phase5-survey.md §8).
 *
 * The server scopes the rows by role; the screen never filters for
 * authorization. Targets and justifications are the writers' text and render
 * as text nodes.
 */
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import * as api from '../api/audit';
import type { AuditEntry } from '../api/audit';
import { ApiError } from '../api/client';
import { useAuth } from '../auth/auth-context';
import { AppShell } from '../components/app-shell';
import type { Route } from '../navigation/use-route';

interface Props {
  route: Extract<Route, { kind: 'audit' }>;
  onNavigate: (route: Route) => void;
}

type Window = 'today' | 'week' | 'all';
const WINDOWS: Window[] = ['today', 'week', 'all'];

function sinceFor(window: Window): string | undefined {
  if (window === 'all') return undefined;
  const now = new Date();
  if (window === 'today') {
    const start = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    return start.toISOString();
  }
  return new Date(now.getTime() - 7 * 24 * 3600 * 1000).toISOString();
}

/** Actions the backend writes today (grep `action=` under backend/app). */
const KNOWN_ACTIONS = new Set([
  'auth.login',
  'auth.logout',
  'auth.refresh',
  'auth.password_change',
  'authz.denied',
  'project.create',
  'analysis.ingest.zip',
  'analysis.ingest.git',
  'finding.verdict.confirmed',
  'finding.verdict.false_positive',
  'report.edit',
  'report.sign',
  'stage.advance',
  'testplan.save',
  'design.diagram.edit',
  'design.cases.save',
  'design.cases.approve',
  'tests.save',
  'verification.run',
  'verification.reopen',
  'verification.mutant.equivalent',
  'vulndb.sync.request',
  'vulndb.import.request',
  'vulndb.sync',
  'vulndb.import',
  'report.export.request',
  'report.export',
  'report.export.download',
]);

function Row({ entry }: { entry: AuditEntry }): React.ReactNode {
  const { t, i18n } = useTranslation();
  const time = new Date(entry.occurred_at).toLocaleTimeString(i18n.resolvedLanguage, {
    timeStyle: 'short',
  });
  const day = new Date(entry.occurred_at).toLocaleDateString(i18n.resolvedLanguage, {
    dateStyle: 'medium',
  });
  const sentence = KNOWN_ACTIONS.has(entry.action) ? (
    t(`audit.action.${entry.action}`)
  ) : (
    <span className="mono">{entry.action}</span>
  );
  return (
    <li className="rowline">
      <span className="mono" title={day}>
        {time}
      </span>
      <div className="grow">
        <b>{entry.actor_username === 'system' ? t('audit.systemActor') : entry.actor_username}</b>{' '}
        {sentence}
        {entry.outcome !== 'ok' && (
          <>
            {' '}
            <span className="badge err">{t(`audit.outcome.${entry.outcome}`)}</span>
          </>
        )}
        <div className="sub">
          {day}
          {entry.target !== null && ` · ${entry.target}`}
          {entry.justification !== null &&
            ` · ${t('audit.justification')}: "${entry.justification}"`}
        </div>
      </div>
    </li>
  );
}

export function AuditScreen({ route, onNavigate }: Props): React.ReactNode {
  const { t } = useTranslation();
  const { accessToken, user } = useAuth();
  const [window, setWindow] = useState<Window>('today');
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [errorKey, setErrorKey] = useState<string | null>(null);

  useEffect(() => {
    if (accessToken === null) return;
    let cancelled = false;
    setEntries(null);
    api
      .getAuditLog(accessToken, { since: sinceFor(window), limit: 500 })
      .then((loaded) => {
        if (!cancelled) setEntries(loaded);
      })
      .catch((error: unknown) => {
        if (!cancelled) setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
      });
    return () => {
      cancelled = true;
    };
  }, [accessToken, window]);

  return (
    <AppShell route={route} onNavigate={onNavigate}>
      {errorKey !== null && (
        <p className="alert" role="alert">
          {t(errorKey)}
        </p>
      )}
      <div className="pagehead">
        <h2>{t('audit.title')}</h2>
        <p className="sub">
          {user?.role === 'admin' ? t('audit.subtitleAdmin') : t('audit.subtitleOwn')}
        </p>
      </div>
      <section className="panel">
        <div className="panelhead">
          <h4>{t('audit.panel')}</h4>
          <div className="radios" role="group" aria-label={t('audit.windowLabel')}>
            {WINDOWS.map((option) => (
              <button
                key={option}
                type="button"
                className={window === option ? 'radio on' : 'radio'}
                aria-pressed={window === option}
                onClick={() => {
                  setWindow(option);
                }}
              >
                {t(`audit.window.${option}`)}
              </button>
            ))}
          </div>
        </div>
        {entries === null ? (
          <p className="hint">{t('audit.loading')}</p>
        ) : entries.length === 0 ? (
          <p className="hint">{t('audit.none')}</p>
        ) : (
          <ul className="caselist">
            {entries.map((entry) => (
              <Row key={entry.id} entry={entry} />
            ))}
          </ul>
        )}
      </section>
    </AppShell>
  );
}
