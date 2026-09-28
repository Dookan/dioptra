/**
 * What a role sees when it opens, by hash, a screen the role map forbids
 * (navigation/access.ts). Rendered INSTEAD of the screen, so the screen's own
 * requests are never made — the server would refuse them anyway.
 */
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';

import type { Route } from '../navigation/use-route';
import { AppShell } from './app-shell';

interface Props {
  route: Route;
  onNavigate: (route: Route) => void;
}

export function AccessRefused({ route, onNavigate }: Props): ReactNode {
  const { t } = useTranslation();
  return (
    <AppShell route={route} onNavigate={onNavigate}>
      <div className="pagehead">
        <h2>{t('access.refusedTitle')}</h2>
        <p className="sub">{t('access.refusedBody')}</p>
      </div>
      <button
        type="button"
        className="btn primary"
        onClick={() => {
          onNavigate({ kind: 'home' });
        }}
      >
        {t('access.backHome')}
      </button>
    </AppShell>
  );
}
