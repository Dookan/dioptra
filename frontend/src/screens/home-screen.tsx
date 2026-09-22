/**
 * Home: greeting and the "continue where you left off" banner pointing at the
 * projects. The full home of mockup 02 (cards with progress) belongs to P2.
 */
import { useTranslation } from 'react-i18next';

import { useAuth } from '../auth/auth-context';
import { AppShell } from '../components/app-shell';
import type { Route } from '../navigation/use-route';

interface Props {
  route: Route;
  onNavigate: (route: Route) => void;
}

export function HomeScreen({ route, onNavigate }: Props): React.ReactNode {
  const { t } = useTranslation();
  const { user } = useAuth();

  if (user === null) return null;

  return (
    <AppShell route={route} onNavigate={onNavigate}>
      <div className="pagehead">
        <h2>{t('home.greeting', { name: user.display_name })}</h2>
        <p className="sub">{t('home.subtitle')}</p>
      </div>
      <section className="nextstep">
        <div className="txt">
          <b>{t('home.nextStepTitle')}</b>
          <div>{t('home.nextStepBody')}</div>
        </div>
        <button
          type="button"
          className="btn primary"
          onClick={() => {
            onNavigate({ kind: 'projects' });
          }}
        >
          {t('home.goToProjects')}
        </button>
      </section>
    </AppShell>
  );
}
