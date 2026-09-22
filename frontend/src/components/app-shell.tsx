/**
 * Application chrome shared by every authenticated screen: the appbar (brand,
 * language, theme, avatar, sign out) and the tabs bar. Mockup anchor: the
 * appbar + tabsbar of screens 02–11 in docs/mockups/index.html.
 */
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';

import { useAuth } from '../auth/auth-context';
import { hrefFor, type Route } from '../navigation/use-route';
import { useTheme } from '../theme/use-theme';
import { initials } from './initials';
import { LanguageToggle } from './language-toggle';
import { ThemeToggle } from './theme-toggle';

interface Props {
  route: Route;
  onNavigate: (route: Route) => void;
  /** Right-hand text of the tabs bar (project name, role). */
  context?: string;
  children: ReactNode;
}

type TabKey = 'home' | 'projects' | 'findings' | 'report';

/**
 * Inicio and Proyectos always; Hallazgos and Reporte (mockups 04 and 09) once
 * the route names an analysis — they are meaningless without one.
 */
function tabsFor(route: Route): { key: TabKey; route: Route }[] {
  const tabs: { key: TabKey; route: Route }[] = [
    { key: 'home', route: { kind: 'home' } },
    { key: 'projects', route: { kind: 'projects' } },
  ];
  if (route.kind === 'findings' || route.kind === 'report') {
    const { id, analysisId } = route;
    tabs.push(
      { key: 'findings', route: { kind: 'findings', id, analysisId } },
      { key: 'report', route: { kind: 'report', id, analysisId } },
    );
  }
  return tabs;
}

function isActive(tab: Route, route: Route): boolean {
  if (tab.kind === 'projects') return route.kind === 'projects' || route.kind === 'project';
  return tab.kind === route.kind;
}

export function AppShell({ route, onNavigate, context, children }: Props): ReactNode {
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
      <nav className="tabsbar" aria-label={t('nav.label')}>
        {tabsFor(route).map((tab) => (
          <a
            key={tab.key}
            className={isActive(tab.route, route) ? 'ptab on' : 'ptab'}
            href={hrefFor(tab.route)}
            aria-current={isActive(tab.route, route) ? 'page' : undefined}
            onClick={(event) => {
              event.preventDefault();
              onNavigate(tab.route);
            }}
          >
            {t(`nav.${tab.key}`)}
          </a>
        ))}
        <span className="right">{context ?? t(`roles.${user.role}`)}</span>
      </nav>
      <main className="content">{children}</main>
    </>
  );
}
