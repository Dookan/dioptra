/**
 * Application chrome shared by every authenticated screen: the appbar (brand,
 * language, theme, avatar, sign out) and the tabs bar. Mockup anchor: the
 * appbar + tabsbar of screens 02–11 in docs/mockups/index.html.
 */
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';

import { useAuth } from '../auth/auth-context';
import type { Role } from '../api/auth';
import { mayOpen } from '../navigation/access';
import { hrefFor, type Route } from '../navigation/use-route';
import { useTheme } from '../theme/use-theme';
import { initials } from './initials';
import { LanguageToggle } from './language-toggle';
import { STAGES, stageIndex } from './stages';
import { ThemeToggle } from './theme-toggle';

interface Props {
  route: Route;
  onNavigate: (route: Route) => void;
  /** Right-hand text of the tabs bar (project name, role). */
  context?: string;
  /** Current workflow stage of the analysis in context; shows the status bar. */
  stage?: string;
  children: ReactNode;
}

type TabKey =
  | 'home'
  | 'projects'
  | 'findings'
  | 'workflow'
  | 'report'
  | 'inventory'
  | 'audit'
  | 'users';

/**
 * Inicio and Proyectos always; Hallazgos, Workflow and Reporte (mockups 04,
 * 05 and 09) once the route names an analysis — they are meaningless without
 * one; Inventario and Bitácora (mockups 11 and 10) always, after them, as
 * every tabs bar of the mockups shows; Usuarios last, as mockup 10 draws it.
 * Workflow opens the current stage's screen. Every tab goes through the role
 * map (navigation/access.ts): a role never sees a tab it cannot open.
 */
function tabsFor(
  route: Route,
  stage: string | undefined,
  role: Role,
): { key: TabKey; route: Route }[] {
  const tabs: { key: TabKey; route: Route }[] = [
    { key: 'home', route: { kind: 'home' } },
    { key: 'projects', route: { kind: 'projects' } },
  ];
  if ('analysisId' in route) {
    const { id, analysisId } = route;
    // Workflow opens the current stage's screen: E4 until the plan closes,
    // then E5, then E6 once the cases are approved and the stage moves on.
    const workflow =
      stage === undefined
        ? 'plan'
        : stageIndex(stage) >= stageIndex('verification')
          ? 'verify'
          : stageIndex(stage) >= stageIndex('tests')
            ? 'tests'
            : stageIndex(stage) >= stageIndex('design')
              ? 'design'
              : 'plan';
    tabs.push(
      { key: 'findings', route: { kind: 'findings', id, analysisId } },
      { key: 'workflow', route: { kind: workflow, id, analysisId } },
      { key: 'report', route: { kind: 'report', id, analysisId } },
    );
  }
  tabs.push(
    { key: 'inventory', route: { kind: 'inventory' } },
    { key: 'audit', route: { kind: 'audit' } },
    { key: 'users', route: { kind: 'users' } },
  );
  return tabs.filter((tab) => mayOpen(tab.route.kind, role));
}

function isActive(tab: Route, route: Route): boolean {
  if (tab.kind === 'projects') return route.kind === 'projects' || route.kind === 'project';
  const WORKFLOW_KINDS = ['plan', 'design', 'tests', 'verify'];
  if (WORKFLOW_KINDS.includes(tab.kind)) return WORKFLOW_KINDS.includes(route.kind);
  return tab.kind === route.kind;
}

export function AppShell({ route, onNavigate, context, stage, children }: Props): ReactNode {
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
        {tabsFor(route, stage, user.role).map((tab) => (
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
      {stage !== undefined && (
        <footer className="statusbar">
          <div className="z">
            <span className="avatar small" aria-hidden="true">
              {initials(user.display_name)}
            </span>
            {user.username} · {t(`roles.${user.role}`)}
          </div>
          <div className="mid">
            {t('statusbar.step', {
              step: stageIndex(stage) + 1,
              total: STAGES.length,
              // Long-form names here (mockup status bars), short names in the stepper.
              stage: t(`statusbar.stage.${STAGES[stageIndex(stage)] ?? 'register'}`),
            })}
          </div>
          <div className="z">
            <span className="mono">v{__APP_VERSION__}</span>
          </div>
        </footer>
      )}
    </>
  );
}
