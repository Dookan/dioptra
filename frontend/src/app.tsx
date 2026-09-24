/**
 * Screen selection.
 *
 * The session state picks between login, forced password change and the
 * authenticated shell; inside the shell a hash route picks the screen
 * (src/navigation/use-route.ts).
 */
import { useTranslation } from 'react-i18next';

import { useAuth } from './auth/auth-context';
import { useRoute } from './navigation/use-route';
import { ReportJobProvider } from './report-jobs/report-job-provider';
import { AuditScreen } from './screens/audit-screen';
import { FindingsScreen } from './screens/findings-screen';
import { InventoryScreen } from './screens/inventory-screen';
import { HomeScreen } from './screens/home-screen';
import { LoginScreen } from './screens/login-screen';
import { PasswordChangeScreen } from './screens/password-change-screen';
import { ProjectScreen } from './screens/project-screen';
import { ProjectsScreen } from './screens/projects-screen';
import { ReportScreen } from './screens/report-screen';
import { CaseDesignScreen } from './screens/case-design-screen';
import { TestPlanScreen } from './screens/test-plan-screen';
import { TestWritingScreen } from './screens/test-writing-screen';
import { VerificationScreen } from './screens/verification-screen';

function Authenticated(): React.ReactNode {
  const { route, navigate } = useRoute();
  switch (route.kind) {
    case 'projects':
      return <ProjectsScreen route={route} onNavigate={navigate} />;
    case 'project':
      return <ProjectScreen route={route} projectId={route.id} onNavigate={navigate} />;
    case 'findings':
      return <FindingsScreen route={route} onNavigate={navigate} />;
    case 'plan':
      return <TestPlanScreen route={route} onNavigate={navigate} />;
    case 'design':
      return <CaseDesignScreen route={route} onNavigate={navigate} />;
    case 'tests':
      return <TestWritingScreen route={route} onNavigate={navigate} />;
    case 'verify':
      return <VerificationScreen route={route} onNavigate={navigate} />;
    case 'report':
      return <ReportScreen route={route} onNavigate={navigate} />;
    case 'inventory':
      return <InventoryScreen route={route} onNavigate={navigate} />;
    case 'audit':
      return <AuditScreen route={route} onNavigate={navigate} />;
    case 'home':
      return <HomeScreen route={route} onNavigate={navigate} />;
  }
}

export function App(): React.ReactNode {
  const { status } = useAuth();
  const { t } = useTranslation();

  switch (status) {
    case 'loading':
      return (
        <div className="login-wrap">
          <p className="sub">{t('app.name')}</p>
        </div>
      );
    case 'password-change':
      return <PasswordChangeScreen />;
    case 'authenticated':
      // Above every screen: the PDF job outlives the screen it started on.
      return (
        <ReportJobProvider>
          <Authenticated />
        </ReportJobProvider>
      );
    case 'anonymous':
      return <LoginScreen />;
  }
}
