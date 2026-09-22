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
import { HomeScreen } from './screens/home-screen';
import { LoginScreen } from './screens/login-screen';
import { PasswordChangeScreen } from './screens/password-change-screen';
import { ProjectScreen } from './screens/project-screen';
import { ProjectsScreen } from './screens/projects-screen';

function Authenticated(): React.ReactNode {
  const { route, navigate } = useRoute();
  switch (route.kind) {
    case 'projects':
      return <ProjectsScreen route={route} onNavigate={navigate} />;
    case 'project':
      return <ProjectScreen route={route} projectId={route.id} onNavigate={navigate} />;
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
      return <Authenticated />;
    case 'anonymous':
      return <LoginScreen />;
  }
}
