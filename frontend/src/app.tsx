/**
 * Screen selection.
 *
 * Phase 0 has three states and no URLs worth bookmarking, so the session state
 * picks the screen directly. Routing arrives with the workflow screens (P2/P3).
 */
import { useTranslation } from 'react-i18next';

import { useAuth } from './auth/auth-context';
import { HomeScreen } from './screens/home-screen';
import { LoginScreen } from './screens/login-screen';
import { PasswordChangeScreen } from './screens/password-change-screen';

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
      return <HomeScreen />;
    case 'anonymous':
      return <LoginScreen />;
  }
}
