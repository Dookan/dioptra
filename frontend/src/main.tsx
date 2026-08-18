import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App } from './app';
import { AuthProvider } from './auth/auth-provider';
import './i18n';
import './theme/tokens.css';
import './theme/base.css';
import './theme/components.css';

const container = document.getElementById('root');
if (container === null) throw new Error('missing #root element');

createRoot(container).render(
  <StrictMode>
    <AuthProvider>
      <App />
    </AuthProvider>
  </StrictMode>,
);
