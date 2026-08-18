/** Session lifecycle: boot, forced password change, sign-out. */
import es from '../locales/es.json';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { App } from '../app';
import { NO_SESSION, stubFetch, type Routes } from '../test/http';
import { AuthProvider } from './auth-provider';

function profile(overrides: Record<string, unknown> = {}) {
  return {
    id: '0f9b2a5e-0000-4000-8000-000000000001',
    username: 'mmarin',
    display_name: 'Moises Marin',
    role: 'analyst',
    must_change_password: false,
    ...overrides,
  };
}

function session(overrides: Record<string, unknown> = {}) {
  return {
    status: 200,
    body: {
      access_token: 'an-access-token',
      token_type: 'bearer',
      expires_in: 900,
      user: profile(overrides),
    },
  };
}

function renderApp(routes: Routes) {
  const calls = stubFetch(routes);
  render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
  return calls;
}

describe('auth provider', () => {
  it('restores the session from the refresh cookie on boot', async () => {
    renderApp({ '/api/v1/auth/refresh': session() });

    expect(await screen.findByText(es.home.greeting.replace('{{name}}', 'Moises Marin'))).toBeInTheDocument();
  });

  it('shows the login screen when there is no valid cookie', async () => {
    renderApp({ '/api/v1/auth/refresh': NO_SESSION });

    expect(await screen.findByRole('button', { name: es.login.submit })).toBeInTheDocument();
  });

  it('forces a password change before the application is reachable', async () => {
    renderApp({ '/api/v1/auth/refresh': session({ must_change_password: true }) });

    expect(await screen.findByText(es.passwordChange.title)).toBeInTheDocument();
    expect(screen.queryByText(es.home.greeting.replace('{{name}}', 'Moises Marin'))).not.toBeInTheDocument();
  });

  it('returns to the login screen after a password change, since it revokes sessions', async () => {
    renderApp({
      '/api/v1/auth/refresh': session({ must_change_password: true }),
      '/api/v1/auth/password': { status: 204 },
    });
    const user = userEvent.setup();

    await user.type(await screen.findByLabelText(es.passwordChange.current), 'initial-password');
    await user.type(screen.getByLabelText(es.passwordChange.new), 'a-brand-new-password');
    await user.click(screen.getByRole('button', { name: es.passwordChange.submit }));

    expect(await screen.findByRole('button', { name: es.login.submit })).toBeInTheDocument();
  });

  it('reports a rejected password change without leaving the screen', async () => {
    renderApp({
      '/api/v1/auth/refresh': session({ must_change_password: true }),
      '/api/v1/auth/password': {
        status: 422,
        body: { code: 'weak_password', message_key: 'errors.auth.weakPassword' },
      },
    });
    const user = userEvent.setup();

    await user.type(await screen.findByLabelText(es.passwordChange.current), 'initial-password');
    await user.type(screen.getByLabelText(es.passwordChange.new), 'short');
    await user.click(screen.getByRole('button', { name: es.passwordChange.submit }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      es.errors.auth.weakPassword,
    );
    expect(screen.getByText(es.passwordChange.title)).toBeInTheDocument();
  });

  it('signs out and calls the server so the family is revoked', async () => {
    const calls = renderApp({
      '/api/v1/auth/refresh': session(),
      '/api/v1/auth/logout': { status: 204 },
    });
    const user = userEvent.setup();

    await user.click(await screen.findByRole('button', { name: es.home.signOut }));

    expect(await screen.findByRole('button', { name: es.login.submit })).toBeInTheDocument();
    expect(calls.mock.calls.some(([path]) => String(path) === '/api/v1/auth/logout')).toBe(true);
  });

  it('signs out locally even if the server call fails', async () => {
    renderApp({
      '/api/v1/auth/refresh': session(),
      '/api/v1/auth/logout': () => {
        throw new Error('connection refused');
      },
    });
    const user = userEvent.setup();

    await user.click(await screen.findByRole('button', { name: es.home.signOut }));

    expect(await screen.findByRole('button', { name: es.login.submit })).toBeInTheDocument();
  });
});
