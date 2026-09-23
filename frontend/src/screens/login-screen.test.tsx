/** Login screen behaviour, in both languages and both themes. */
import es from '../locales/es.json';
import en from '../locales/en.json';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { App } from '../app';
import { AuthProvider } from '../auth/auth-provider';
import { NO_SESSION, stubFetch, type Routes } from '../test/http';

const SESSION = {
  status: 200,
  body: {
    access_token: 'an-access-token',
    token_type: 'bearer',
    expires_in: 900,
    user: {
      id: '0f9b2a5e-0000-4000-8000-000000000001',
      username: 'mmarin',
      display_name: 'Moises Marin',
      role: 'analyst',
      must_change_password: false,
    },
  },
};

function renderApp(routes: Routes) {
  const calls = stubFetch({ '/api/v1/auth/refresh': NO_SESSION, ...routes });
  render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
  return calls;
}

async function signIn(username = 'mmarin', password = 'correct-horse-battery-staple') {
  const user = userEvent.setup();
  await user.type(await screen.findByLabelText(es.login.username), username);
  await user.type(screen.getByLabelText(es.login.password), password);
  await user.click(screen.getByRole('button', { name: es.login.submit }));
  return user;
}

describe('login screen', () => {
  it('opens in Spanish with the mockup copy', async () => {
    renderApp({});

    expect(
      await screen.findByText(es.login.greeting),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: es.login.submit })).toBeInTheDocument();
    expect(screen.getByText(es.login.noAccount)).toBeVisible();
  });

  it('signs in and lands on the home screen', async () => {
    renderApp({ '/api/v1/auth/login': SESSION });

    await signIn();

    expect(await screen.findByText(es.home.greeting.replace('{{name}}', 'Moises Marin'))).toBeInTheDocument();
    expect(screen.getByText('mmarin')).toBeInTheDocument();
    // The role shows in the appbar and in the tabs bar context.
    expect(screen.getAllByText(es.roles.analyst).length).toBeGreaterThan(0);
  });

  it('sends the credentials to the API exactly once', async () => {
    const calls = renderApp({ '/api/v1/auth/login': SESSION });

    await signIn();

    await waitFor(() => {
      const loginCalls = calls.mock.calls.filter(
        ([path]) => String(path) === '/api/v1/auth/login',
      );
      expect(loginCalls).toHaveLength(1);
    });
  });

  it('shows the translated message for wrong credentials and clears the password', async () => {
    renderApp({
      '/api/v1/auth/login': {
        status: 401,
        body: { code: 'invalid_credentials', message_key: 'errors.auth.invalidCredentials' },
      },
    });

    await signIn('mmarin', 'wrong-password');

    expect(await screen.findByRole('alert')).toHaveTextContent(
      es.errors.auth.invalidCredentials,
    );
    expect(screen.getByLabelText(es.login.password)).toHaveValue('');
  });

  it('explains a locked account instead of showing a status code', async () => {
    renderApp({
      '/api/v1/auth/login': {
        status: 423,
        body: { code: 'account_locked', message_key: 'errors.auth.accountLocked' },
      },
    });

    await signIn();

    expect(await screen.findByRole('alert')).toHaveTextContent(
      es.errors.auth.accountLocked,
    );
  });

  it('falls back to a generic message when the server is unreachable', async () => {
    renderApp({
      '/api/v1/auth/login': () => {
        throw new Error('connection refused');
      },
    });

    await signIn();

    expect(await screen.findByRole('alert')).toHaveTextContent(
      es.errors.network,
    );
  });

  it('switches the whole screen to English', async () => {
    renderApp({});
    const user = userEvent.setup();

    await user.click(await screen.findByRole('button', { name: es.language.en }));

    expect(screen.getByRole('button', { name: en.login.submit })).toBeInTheDocument();
    expect(
      screen.getByText(en.login.greeting),
    ).toBeInTheDocument();
  });

  it('toggles the theme on the document root', async () => {
    renderApp({});
    const user = userEvent.setup();

    // The accessible name must stay the label the user can SEE, so voice control
    // can activate it by those words (WCAG 2.5.3). The state the click leads to
    // rides on `title`, which is a description and does not replace the name.
    const toggle = await screen.findByRole('button', { name: new RegExp(es.theme.toggle) });
    expect(toggle).toHaveAttribute('title', es.theme.dark);

    await user.click(toggle);

    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(toggle).toHaveAttribute('title', es.theme.light);

    await user.click(toggle);

    expect(document.documentElement.dataset.theme).toBe('light');
  });

  it('keeps the password field masked', async () => {
    renderApp({});

    expect(await screen.findByLabelText(es.login.password)).toHaveAttribute('type', 'password');
  });

  it('reveals and hides the typed password on screen only', async () => {
    const calls = renderApp({ '/api/v1/auth/login': SESSION });
    const user = userEvent.setup();
    const field = await screen.findByLabelText(es.login.password);
    await user.type(field, 'correct-horse-battery-staple');

    const toggle = screen.getByRole('button', { name: es.password.show });
    await user.click(toggle);

    // Revealing changes how the browser paints the field, nothing else.
    expect(field).toHaveAttribute('type', 'text');
    expect(field).toHaveValue('correct-horse-battery-staple');
    // The accessible name IS the state cue: it now offers to hide.
    expect(screen.getByRole('button', { name: es.password.hide })).toBeInTheDocument();
    expect(calls.mock.calls.filter(([path]) => String(path) === '/api/v1/auth/login')).toHaveLength(0);

    await user.click(screen.getByRole('button', { name: es.password.hide }));
    expect(field).toHaveAttribute('type', 'password');
  });

  it('sends what was typed WHILE revealed, unchanged', async () => {
    // Every other reveal test types masked and then reveals. This is the other
    // ordering: a mutant that mangles input typed while revealed survives them.
    const calls = renderApp({ '/api/v1/auth/login': SESSION });
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(es.login.username), 'mmarin');
    await user.click(screen.getByRole('button', { name: es.password.show }));
    const secret = '  Mixed CASE p@ss  ';
    await user.type(screen.getByLabelText(es.login.password), secret);
    await user.click(screen.getByRole('button', { name: es.login.submit }));

    await waitFor(() => {
      const loginCalls = calls.mock.calls.filter(([path]) => String(path) === '/api/v1/auth/login');
      expect(loginCalls).toHaveLength(1);
      const init = (loginCalls[0] as unknown as [string, RequestInit])[1];
      expect(JSON.parse(String(init.body))).toEqual({ username: 'mmarin', password: secret });
    });
  });

  it('sends the same request whether the password is shown or hidden, and re-masks on submit', async () => {
    const calls = renderApp({ '/api/v1/auth/login': SESSION });
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(es.login.username), 'mmarin');
    const field = screen.getByLabelText(es.login.password);
    await user.type(field, 'correct-horse-battery-staple');
    await user.click(screen.getByRole('button', { name: es.password.show }));
    expect(field).toHaveAttribute('type', 'text');

    await user.click(screen.getByRole('button', { name: es.login.submit }));

    await waitFor(() => {
      const loginCalls = calls.mock.calls.filter(([path]) => String(path) === '/api/v1/auth/login');
      expect(loginCalls).toHaveLength(1);
      const init = (loginCalls[0] as unknown as [string, RequestInit])[1];
      // The body is the JSON the masked form has always sent: a POST, the
      // credentials as fields, nothing in the URL or the headers.
      expect(init.method).toBe('POST');
      expect(JSON.parse(String(init.body))).toEqual({
        username: 'mmarin',
        password: 'correct-horse-battery-staple',
      });
    });
    expect(await screen.findByText(es.home.greeting.replace('{{name}}', 'Moises Marin'))).toBeInTheDocument();
  });

  it('masks the field again when a wrong password is submitted while revealed', async () => {
    renderApp({
      '/api/v1/auth/login': {
        status: 401,
        body: { code: 'invalid_credentials', message_key: 'errors.auth.invalidCredentials' },
      },
    });
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(es.login.username), 'mmarin');
    const field = screen.getByLabelText(es.login.password);
    await user.type(field, 'wrong-password');
    await user.click(screen.getByRole('button', { name: es.password.show }));

    await user.click(screen.getByRole('button', { name: es.login.submit }));

    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(field).toHaveAttribute('type', 'password');
    expect(field).toHaveValue('');
    expect(screen.getByRole('button', { name: es.password.show })).toBeInTheDocument();
  });
});
