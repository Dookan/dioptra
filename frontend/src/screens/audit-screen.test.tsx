/** Audit log: one sentence per row, the writers' text as text, the window as a `since`. */
import es from '../locales/es.json';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { App } from '../app';
import { AuthProvider } from '../auth/auth-provider';
import { NO_SESSION, stubFetch, type Routes } from '../test/http';

const HOSTILE = '<script>alert(1)</script>';

const SESSION = {
  status: 200,
  body: {
    access_token: 'an-access-token',
    token_type: 'bearer',
    expires_in: 900,
    user: {
      id: '0f9b2a5e-0000-4000-8000-000000000001',
      username: 'amedina',
      display_name: 'Ana Medina',
      role: 'admin',
      must_change_password: false,
    },
  },
};

const ENTRIES = [
  {
    id: 'e-1',
    occurred_at: '2026-09-22T16:03:00Z',
    actor_username: 'cperez',
    actor_role: 'developer',
    action: 'verification.run',
    target: 'analysis:1:2',
    outcome: 'ok',
    justification: null,
  },
  {
    id: 'e-2',
    occurred_at: '2026-09-22T15:31:00Z',
    actor_username: 'mmarin',
    actor_role: 'analyst',
    action: 'finding.verdict.false_positive',
    target: 'finding:9',
    outcome: 'ok',
    justification: HOSTILE,
  },
  {
    id: 'e-3',
    occurred_at: '2026-09-22T15:00:00Z',
    actor_username: 'cperez',
    actor_role: 'developer',
    action: 'something.new',
    target: null,
    outcome: 'denied',
    justification: null,
  },
];

function renderAudit(entries: unknown[]) {
  globalThis.location.hash = '#/audit';
  const base: Routes = {
    '/api/v1/auth/refresh': NO_SESSION,
    '/api/v1/auth/login': SESSION,
  };
  // `since` is a timestamp computed at render time, so the audit route
  // matches by prefix; a Proxy cannot be spread, hence it wraps the base.
  const routes = new Proxy(base, {
    get: (target, key: string) =>
      key.startsWith('/api/v1/audit') ? { status: 200, body: entries } : target[key],
  });
  const calls = stubFetch(routes);
  render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
  return calls;
}

async function signIn() {
  const user = userEvent.setup();
  await user.type(await screen.findByLabelText(es.login.username), 'amedina');
  await user.type(screen.getByLabelText(es.login.password), 'correct-horse-battery-staple');
  await user.click(screen.getByRole('button', { name: es.login.submit }));
  return user;
}

describe('audit screen', () => {
  it('tells each action as a sentence and renders justifications as text', async () => {
    const calls = renderAudit(ENTRIES);
    await signIn();
    expect(await screen.findByText(es.audit.action['verification.run'])).toBeTruthy();
    expect(screen.getByText(es.audit.action['finding.verdict.false_positive'])).toBeTruthy();
    expect(screen.getByText(new RegExp(`${es.audit.justification}: "<script>`))).toBeTruthy();
    expect(document.querySelector('script')).toBeNull();
    // An action the screen has no sentence for shows its code, never a blank.
    expect(screen.getByText('something.new')).toBeTruthy();
    expect(screen.getByText(es.audit.outcome.denied)).toBeTruthy();
    const first = (calls.mock.calls as unknown as [RequestInfo | URL][]).find(([url]) =>
      String(url).startsWith('/api/v1/audit'),
    );
    expect(String(first?.[0])).toContain('since=');
  });

  it('switches the window and asks the server again', async () => {
    const calls = renderAudit([]);
    const user = await signIn();
    expect(await screen.findByText(es.audit.none)).toBeTruthy();
    await user.click(screen.getByRole('button', { name: es.audit.window.all }));
    await waitFor(() => {
      const urls = (calls.mock.calls as unknown as [RequestInfo | URL][])
        .map(([url]) => String(url))
        .filter((url) => url.startsWith('/api/v1/audit'));
      expect(urls.some((url) => !url.includes('since='))).toBe(true);
    });
  });
});
