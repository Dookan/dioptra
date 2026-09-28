/**
 * Usuarios (phase 6) and the role map: the tabs each role sees, a forbidden
 * hash that never reaches the API, and the admin's screen with its reason
 * floor and its refusals. Authorization itself is proven on the server
 * (backend/tests/test_users_admin.py); this is presentation.
 */
import es from '../locales/es.json';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { Role } from '../api/auth';
import { App } from '../app';
import { AuthProvider } from '../auth/auth-provider';
import { ROUTE_ROLES, mayOpen } from '../navigation/access';
import { NO_SESSION, stubFetch, type Routes } from '../test/http';

const USERNAMES: Record<Role, string> = { admin: 'amedina', analyst: 'mmarin', developer: 'cperez' };

function session(role: Role) {
  return {
    status: 200,
    body: {
      access_token: 'an-access-token',
      token_type: 'bearer',
      expires_in: 900,
      user: {
        id: `id-${role}`,
        username: USERNAMES[role],
        display_name: 'Ana Medina',
        role,
        must_change_password: false,
      },
    },
  };
}

const ACCOUNTS = [
  {
    id: 'id-admin',
    username: 'amedina',
    display_name: 'Ana Medina',
    email: null,
    role: 'admin',
    disabled: false,
    must_change_password: false,
    last_login_at: '2026-09-28T10:00:00Z',
    locked_until: null,
    created_at: '2026-09-01T10:00:00Z',
  },
  {
    id: 'id-cperez',
    username: 'cperez',
    display_name: 'Carla Perez',
    email: null,
    role: 'developer',
    disabled: false,
    must_change_password: true,
    last_login_at: null,
    locked_until: '2999-01-01T00:00:00Z',
    created_at: '2026-09-01T10:00:00Z',
  },
];

function renderAt(hash: string, role: Role, extra: Routes = {}) {
  globalThis.location.hash = hash;
  const calls = stubFetch({
    '/api/v1/auth/refresh': NO_SESSION,
    '/api/v1/auth/login': session(role),
    ...extra,
  });
  render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
  return calls;
}

async function signIn(role: Role) {
  const user = userEvent.setup();
  await user.type(await screen.findByLabelText(es.login.username), USERNAMES[role]);
  await user.type(screen.getByLabelText(es.login.password), 'correct-horse-battery-staple');
  await user.click(screen.getByRole('button', { name: es.login.submit }));
  return user;
}

/** The method and JSON body of the last request to `path` (the stub matches on path only). */
function sent(
  calls: ReturnType<typeof stubFetch>,
  path: string,
): { method: string | undefined; body: unknown } {
  const found = (calls.mock.calls as unknown as [RequestInfo | URL, RequestInit?][])
    .filter(([url]) => String(url) === path)
    .at(-1);
  return { method: found?.[1]?.method, body: JSON.parse(String(found?.[1]?.body)) };
}

function requested(calls: ReturnType<typeof stubFetch>): string[] {
  return (calls.mock.calls as unknown as [RequestInfo | URL, RequestInit?][]).map(([url]) =>
    String(url),
  );
}

describe('role map', () => {
  it('covers every route kind and restricts only the users screen', () => {
    const restricted = Object.entries(ROUTE_ROLES)
      .filter(([, roles]) => roles.length < 3)
      .map(([kind]) => kind);
    expect(restricted).toEqual(['users']);
    expect(mayOpen('users', 'admin')).toBe(true);
    expect(mayOpen('users', 'analyst')).toBe(false);
    expect(mayOpen('users', 'developer')).toBe(false);
  });

  it.each([
    ['admin', ['Inicio', 'Proyectos', 'Inventario', 'Bitácora', 'Usuarios']],
    ['analyst', ['Inicio', 'Proyectos', 'Inventario', 'Bitácora']],
    ['developer', ['Inicio', 'Proyectos', 'Inventario', 'Bitácora']],
  ] as const)('shows the %s exactly the tabs it may open', async (role, tabs) => {
    renderAt('#/', role);
    await signIn(role);
    const nav = await screen.findByRole('navigation', { name: es.nav.label });
    await waitFor(() => {
      expect(within(nav).getAllByRole('link').map((link) => link.textContent)).toEqual(tabs);
    });
  });

  it.each(['analyst', 'developer'] as const)(
    'refuses #/users to the %s in words and never asks the API',
    async (role) => {
      const calls = renderAt('#/users', role);
      await signIn(role);
      expect(await screen.findByText(es.access.refusedTitle)).toBeTruthy();
      expect(requested(calls).some((url) => url.startsWith('/api/v1/users'))).toBe(false);
      await userEvent.setup().click(screen.getByRole('button', { name: es.access.backHome }));
      await waitFor(() => {
        expect(globalThis.location.hash).toBe('#/');
      });
    },
  );
});

describe('users screen', () => {
  it('lists each account in words: role, state, last access and lock', async () => {
    renderAt('#/users', 'admin', { '/api/v1/users': { status: 200, body: ACCOUNTS } });
    await signIn('admin');
    const row = (await screen.findByText('cperez')).closest('li');
    expect(row).not.toBeNull();
    const text = row?.textContent ?? '';
    expect(text).toContain(es.users.state.mustChange);
    expect(text).toContain(es.users.neverLoggedIn);
    expect(text).toContain('bloqueada hasta');
    expect(within(row as HTMLElement).getByText(es.roles.developer, { selector: '.badge' })).toBeTruthy();
  });

  it('offers no action on the admin’s own account', async () => {
    renderAt('#/users', 'admin', { '/api/v1/users': { status: 200, body: ACCOUNTS } });
    const user = await signIn('admin');
    await user.click(await screen.findByRole('button', { name: /amedina/ }));
    expect(screen.getByText(es.users.self)).toBeTruthy();
    expect(screen.queryByRole('button', { name: es.users.actions.disable })).toBeNull();
  });

  it('asks for a ten-character reason and keeps it when the server refuses', async () => {
    renderAt('#/users', 'admin', {
      '/api/v1/users': { status: 200, body: ACCOUNTS },
      '/api/v1/users/id-cperez/status': () => ({
        status: 422,
        body: { code: 'status_unchanged', message_key: 'errors.auth.statusUnchanged' },
      }),
    });
    const user = await signIn('admin');
    await user.click(await screen.findByRole('button', { name: /cperez/ }));
    const disable = screen.getByRole('button', { name: es.users.actions.disable });
    const reason = screen.getByLabelText(es.users.actions.reasonLabel);
    await user.type(reason, 'corto');
    expect((disable as HTMLButtonElement).disabled).toBe(true);
    await user.type(reason, ' pero ahora sí alcanza');
    expect((disable as HTMLButtonElement).disabled).toBe(false);
    await user.click(disable);
    expect(await screen.findByText(es.errors.auth.statusUnchanged)).toBeTruthy();
    expect((reason as HTMLTextAreaElement).value).toBe('corto pero ahora sí alcanza');
  });

  it('creates an account without a reason and selects it', async () => {
    const created = { ...ACCOUNTS[1], id: 'id-jrivas', username: 'jrivas', display_name: 'Juan Rivas' };
    // The same path answers the GET (nothing yet) and then the POST (the account).
    let seen = 0;
    const calls = renderAt('#/users', 'admin', {
      '/api/v1/users': () => (seen++ === 0 ? { status: 200, body: [] } : { status: 201, body: created }),
    });
    const user = await signIn('admin');
    await user.click(await screen.findByRole('button', { name: es.users.create.open }));
    expect(screen.queryByLabelText(es.users.actions.reasonLabel)).toBeNull();
    await user.type(screen.getByLabelText(es.users.create.username), 'jrivas');
    await user.type(screen.getByLabelText(es.users.create.displayName), 'Juan Rivas');
    await user.type(screen.getByLabelText(es.users.create.password), 'una-clave-larga-inicial');
    await user.click(screen.getByRole('button', { name: es.users.create.submit }));
    expect(await screen.findByText(es.users.notice.created)).toBeTruthy();
    const post = (calls.mock.calls as unknown as [RequestInfo | URL, RequestInit?][]).find(
      ([url, init]) => String(url) === '/api/v1/users' && init?.method === 'POST',
    );
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({
      username: 'jrivas',
      display_name: 'Juan Rivas',
      email: null,
      role: 'developer',
      password: 'una-clave-larga-inicial',
    });
  });

  it('counts the reason after trimming, at exactly ten characters', async () => {
    renderAt('#/users', 'admin', { '/api/v1/users': { status: 200, body: ACCOUNTS } });
    const user = await signIn('admin');
    await user.click(await screen.findByRole('button', { name: /cperez/ }));
    const disable = screen.getByRole('button', { name: es.users.actions.disable });
    const reason = screen.getByLabelText(es.users.actions.reasonLabel);
    await user.type(reason, '   123456789   ');
    expect((disable as HTMLButtonElement).disabled).toBe(true);
    await user.clear(reason);
    await user.type(reason, '1234567890');
    expect((disable as HTMLButtonElement).disabled).toBe(false);
  });

  it('changes a role only with a reason and a different role, and shows the result', async () => {
    const calls = renderAt('#/users', 'admin', {
      '/api/v1/users': { status: 200, body: ACCOUNTS },
      '/api/v1/users/id-cperez/role': { status: 200, body: { ...ACCOUNTS[1], role: 'analyst' } },
    });
    const user = await signIn('admin');
    await user.click(await screen.findByRole('button', { name: /cperez/ }));
    const change = screen.getByRole('button', { name: es.users.actions.changeRole });
    const role = screen.getByLabelText(es.users.actions.roleLabel);
    await user.selectOptions(role, 'analyst');
    expect((change as HTMLButtonElement).disabled).toBe(true); // no reason yet
    const reason = screen.getByLabelText(es.users.actions.reasonLabel);
    await user.type(reason, 'Pasa al equipo de análisis');
    await user.selectOptions(role, 'developer');
    expect((change as HTMLButtonElement).disabled).toBe(true); // the same role
    await user.selectOptions(role, 'analyst');
    expect((change as HTMLButtonElement).disabled).toBe(false);
    await user.click(change);
    expect(await screen.findByText(es.users.notice.role)).toBeTruthy();
    expect(sent(calls, '/api/v1/users/id-cperez/role')).toEqual({
      method: 'PATCH',
      body: { role: 'analyst', justification: 'Pasa al equipo de análisis' },
    });
    expect((screen.getByLabelText(es.users.actions.reasonLabel) as HTMLTextAreaElement).value).toBe(
      '',
    );
    const row = screen.getByText('cperez').closest('li') as HTMLElement;
    expect(within(row).getByText(es.roles.analyst, { selector: '.badge' })).toBeTruthy();
  });

  it('resets a password only with both fields, and sends each where it belongs', async () => {
    const calls = renderAt('#/users', 'admin', {
      '/api/v1/users': { status: 200, body: ACCOUNTS },
      '/api/v1/users/id-cperez/password-reset': { status: 200, body: ACCOUNTS[1] },
    });
    const user = await signIn('admin');
    await user.click(await screen.findByRole('button', { name: /cperez/ }));
    const reset = screen.getByRole('button', { name: es.users.actions.resetPassword });
    const password = screen.getByLabelText(es.users.actions.passwordLabel);
    await user.type(password, 'otra-clave-bastante-larga');
    expect((reset as HTMLButtonElement).disabled).toBe(true); // no reason
    await user.type(screen.getByLabelText(es.users.actions.reasonLabel), 'Olvidó su contraseña hoy');
    expect((reset as HTMLButtonElement).disabled).toBe(false);
    await user.clear(password);
    expect((reset as HTMLButtonElement).disabled).toBe(true); // no password
    await user.type(password, 'otra-clave-bastante-larga');
    await user.click(reset);
    expect(await screen.findByText(es.users.notice.reset)).toBeTruthy();
    expect(sent(calls, '/api/v1/users/id-cperez/password-reset')).toEqual({
      method: 'POST',
      body: { password: 'otra-clave-bastante-larga', justification: 'Olvidó su contraseña hoy' },
    });
  });

  it('shows a disabled account as such and enables it again', async () => {
    const off = {
      ...ACCOUNTS[1],
      id: 'id-lrivas',
      username: 'lrivas',
      disabled: true,
      must_change_password: false,
      locked_until: '2000-01-01T00:00:00Z',
    };
    const calls = renderAt('#/users', 'admin', {
      '/api/v1/users': { status: 200, body: [...ACCOUNTS, off] },
      '/api/v1/users/id-lrivas/status': { status: 200, body: { ...off, disabled: false } },
    });
    const user = await signIn('admin');
    const row = (await screen.findByText('lrivas')).closest('li') as HTMLElement;
    expect(row.textContent).toContain(es.users.state.disabled);
    expect(row.textContent).not.toContain(es.users.state.active);
    expect(row.textContent).not.toContain('bloqueada hasta'); // a lock in the past is no lock
    await user.click(within(row).getByRole('button', { name: /lrivas/ }));
    await user.type(screen.getByLabelText(es.users.actions.reasonLabel), 'Renovó el contrato hoy');
    await user.click(screen.getByRole('button', { name: es.users.actions.enable }));
    expect(await screen.findByText(es.users.notice.enabled)).toBeTruthy();
    expect(sent(calls, '/api/v1/users/id-lrivas/status')).toEqual({
      method: 'PATCH',
      body: { disabled: false, justification: 'Renovó el contrato hoy' },
    });
  });
});
