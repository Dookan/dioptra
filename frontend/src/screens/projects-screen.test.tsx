/** Projects list and the E1 registration form. */
import es from '../locales/es.json';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { App } from '../app';
import { AuthProvider } from '../auth/auth-provider';
import { NO_SESSION, stubFetch, type Routes } from '../test/http';

function session(role: 'analyst' | 'developer', username = 'mmarin') {
  return {
    status: 200,
    body: {
      access_token: 'an-access-token',
      token_type: 'bearer',
      expires_in: 900,
      user: {
        id: '0f9b2a5e-0000-4000-8000-000000000001',
        username,
        display_name: 'Moises Marin',
        role,
        must_change_password: false,
      },
    },
  };
}

const PROJECT = {
  id: '11111111-1111-4111-8111-111111111111',
  name: 'formulario_mincyt_apirest-desarrollo',
  description: null,
  created_at: '2026-09-21T12:00:00Z',
  system: {
    name: 'formulario_mincyt_apirest-desarrollo',
    framework: 'Express',
    database: null,
    developer: null,
    installed_at: null,
  },
};

type FetchCall = [RequestInfo | URL, RequestInit | undefined];

function calledWithMethod(calls: { mock: { calls: unknown[] } }, path: string, method: string) {
  return (calls.mock.calls as FetchCall[]).find(
    ([url, init]) => String(url) === path && init?.method === method,
  );
}

function renderAt(hash: string, routes: Routes) {
  globalThis.location.hash = hash;
  const calls = stubFetch({ '/api/v1/auth/refresh': NO_SESSION, ...routes });
  render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
  return calls;
}

async function signIn() {
  const user = userEvent.setup();
  await user.type(await screen.findByLabelText(es.login.username), 'mmarin');
  await user.type(screen.getByLabelText(es.login.password), 'correct-horse-battery-staple');
  await user.click(screen.getByRole('button', { name: es.login.submit }));
  return user;
}

describe('projects screen', () => {
  it('lists the projects with their latest analysis status', async () => {
    renderAt('#/projects', {
      '/api/v1/auth/login': session('analyst'),
      '/api/v1/projects': { status: 200, body: [PROJECT] },
      [`/api/v1/projects/${PROJECT.id}/analyses`]: {
        status: 200,
        body: [{ id: 'a1', status: 'done', finding_counts: {}, tool_runs: [], languages: {}, frameworks: [], lockfiles: [] }],
      },
    });
    await signIn();

    expect(await screen.findByRole('link', { name: PROJECT.name })).toBeInTheDocument();
    expect(await screen.findByText(es.analysis.status.done)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: es.projects.register })).toBeInTheDocument();
  });

  it('hides the register button from a developer', async () => {
    renderAt('#/projects', {
      '/api/v1/auth/login': session('developer', 'cperez'),
      '/api/v1/projects': { status: 200, body: [] },
    });
    await signIn();

    expect(await screen.findByText(es.projects.empty)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.projects.register })).not.toBeInTheDocument();
    expect(screen.getByText(es.projects.nextStepBodyDeveloper)).toBeInTheDocument();
  });

  it('posts the E1 form and navigates to the new project', async () => {
    const calls = renderAt('#/projects', {
      '/api/v1/auth/login': session('analyst'),
      '/api/v1/projects': () =>
        calledWithMethod(calls, '/api/v1/projects', 'POST') === undefined
          ? { status: 200, body: [] }
          : { status: 201, body: PROJECT },
      [`/api/v1/projects/${PROJECT.id}`]: { status: 200, body: PROJECT },
      [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [] },
    });
    const user = await signIn();

    await user.click(await screen.findByRole('button', { name: es.projects.register }));
    await user.type(screen.getByLabelText(es.projects.form.name), PROJECT.name);
    await user.type(screen.getByLabelText(es.projects.form.systemName), PROJECT.system.name);
    await user.type(screen.getByLabelText(es.projects.form.framework), 'Express');
    await user.click(screen.getByRole('button', { name: es.projects.form.submit }));

    await waitFor(() => {
      const post = calledWithMethod(calls, '/api/v1/projects', 'POST');
      if (post?.[1] === undefined) throw new Error('no POST /api/v1/projects');
      const body = JSON.parse(String(post[1].body));
      expect(body).toEqual({
        name: PROJECT.name,
        system: { name: PROJECT.system.name, framework: 'Express' },
      });
    });
    expect(await screen.findByText(es.project.nextStep.codeTitle)).toBeInTheDocument();
    expect(globalThis.location.hash).toBe(`#/projects/${PROJECT.id}`);
  });
});
