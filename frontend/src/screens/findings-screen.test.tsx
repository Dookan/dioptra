/** Stage E3 screen: plain-language triage, mandatory reason, hostile text as text. */
import es from '../locales/es.json';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { App } from '../app';
import { AuthProvider } from '../auth/auth-provider';
import { NO_SESSION, stubFetch, type Routes } from '../test/http';

const PROJECT_ID = '22222222-2222-4222-8222-222222222222';
const ANALYSIS_ID = 'a-1';
const HOSTILE_TITLE = '<img src=x onerror=alert(1)>';

function session(role: 'analyst' | 'developer') {
  return {
    status: 200,
    body: {
      access_token: 'an-access-token',
      token_type: 'bearer',
      expires_in: 900,
      user: {
        id: '0f9b2a5e-0000-4000-8000-000000000001',
        username: role === 'analyst' ? 'mmarin' : 'cperez',
        display_name: role === 'analyst' ? 'Moises Marin' : 'Carla Perez',
        role,
        must_change_password: false,
      },
    },
  };
}

const PROJECT = {
  id: PROJECT_ID,
  name: 'sistema-demo',
  description: null,
  created_at: '2026-09-21T12:00:00Z',
  system: { name: 'sistema-demo', framework: null, database: null, developer: null, installed_at: null },
};

const ANALYSIS = {
  id: ANALYSIS_ID,
  project_id: PROJECT_ID,
  source_kind: 'zip',
  source_ref: 'src.zip',
  status: 'done',
  failure_code: null,
  languages: { JavaScript: 3 },
  frameworks: [],
  lockfiles: [],
  created_at: '2026-09-21T12:00:00Z',
  started_at: null,
  finished_at: null,
  finding_counts: { high: 1, medium: 1 },
  report_counts: { high: 1, medium: 1 },
  triage: { total: 2, confirmed: 0, false_positive: 0, pending: 2, complete: false },
  tool_runs: [],
};

function finding(id: string, overrides: Record<string, unknown> = {}) {
  return {
    id,
    ordinal: 0,
    category: 'sast',
    tools: ['semgrep'],
    rule_id: 'dioptra.xss',
    cwe: 79,
    owasp: 'A03:2021',
    title: `Hallazgo ${id}`,
    severity: 'high',
    cvss_score: null,
    path: 'src/index.js',
    line: 36,
    snippet: null,
    message: null,
    references: [],
    description: 'Descripción del catálogo.',
    impact: 'Impacto del catálogo.',
    mitigation: ['Escapar la salida.'],
    verdict: null,
    verdict_justification: null,
    verdict_by_username: null,
    verdict_at: null,
    ...overrides,
  };
}

/** Interpolate `{{name}}` slots of a locale string, so tests never restate the copy. */
function fill(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_match, name: string) => String(values[name] ?? ''));
}

type FetchCall = [RequestInfo | URL, RequestInit | undefined];

function bodyOf(calls: { mock: { calls: unknown[] } }, path: string, method: string): unknown {
  const call = (calls.mock.calls as FetchCall[]).find(
    ([url, init]) => String(url) === path && init?.method === method,
  );
  return call?.[1]?.body === undefined ? undefined : JSON.parse(String(call[1].body));
}

function renderFindings(role: 'analyst' | 'developer', findings: unknown[], routes: Routes = {}) {
  globalThis.location.hash = `#/projects/${PROJECT_ID}/analyses/${ANALYSIS_ID}/findings`;
  const calls = stubFetch({
    '/api/v1/auth/refresh': NO_SESSION,
    '/api/v1/auth/login': session(role),
    [`/api/v1/projects/${PROJECT_ID}`]: { status: 200, body: PROJECT },
    [`/api/v1/analyses/${ANALYSIS_ID}`]: { status: 200, body: ANALYSIS },
    [`/api/v1/analyses/${ANALYSIS_ID}/findings`]: { status: 200, body: findings },
    ...routes,
  });
  render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
  return calls;
}

async function signIn(username = 'mmarin') {
  const user = userEvent.setup();
  await user.type(await screen.findByLabelText(es.login.username), username);
  await user.type(screen.getByLabelText(es.login.password), 'correct-horse-battery-staple');
  await user.click(screen.getByRole('button', { name: es.login.submit }));
  return user;
}

describe('findings screen', () => {
  it('lists the findings, counts what is left and explains the selected one in plain words', async () => {
    renderFindings('analyst', [
      finding('f-1', { title: HOSTILE_TITLE, snippet: '<script>alert(1)</script>' }),
      finding('f-2', { severity: 'medium', owasp: 'A01:2021', path: 'src/auth.js' }),
    ]);
    await signIn();

    expect(
      await screen.findByText(fill(es.findings.nextStep.pendingTitle, { count: 2 })),
    ).toBeInTheDocument();
    expect(screen.getByText(fill(es.findings.progress, { reviewed: 0, total: 2 }))).toBeInTheDocument();
    expect(screen.getByText(es.findings.what)).toBeInTheDocument();
    expect(screen.getByText(es.findings.how)).toBeInTheDocument();
    expect(screen.getByText('Descripción del catálogo.')).toBeInTheDocument();
    // Hostile values are text nodes: the markup shows up literally, never as elements.
    expect(screen.getAllByText(HOSTILE_TITLE).length).toBeGreaterThan(0);
    expect(document.querySelector('img')).toBeNull();
    expect(document.querySelector('script')).toBeNull();
    expect(screen.getByText('<script>alert(1)</script>')).toBeInTheDocument();
    expect(screen.getByText(es.stepper.analysis)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: es.nav.findings })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: es.nav.report })).toBeInTheDocument();
  });

  it('filters by severity', async () => {
    renderFindings('analyst', [
      finding('f-1'),
      finding('f-2', { severity: 'medium', path: 'src/auth.js' }),
    ]);
    const user = await signIn();
    const list = await screen.findByRole('list', { name: es.findings.listLabel });
    expect(within(list).getAllByRole('button')).toHaveLength(2);

    await user.selectOptions(screen.getByLabelText(es.findings.filters.severity), 'medium');
    expect(within(list).getAllByRole('button')).toHaveLength(1);
    expect(within(list).getByText('Hallazgo f-2')).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText(es.findings.filters.file), 'src/index.js');
    expect(screen.getByText(es.findings.filters.none)).toBeInTheDocument();
  });

  it('sends the verdict with its reason and updates the count', async () => {
    const reviewed = finding('f-1', {
      verdict: 'false_positive',
      verdict_justification: 'Es un archivo de ejemplo que no se despliega.',
      verdict_by_username: 'mmarin',
      verdict_at: '2026-09-22T10:00:00Z',
    });
    const calls = renderFindings('analyst', [finding('f-1'), finding('f-2')], {
      '/api/v1/findings/f-1/verdict': { status: 200, body: reviewed },
    });
    const user = await signIn();

    const discard = await screen.findByRole('button', { name: es.findings.discard });
    const confirm = screen.getByRole('button', { name: es.findings.confirm });
    expect(discard).toBeDisabled();
    expect(confirm).toBeDisabled();

    const field = screen.getByLabelText(es.findings.justificationLabel);
    await user.type(field, 'corto');
    expect(discard).toBeDisabled();
    // The floor counts collapsed characters: nine + padding stays short, ten enables.
    await user.clear(field);
    await user.type(field, '  a   b c  ');
    expect(discard).toBeDisabled();
    await user.clear(field);
    await user.type(field, '123456789');
    expect(discard).toBeDisabled();
    await user.type(field, '0');
    expect(discard).toBeEnabled();
    await user.clear(field);
    await user.type(field, '  Es un   archivo de ejemplo\nque no se despliega.  ');
    expect(discard).toBeEnabled();
    await user.click(discard);

    await waitFor(() => {
      expect(bodyOf(calls, '/api/v1/findings/f-1/verdict', 'POST')).toEqual({
        verdict: 'false_positive',
        justification: 'Es un archivo de ejemplo que no se despliega.',
      });
    });
    expect(
      await screen.findByText(fill(es.findings.nextStep.pendingTitle, { count: 1 })),
    ).toBeInTheDocument();
    expect(screen.getByText(fill(es.findings.progress, { reviewed: 1, total: 2 }))).toBeInTheDocument();
    expect(screen.getAllByText(es.findings.verdict.false_positive).length).toBeGreaterThan(0);
  });

  it('shows the rejection reason when the server refuses the verdict', async () => {
    renderFindings('analyst', [finding('f-1')], {
      '/api/v1/findings/f-1/verdict': {
        status: 422,
        body: { code: 'justification_required', message_key: 'errors.workflow.justificationRequired' },
      },
    });
    const user = await signIn();
    await user.type(
      await screen.findByLabelText(es.findings.justificationLabel),
      'una razón cualquiera',
    );
    await user.click(screen.getByRole('button', { name: es.findings.confirm }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      es.errors.workflow.justificationRequired,
    );
  });

  it('hides the verdict form from a developer', async () => {
    renderFindings('developer', [finding('f-1')]);
    await signIn('cperez');
    expect(await screen.findByText(es.findings.what)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.findings.confirm })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(es.findings.justificationLabel)).not.toBeInTheDocument();
  });
});
