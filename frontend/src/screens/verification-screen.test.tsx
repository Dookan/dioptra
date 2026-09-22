/**
 * Stage E7: a rejection has to be legible. The surviving mutant, the uncovered
 * brief items and the cases that assert nothing are each shown by name, as
 * text; the analyst sees the result without the buttons.
 */
import es from '../locales/es.json';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { App } from '../app';
import { AuthProvider } from '../auth/auth-provider';
import { NO_SESSION, stubFetch, type Routes } from '../test/http';

const PROJECT_ID = '22222222-2222-4222-8222-222222222222';
const ANALYSIS_ID = 'a-1';
const HOSTILE = '<img src=x onerror=alert(1)>';

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
  system: { name: 'Sistema Demo', framework: null, database: null, developer: null, installed_at: null },
};

const ANALYSIS = {
  id: ANALYSIS_ID,
  project_id: PROJECT_ID,
  source_kind: 'zip',
  source_ref: 'src.zip',
  status: 'done',
  failure_code: null,
  stage: 'verification',
  languages: {},
  frameworks: [],
  lockfiles: [],
  created_at: '2026-09-21T12:00:00Z',
  started_at: null,
  finished_at: null,
  finding_counts: {},
  report_counts: {},
  triage: { total: 0, confirmed: 0, false_positive: 0, pending: 0, complete: true },
  tool_runs: [],
};

const PLAN = {
  analysis_id: ANALYSIS_ID,
  criterion: 'decisions',
  rationale: 'Plan de prueba.',
  functions: [{ path: 'src/validators.js', function: 'validateForm', line: 10, ccn: 3 }],
  created_by_username: 'cperez',
  created_at: '2026-09-22T10:00:00Z',
  updated_at: '2026-09-22T10:00:00Z',
};

const FAILED_RUN = {
  path: 'src/validators.js',
  function: 'validateForm',
  line: 10,
  status: 'failed',
  reasons: ['mutant_survived', 'brief_uncovered', 'assertion_free'],
  coverage: { statement_percent: 80, branch_percent: 50 },
  uncovered_items: ['R2', 'F1'],
  surviving_mutants: [{ id: '3', line: '11', mutant: `ConditionalExpression: ${HOSTILE}` }],
  assertion_free_cases: ['C3'],
  failed_cases: [],
  detail: null,
  duration_ms: 4200,
  created_by_username: 'cperez',
  created_at: '2026-09-22T14:00:00Z',
};

const VERIFICATION_URL = `/api/v1/analyses/${ANALYSIS_ID}/verification`;
const REOPEN_URL = `/api/v1/analyses/${ANALYSIS_ID}/reopen-design`;

function fill(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_match, name: string) => String(values[name] ?? ''));
}

function renderVerify(role: 'analyst' | 'developer', routes: Routes = {}) {
  globalThis.location.hash = `#/projects/${PROJECT_ID}/analyses/${ANALYSIS_ID}/verify`;
  const calls = stubFetch({
    '/api/v1/auth/refresh': NO_SESSION,
    '/api/v1/auth/login': session(role),
    [`/api/v1/projects/${PROJECT_ID}`]: { status: 200, body: PROJECT },
    [`/api/v1/analyses/${ANALYSIS_ID}`]: { status: 200, body: ANALYSIS },
    [`/api/v1/analyses/${ANALYSIS_ID}/test-plan`]: { status: 200, body: PLAN },
    [VERIFICATION_URL]: { status: 200, body: [FAILED_RUN] },
    ...routes,
  });
  render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
  return calls;
}

async function signIn(username: string) {
  const user = userEvent.setup();
  await user.type(await screen.findByLabelText(es.login.username), username);
  await user.type(screen.getByLabelText(es.login.password), 'correct-horse-battery-staple');
  await user.click(screen.getByRole('button', { name: es.login.submit }));
  return user;
}

describe('verification screen', () => {
  it('names the surviving mutant, the uncovered items and the toothless cases', async () => {
    renderVerify('developer');
    await signIn('cperez');
    expect(await screen.findByText(es.verify.reason.mutant_survived)).toBeTruthy();
    expect(screen.getByText(es.verify.reason.brief_uncovered)).toBeTruthy();
    expect(screen.getByText(es.verify.reason.assertion_free)).toBeTruthy();
    // The mutant text comes from the audited code's own tooling: rendered as text.
    expect(screen.getByText(`línea 11 · ConditionalExpression: ${HOSTILE}`)).toBeTruthy();
    expect(document.querySelector('img')).toBeNull();
    expect(screen.getByText('R2')).toBeTruthy();
    expect(screen.getByText('F1')).toBeTruthy();
    expect(
      screen.getByText(fill(es.verify.coverage, { statements: 80, branches: 50 })),
    ).toBeTruthy();
    expect(
      screen.getByText(fill(es.verify.nextStep.resultTitle_one, { passed: 0, count: 1 })),
    ).toBeTruthy();
  });

  it('asks for a written reason before reopening the design', async () => {
    const calls = renderVerify('developer', {
      [REOPEN_URL]: { status: 200, body: [FAILED_RUN] },
    });
    const user = await signIn('cperez');
    const button = await screen.findByRole('button', { name: es.verify.reopen });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    await user.type(screen.getByLabelText(es.verify.reasonLabel), 'El mutante sobrevivió.');
    expect((button as HTMLButtonElement).disabled).toBe(false);
    await user.click(button);
    await waitFor(() => {
      expect(screen.getByText(es.verify.reopened)).toBeTruthy();
    });
    const posted = (calls.mock.calls as unknown as [RequestInfo | URL, RequestInit | undefined][]).find(
      ([url, init]) => String(url) === REOPEN_URL && init?.method === 'POST',
    );
    expect(JSON.parse(String(posted?.[1]?.body)).justification).toContain('mutante');
  });

  it('gives the analyst the result without the buttons', async () => {
    renderVerify('analyst');
    await signIn('mmarin');
    expect(await screen.findByText(es.verify.readOnly)).toBeTruthy();
    expect(screen.queryByRole('button', { name: es.verify.run })).toBeNull();
    expect(screen.queryByRole('button', { name: es.verify.reopen })).toBeNull();
  });
});
