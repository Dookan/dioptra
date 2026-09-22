/** Stage E4 screen: the server's ranking, include/exclude, the plan PUT, save-and-advance. */
import es from '../locales/es.json';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { App } from '../app';
import { AuthProvider } from '../auth/auth-provider';
import { NO_SESSION, stubFetch, type Routes } from '../test/http';

const PROJECT_ID = '22222222-2222-4222-8222-222222222222';
const ANALYSIS_ID = 'a-1';

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

function analysis(stage: string) {
  return {
    id: ANALYSIS_ID,
    project_id: PROJECT_ID,
    source_kind: 'zip',
    source_ref: 'src.zip',
    status: 'done',
    failure_code: null,
    stage,
    languages: {},
    frameworks: [],
    lockfiles: [],
    created_at: '2026-09-21T12:00:00Z',
    started_at: null,
    finished_at: null,
    finding_counts: { high: 1 },
    report_counts: { high: 1 },
    triage: { total: 1, confirmed: 1, false_positive: 0, pending: 0, complete: true },
    tool_runs: [],
  };
}

const MATRIX = [
  { path: 'src/validators.js', function: 'validateForm', line: 10, ccn: 12, nloc: 40, findings: 1, max_severity: 'high', score: 72, level: 'high' },
  { path: 'src/billing/discount.js', function: 'calculateDiscount', line: 20, ccn: 5, nloc: 18, findings: 1, max_severity: 'medium', score: 20, level: 'high' },
  { path: 'src/utils.js', function: 'formatDate', line: 3, ccn: 2, nloc: 6, findings: 0, max_severity: null, score: 2, level: 'low' },
];

const NO_PLAN = { status: 404, body: { code: 'test_plan_not_found', message_key: 'errors.workflow.testPlanNotFound' } };

type FetchCall = [RequestInfo | URL, RequestInit | undefined];

function bodyOf(calls: { mock: { calls: unknown[] } }, path: string, method: string): unknown {
  const call = (calls.mock.calls as FetchCall[]).find(
    ([url, init]) => String(url) === path && init?.method === method,
  );
  return call?.[1]?.body === undefined ? undefined : JSON.parse(String(call[1].body));
}

function fill(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_match, name: string) => String(values[name] ?? ''));
}

function renderPlan(role: 'analyst' | 'developer', stage: string, routes: Routes = {}) {
  globalThis.location.hash = `#/projects/${PROJECT_ID}/analyses/${ANALYSIS_ID}/plan`;
  const calls = stubFetch({
    '/api/v1/auth/refresh': NO_SESSION,
    '/api/v1/auth/login': session(role),
    [`/api/v1/projects/${PROJECT_ID}`]: { status: 200, body: PROJECT },
    [`/api/v1/analyses/${ANALYSIS_ID}`]: { status: 200, body: analysis(stage) },
    [`/api/v1/analyses/${ANALYSIS_ID}/risk-matrix`]: { status: 200, body: MATRIX },
    [`/api/v1/analyses/${ANALYSIS_ID}/test-plan`]: NO_PLAN,
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

describe('test plan screen', () => {
  it('shows the ranking from the server in plain words with the stepper at Plan', async () => {
    renderPlan('developer', 'plan');
    await signIn('cperez');

    expect(await screen.findByText(es.plan.title)).toBeInTheDocument();
    const ranking = screen.getByRole('list', { name: es.plan.rankingLabel });
    const rows = within(ranking).getAllByRole('listitem');
    expect(rows).toHaveLength(3);
    expect(rows[0]).toHaveTextContent('validateForm()');
    expect(rows[0]).toHaveTextContent(fill(es.plan.reason.complexWithFindings, { ccn: 12, count: 1 }));
    expect(rows[0]).toHaveTextContent(es.plan.level.high);
    expect(rows[2]).toHaveTextContent(fill(es.plan.reason.simple, { ccn: 2 }));
    expect(rows[2]).toHaveTextContent(es.plan.level.low);
    expect(screen.getByRole('listitem', { current: 'step' })).toHaveTextContent(es.stepper.plan);
    expect(screen.getByRole('radio', { name: es.plan.criterion.decisions })).toBeChecked();
    expect(screen.getByRole('link', { name: es.nav.workflow })).toHaveAttribute('aria-current', 'page');
    // At the plan stage itself: neither "not yet" nor "locked".
    expect(screen.getByText(es.plan.nextStep.emptyTitle)).toBeInTheDocument();
    expect(screen.queryByText(es.plan.nextStep.notYetTitle)).not.toBeInTheDocument();
    expect(screen.queryByText(es.plan.nextStep.lockedTitle)).not.toBeInTheDocument();
  });

  it('saves the plan with the included functions, then advances with a reason', async () => {
    const plan = {
      analysis_id: ANALYSIS_ID,
      criterion: 'paths',
      rationale: 'Empezamos por la validación porque concentra los hallazgos.',
      functions: [{ path: 'src/validators.js', function: 'validateForm', line: 10, ccn: 12 }],
      created_by_username: 'cperez',
      created_at: '2026-09-22T10:00:00Z',
      updated_at: '2026-09-22T10:00:00Z',
    };
    const calls = renderPlan('developer', 'plan', {
      [`/api/v1/analyses/${ANALYSIS_ID}/test-plan`]: () =>
        calls.mock.calls.some(
          ([url, init]: unknown[]) =>
            String(url).endsWith('/test-plan') && (init as RequestInit | undefined)?.method === 'PUT',
        )
          ? { status: 200, body: plan }
          : NO_PLAN,
      [`/api/v1/analyses/${ANALYSIS_ID}/stage/advance`]: { status: 200, body: analysis('design') },
    });
    const user = await signIn('cperez');

    const advance = await screen.findByRole('button', { name: es.plan.saveAndDesign });
    expect(advance).toBeDisabled();
    expect(screen.getByText(fill(es.plan.incomplete, { min: 10 }))).toBeInTheDocument();
    const ranking = screen.getByRole('list', { name: es.plan.rankingLabel });
    const [first] = within(ranking).getAllByRole('listitem');
    await user.click(within(first!).getByRole('button', { name: es.plan.include }));
    // Dejar fuera really excludes; then include again.
    await user.click(within(first!).getByRole('button', { name: es.plan.exclude }));
    expect(within(first!).getByRole('button', { name: es.plan.include })).toBeInTheDocument();
    expect(advance).toBeDisabled();
    await user.click(within(first!).getByRole('button', { name: es.plan.include }));
    expect(within(first!).getByRole('button', { name: es.plan.exclude })).toBeInTheDocument();
    await user.click(screen.getByRole('radio', { name: es.plan.criterion.paths }));
    // Doubled whitespace on purpose: the request must carry the collapsed text.
    await user.type(
      screen.getByLabelText(es.plan.rationaleLabel),
      '  Empezamos por la   validación porque concentra los hallazgos. ',
    );
    expect(advance).toBeEnabled();
    expect(screen.queryByText(fill(es.plan.incomplete, { min: 10 }))).not.toBeInTheDocument();

    await user.click(advance);
    await user.type(
      screen.getByLabelText(es.workflow.advance.reasonLabel),
      '  Plan   acordado con el analista. ',
    );
    await user.click(screen.getByRole('button', { name: es.plan.saveAndDesign }));

    await waitFor(() => {
      expect(bodyOf(calls, `/api/v1/analyses/${ANALYSIS_ID}/test-plan`, 'PUT')).toEqual({
        criterion: 'paths',
        rationale: 'Empezamos por la validación porque concentra los hallazgos.',
        functions: [{ path: 'src/validators.js', function: 'validateForm', line: 10 }],
      });
    });
    await waitFor(() => {
      expect(bodyOf(calls, `/api/v1/analyses/${ANALYSIS_ID}/stage/advance`, 'POST')).toEqual({
        justification: 'Plan acordado con el analista.',
      });
    });
    expect(await screen.findByText(es.plan.nextStep.lockedTitle)).toBeInTheDocument();
    expect(screen.getByRole('listitem', { current: 'step' })).toHaveTextContent(es.stepper.design);
    expect(screen.queryByRole('button', { name: es.plan.include })).not.toBeInTheDocument();
  });

  it('does not advance when the server rejects the plan', async () => {
    const calls = renderPlan('developer', 'plan', {
      [`/api/v1/analyses/${ANALYSIS_ID}/test-plan`]: () =>
        calls.mock.calls.some(
          ([url, init]: unknown[]) =>
            String(url).endsWith('/test-plan') && (init as RequestInit | undefined)?.method === 'PUT',
        )
          ? {
              status: 422,
              body: {
                code: 'test_plan_function_unknown',
                message_key: 'errors.workflow.testPlanFunctionUnknown',
              },
            }
          : NO_PLAN,
      [`/api/v1/analyses/${ANALYSIS_ID}/stage/advance`]: { status: 200, body: analysis('design') },
    });
    const user = await signIn('cperez');
    const ranking = await screen.findByRole('list', { name: es.plan.rankingLabel });
    const [first] = within(ranking).getAllByRole('listitem');
    await user.click(within(first!).getByRole('button', { name: es.plan.include }));
    await user.type(screen.getByLabelText(es.plan.rationaleLabel), 'Una razón suficiente para el plan.');
    await user.click(screen.getByRole('button', { name: es.plan.saveAndDesign }));
    await user.type(screen.getByLabelText(es.workflow.advance.reasonLabel), 'Plan acordado con el analista.');
    await user.click(screen.getByRole('button', { name: es.plan.saveAndDesign }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      es.errors.workflow.testPlanFunctionUnknown,
    );
    expect(bodyOf(calls, `/api/v1/analyses/${ANALYSIS_ID}/stage/advance`, 'POST')).toBeUndefined();
    expect(screen.getByRole('listitem', { current: 'step' })).toHaveTextContent(es.stepper.plan);
  });

  it('names the function the server refused, from the error context, as text', async () => {
    const hostile = 'src/<img src=x onerror=alert(1)>.js';
    const calls = renderPlan('developer', 'plan', {
      [`/api/v1/analyses/${ANALYSIS_ID}/test-plan`]: () =>
        calls.mock.calls.some(
          ([url, init]: unknown[]) =>
            String(url).endsWith('/test-plan') && (init as RequestInit | undefined)?.method === 'PUT',
        )
          ? {
              status: 422,
              body: {
                code: 'test_plan_function_too_complex',
                message_key: 'errors.workflow.testPlanFunctionTooComplex',
                context: { path: hostile, function: 'validateForm', line: 7, extra: '10' },
              },
            }
          : NO_PLAN,
    });
    const user = await signIn('cperez');
    const ranking = await screen.findByRole('list', { name: es.plan.rankingLabel });
    const [first] = within(ranking).getAllByRole('listitem');
    await user.click(within(first!).getByRole('button', { name: es.plan.include }));
    await user.type(screen.getByLabelText(es.plan.rationaleLabel), 'Una razón suficiente para el plan.');
    await user.click(screen.getByRole('button', { name: es.plan.saveAndDesign }));
    await user.type(screen.getByLabelText(es.workflow.advance.reasonLabel), 'Plan acordado con el analista.');
    await user.click(screen.getByRole('button', { name: es.plan.saveAndDesign }));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain(`validateForm (${hostile}`);
    expect(document.querySelector('img')).toBeNull();
    // A non-string context value is dropped: the number 7 never reaches the message.
    expect(alert.textContent).not.toContain('7');
  });

  it('is read-only for the analyst even at the plan stage', async () => {
    renderPlan('analyst', 'plan');
    await signIn('mmarin');
    expect(await screen.findByText(es.plan.nextStep.emptyTitle)).toBeInTheDocument();
    expect(screen.getByText(es.plan.nextStep.readerBody)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.plan.include })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.plan.saveAndDesign })).not.toBeInTheDocument();
    expect(screen.getByLabelText(es.plan.rationaleLabel)).toBeDisabled();
  });

  it('is read-only for the analyst and before the plan stage', async () => {
    renderPlan('analyst', 'analysis');
    await signIn('mmarin');
    expect(await screen.findByText(es.plan.nextStep.notYetTitle)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.plan.include })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.plan.saveAndDesign })).not.toBeInTheDocument();
    expect(screen.getByLabelText(es.plan.rationaleLabel)).toBeDisabled();
  });
});
