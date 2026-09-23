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
  stage: 'analysis',
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

  it('offers the next stage only when every finding has a verdict, and posts the reason', async () => {
    const reviewed = finding('f-1', {
      verdict: 'confirmed',
      verdict_justification: 'Es real y afecta al formulario público.',
      verdict_by_username: 'mmarin',
      verdict_at: '2026-09-22T10:00:00Z',
    });
    const calls = renderFindings('analyst', [reviewed], {
      [`/api/v1/analyses/${ANALYSIS_ID}/stage/advance`]: {
        status: 200,
        body: { ...ANALYSIS, stage: 'plan', triage: { ...ANALYSIS.triage, pending: 0, complete: true } },
      },
    });
    const user = await signIn();

    await user.click(await screen.findByRole('button', { name: es.findings.nextStep.advance }));
    const reason = screen.getByLabelText(es.workflow.advance.reasonLabel);
    const submit = screen.getByRole('button', { name: es.findings.nextStep.advance });
    expect(submit).toBeDisabled();
    await user.type(reason, 'Revisión completa con el equipo.');
    await user.click(submit);

    await waitFor(() => {
      expect(bodyOf(calls, `/api/v1/analyses/${ANALYSIS_ID}/stage/advance`, 'POST')).toEqual({
        justification: 'Revisión completa con el equipo.',
      });
    });
    // The stepper follows the server's stage, and the status bar says where we are.
    expect(await screen.findByRole('listitem', { current: 'step' })).toHaveTextContent(es.stepper.plan);
    expect(
      screen.getByText(fill(es.statusbar.step, { step: 4, total: 8, stage: es.statusbar.stage.plan })),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.findings.nextStep.advance })).not.toBeInTheDocument();
  });

  it('offers to start the review at the code stage, only once the pipeline is done', async () => {
    renderFindings('analyst', [finding('f-1')], {
      [`/api/v1/analyses/${ANALYSIS_ID}`]: { status: 200, body: { ...ANALYSIS, stage: 'code' } },
    });
    await signIn();
    expect(await screen.findByRole('button', { name: es.project.stage.startReview })).toBeEnabled();
    expect(screen.queryByRole('button', { name: es.findings.nextStep.advance })).not.toBeInTheDocument();
  });

  it('keeps "start the review" disabled while the pipeline is still running', async () => {
    renderFindings('analyst', [], {
      [`/api/v1/analyses/${ANALYSIS_ID}`]: {
        status: 200,
        body: { ...ANALYSIS, stage: 'code', status: 'running' },
      },
    });
    await signIn();
    expect(await screen.findByRole('button', { name: es.project.stage.startReview })).toBeDisabled();
  });

  it('keeps the next stage disabled while a verdict is pending', async () => {
    const reviewed = finding('f-2', {
      verdict: 'confirmed',
      verdict_justification: 'x',
      verdict_by_username: 'mmarin',
      verdict_at: '2026-09-22T10:00:00Z',
    });
    renderFindings('analyst', [finding('f-1'), reviewed]);
    const user = await signIn();
    const advance = await screen.findByRole('button', { name: es.findings.nextStep.advance });
    expect(advance).toBeDisabled();
    await user.click(advance);
    expect(screen.queryByLabelText(es.workflow.advance.reasonLabel)).not.toBeInTheDocument();
  });

  it('shows the gate refusal in plain words when the server closes the door', async () => {
    renderFindings('analyst', [finding('f-1', { verdict: 'confirmed', verdict_justification: 'x', verdict_by_username: 'mmarin', verdict_at: '2026-09-22T10:00:00Z' })], {
      [`/api/v1/analyses/${ANALYSIS_ID}/stage/advance`]: {
        status: 409,
        body: { code: 'gate_closed', message_key: 'errors.workflow.gate.triagePending' },
      },
    });
    const user = await signIn();
    await user.click(await screen.findByRole('button', { name: es.findings.nextStep.advance }));
    await user.type(screen.getByLabelText(es.workflow.advance.reasonLabel), 'Una razón suficiente.');
    await user.click(screen.getByRole('button', { name: es.findings.nextStep.advance }));
    expect(await screen.findByRole('alert')).toHaveTextContent(es.errors.workflow.gate.triagePending);
    expect(screen.getByRole('listitem', { current: 'step' })).toHaveTextContent(es.stepper.analysis);
  });

  it('hides the verdict form once the analysis has left the review stage', async () => {
    renderFindings('analyst', [finding('f-1')], {
      [`/api/v1/analyses/${ANALYSIS_ID}`]: { status: 200, body: { ...ANALYSIS, stage: 'plan' } },
    });
    await signIn();
    expect(await screen.findByText(es.findings.what)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.findings.confirm })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(es.findings.justificationLabel)).not.toBeInTheDocument();
  });

  it('hides the verdict form from a developer', async () => {
    renderFindings('developer', [finding('f-1')]);
    await signIn('cperez');
    expect(await screen.findByText(es.findings.what)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.findings.confirm })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(es.findings.justificationLabel)).not.toBeInTheDocument();
  });

  it('paints one page at a time and walks to the next', async () => {
    // A real Laravel application produced 687 findings and the browser froze
    // painting a card for every one of them (2026-09-23). The server was never
    // the problem: it answered in 0.08 s.
    const many = Array.from({ length: 60 }, (_, i) => finding(`f-${i + 1}`));
    renderFindings('analyst', many);
    const user = await signIn();

    // Scoped to the LIST: a title also appears in the detail panel beside it.
    const list = () => within(screen.getByRole('list', { name: es.findings.listLabel }));
    await screen.findByRole('list', { name: es.findings.listLabel });

    expect(list().getByText('Hallazgo f-1')).toBeInTheDocument();
    expect(list().getByText('Hallazgo f-25')).toBeInTheDocument();
    expect(list().queryByText('Hallazgo f-26')).not.toBeInTheDocument();
    expect(
      screen.getByText(fill(es.findings.page.of, { page: 1, pages: 3, shown: 25, total: 60 })),
    ).toBeInTheDocument();
    expect(
      (screen.getByRole('button', { name: es.findings.page.previous }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);

    await user.click(screen.getByRole('button', { name: es.findings.page.next }));
    expect(list().getByText('Hallazgo f-26')).toBeInTheDocument();
    expect(list().queryByText('Hallazgo f-25')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: es.findings.page.next }));
    expect(list().getByText('Hallazgo f-60')).toBeInTheDocument();
    expect(
      (screen.getByRole('button', { name: es.findings.page.next }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  it('keeps dependency findings out of the queue but visible on the screen', async () => {
    // `mmarin`, from real use: 422 of a Laravel app's 687 findings were inside
    // `vendor/`, and E3 demanded a written verdict for every one of them.
    renderFindings('analyst', [
      finding('own-1', { path: 'app/Http/Controllers/X.php' }),
      finding('dep-1', { path: 'vendor/symfony/console/A.php', third_party: true }),
      finding('dep-2', { path: 'vendor/laravel/framework/B.php', third_party: true }),
    ]);
    await signIn();

    // The queue counts ONE, not three.
    expect(
      await screen.findByText(fill(es.findings.nextStep.pendingTitle, { count: 1 })),
    ).toBeInTheDocument();

    const list = within(screen.getByRole('list', { name: es.findings.listLabel }));
    expect(list.getByText('Hallazgo own-1')).toBeInTheDocument();
    expect(list.queryByText('Hallazgo dep-1')).not.toBeInTheDocument();

    // But they are on the screen, in their own section, with the reason.
    const deps = within(screen.getByRole('list', { name: es.findings.thirdParty.listLabel }));
    expect(deps.getByText('Hallazgo dep-1')).toBeInTheDocument();
    expect(deps.getByText('Hallazgo dep-2')).toBeInTheDocument();
    expect(screen.getByText(es.findings.thirdParty.why)).toBeInTheDocument();
  });

  it('offers no verdict form for a dependency finding, and says why', async () => {
    renderFindings('analyst', [
      finding('dep-1', { path: 'vendor/x/y.php', third_party: true }),
    ]);
    const user = await signIn();
    const deps = within(
      await screen.findByRole('list', { name: es.findings.thirdParty.listLabel }),
    );
    await user.click(deps.getByText('Hallazgo dep-1'));

    expect(await screen.findByText(es.findings.thirdParty.note)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.findings.confirm })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(es.findings.justificationLabel)).not.toBeInTheDocument();
  });

  it('makes the card list its own scroll region, not the page', async () => {
    // What `mmarin` asked for: "deberían bajar las tarjetas si tengo el
    // puntero sobre la caja de las tarjetas". Before this the page scrolled
    // and the cards came with it.
    renderFindings('analyst', Array.from({ length: 60 }, (_, i) => finding(`f-${i + 1}`)));
    await signIn();
    const list = await screen.findByRole('list', { name: es.findings.listLabel });
    expect(list.className).toContain('scrollpane');
    expect((list as HTMLElement).tabIndex).toBe(0);
    // The pager must NOT be inside the scrolling box, or it scrolls away.
    const pager = screen.getByRole('button', { name: es.findings.page.next }).parentElement;
    expect(pager?.className).toContain('pager');
    expect(list.contains(pager)).toBe(false);
  });

  it('exposes the detail as a named region a keyboard can reach and scroll', async () => {
    // A scrollable box that is not focusable cannot be scrolled with the
    // keyboard, and an unnamed one is announced as nothing. Asked for by
    // `mmarin` after the sticky panel turned out not to look scrollable.
    renderFindings('analyst', [finding('f-1')]);
    await signIn();
    const detail = await screen.findByRole('region', { name: es.findings.detailLabel });
    expect(detail.tabIndex).toBe(0);
    expect(detail.className).toContain('scrollpane');
  });

  it('does not show a pager when everything fits on one page', async () => {
    renderFindings('analyst', [finding('f-1'), finding('f-2')]);
    await signIn();
    await screen.findByRole('list', { name: es.findings.listLabel });
    expect(screen.queryByRole('button', { name: es.findings.page.next })).not.toBeInTheDocument();
  });

  it('goes back to the first page when a filter changes', async () => {
    const many = [
      ...Array.from({ length: 40 }, (_, i) => finding(`f-${i + 1}`)),
      finding('solo-critico', { severity: 'critical', title: 'Hallazgo solo-critico' }),
    ];
    renderFindings('analyst', many);
    const user = await signIn();
    const list = () => within(screen.getByRole('list', { name: es.findings.listLabel }));
    await screen.findByRole('list', { name: es.findings.listLabel });

    await user.click(screen.getByRole('button', { name: es.findings.page.next }));
    expect(list().getByText('Hallazgo f-26')).toBeInTheDocument();

    // Filtering down to a single finding must not leave the list on a page
    // that no longer exists.
    await user.selectOptions(screen.getByLabelText(es.findings.filters.severity), 'critical');
    expect(list().getByText('Hallazgo solo-critico')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.findings.page.next })).not.toBeInTheDocument();
  });

  it('returns to page one on a filter that still has several pages', async () => {
    // The test above narrows to ONE finding, so `pages` becomes 1 and the
    // clamp `Math.min(page, pages - 1)` lands on page 1 by itself: it proves
    // the clamp, not the reset. The precommit coverage adversary removed all
    // four `setPage(0)` calls and the whole suite stayed green (2026-09-23).
    // Here the narrowed set keeps THREE pages, so clamp and reset give
    // different answers: without the reset the analyst stays on page 3 and
    // reads the LAST cards of the narrowed list instead of the first.
    const many = [
      ...Array.from({ length: 40 }, (_, i) => finding(`f-${i + 1}`)),
      ...Array.from({ length: 60 }, (_, i) =>
        finding(`c-${i + 1}`, { severity: 'critical', title: `Hallazgo c-${i + 1}` }),
      ),
    ];
    renderFindings('analyst', many);
    const user = await signIn();
    const list = () => within(screen.getByRole('list', { name: es.findings.listLabel }));
    await screen.findByRole('list', { name: es.findings.listLabel });

    await user.click(screen.getByRole('button', { name: es.findings.page.next }));
    await user.click(screen.getByRole('button', { name: es.findings.page.next }));
    expect(list().queryByText('Hallazgo c-1')).not.toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText(es.findings.filters.severity), 'critical');

    // First card of the narrowed set, and the set still HAS a next page —
    // which is what distinguishes a reset from the clamp.
    expect(list().getByText('Hallazgo c-1')).toBeInTheDocument();
    expect(list().queryByText('Hallazgo c-60')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: es.findings.page.next })).toBeEnabled();
  });
});
