/**
 * Stage E5: the diagram is drawn from the server's layout and edited Mermaid
 * stays text (day 14); the brief renders from the payload and the cases
 * declare what they cover (day 15).
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
    finding_counts: {},
    report_counts: {},
    triage: { total: 0, confirmed: 0, false_positive: 0, pending: 0, complete: true },
    tool_runs: [],
  };
}

const PLAN = {
  analysis_id: ANALYSIS_ID,
  criterion: 'decisions',
  rationale: 'Plan de prueba.',
  functions: [
    { path: 'src/validators.js', function: 'validateForm', line: 10, ccn: 12 },
    { path: 'src/utils.js', function: 'formatDate', line: 3, ccn: 2 },
  ],
  created_by_username: 'cperez',
  created_at: '2026-09-22T10:00:00Z',
  updated_at: '2026-09-22T10:00:00Z',
};

function diagram(editedText: string | null) {
  const nodes = [
    { id: 'n0', kind: 'start', label: 'validateForm', line: 10, x: 135, y: 20, width: 190, height: 46 },
    { id: 'n1', kind: 'decision', label: `if ${HOSTILE}`, line: 11, x: 135, y: 126, width: 190, height: 46 },
    { id: 'n2', kind: 'return', label: 'return false;', line: 11, x: 20, y: 232, width: 190, height: 46 },
    { id: 'n4', kind: 'process', label: 'x -= 1', line: 12, x: 250, y: 232, width: 190, height: 46 },
    { id: 'n3', kind: 'end', label: '', line: 13, x: 135, y: 338, width: 190, height: 46 },
  ];
  return {
    path: 'src/validators.js',
    function: 'validateForm',
    line: 10,
    language: 'javascript',
    complexity: 2,
    mermaid: 'flowchart TD\n    n0(["validateForm"])\n',
    graph: {
      name: 'validateForm',
      params: ['data'],
      nodes: nodes.map(({ id, kind, label, line }) => ({ id, kind, label, line })),
      edges: [
        { source: 'n0', target: 'n1', label: '' },
        { source: 'n1', target: 'n2', label: 'true' },
        { source: 'n1', target: 'n4', label: "case 'x'" },
        { source: 'n4', target: 'n1', label: 'loop' },
        { source: 'n2', target: 'n3', label: '' },
      ],
    },
    layout: {
      width: 460,
      height: 404,
      nodes,
      edges: [
        { source: 'n0', target: 'n1', label: '', points: [[230, 66], [230, 126]], back: false },
        { source: 'n1', target: 'n2', label: 'true', points: [[230, 172], [115, 232]], back: false },
        { source: 'n1', target: 'n4', label: "case 'x'", points: [[230, 172], [345, 232]], back: false },
        { source: 'n4', target: 'n1', label: 'loop', points: [[440, 255], [460, 255], [460, 149], [325, 149]], back: true },
        { source: 'n2', target: 'n3', label: '', points: [[115, 278], [230, 338]], back: false },
      ],
    },
    edited_text: editedText,
    edited_by_username: editedText === null ? null : 'cperez',
    edited_at: editedText === null ? null : '2026-09-22T11:00:00Z',
  };
}

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

const DIAGRAM_URL = `/api/v1/analyses/${ANALYSIS_ID}/diagram?path=src%2Fvalidators.js&function=validateForm&line=10`;
const BRIEF_URL = `/api/v1/analyses/${ANALYSIS_ID}/brief?path=src%2Fvalidators.js&function=validateForm&line=10`;
const STATES_URL = `/api/v1/analyses/${ANALYSIS_ID}/case-designs`;
const CASES_URL = `/api/v1/analyses/${ANALYSIS_ID}/cases`;
const APPROVE_URL = `/api/v1/analyses/${ANALYSIS_ID}/cases/approve`;

const BRIEF = {
  function: 'validateForm',
  path: 'src/validators.js',
  line: 10,
  language: 'javascript',
  params: ['data'],
  complexity: 2,
  min_cases: 3,
  items: [
    { id: 'R1', kind: 'branch', line: 11, text: `if ${HOSTILE}`, detail: 'true', values: [], finding_id: null },
    { id: 'R2', kind: 'branch', line: 11, text: `if ${HOSTILE}`, detail: 'false', values: [], finding_id: null },
    { id: 'F1', kind: 'boundary', line: 11, text: 'age >= 18', detail: '>=', values: ['17', '18', '19'], finding_id: null },
    { id: 'F2', kind: 'boundary', line: 12, text: 'role === "admin"', detail: '===', values: ['admin', ''], finding_id: null },
    { id: 'F3', kind: 'boundary', line: 13, text: 'x < limit', detail: '<', values: [], finding_id: null },
    { id: 'E1', kind: 'error', line: 11, text: 'return false;', detail: 'early_return', values: [], finding_id: null },
    { id: 'M1', kind: 'malicious', line: 12, text: 'Registro sin sanear', detail: 'dioptra.log', values: ['CWE-117'], finding_id: 'f-1' },
  ],
};

function briefState(cases: { title: string; covers: string[] }[], approvedBy: string | null = null) {
  return {
    brief: BRIEF,
    cases,
    approved_at: approvedBy === null ? null : '2026-09-22T12:00:00Z',
    approved_by_username: approvedBy,
  };
}

function states(first: string | null, second: string | null) {
  return [
    { ...PLAN.functions[0], cases: first === null ? 0 : 3, approved_at: first === null ? null : '2026-09-22T12:00:00Z', approved_by_username: first },
    { ...PLAN.functions[1], cases: second === null ? 0 : 1, approved_at: second === null ? null : '2026-09-22T12:00:00Z', approved_by_username: second },
  ];
}

const FULL_CASES = [
  { title: `C1 · Sin datos → rechaza ${HOSTILE}`, covers: ['R1', 'E1'] },
  { title: 'C2 · Con 17, 18 y 19 años', covers: ['R2', 'F1', 'F2', 'F3'] },
  { title: 'C3 · Entrada maliciosa en el registro', covers: ['M1'] },
];

function renderDesign(role: 'analyst' | 'developer', stage: string, routes: Routes = {}) {
  globalThis.location.hash = `#/projects/${PROJECT_ID}/analyses/${ANALYSIS_ID}/design`;
  const calls = stubFetch({
    '/api/v1/auth/refresh': NO_SESSION,
    '/api/v1/auth/login': session(role),
    [`/api/v1/projects/${PROJECT_ID}`]: { status: 200, body: PROJECT },
    [`/api/v1/analyses/${ANALYSIS_ID}`]: { status: 200, body: analysis(stage) },
    [`/api/v1/analyses/${ANALYSIS_ID}/test-plan`]: { status: 200, body: PLAN },
    [DIAGRAM_URL]: { status: 200, body: diagram(null) },
    [BRIEF_URL]: { status: 200, body: briefState([]) },
    [STATES_URL]: { status: 200, body: states(null, null) },
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

describe('case design screen', () => {
  it('draws the diagram from the layout with hostile labels as text', async () => {
    renderDesign('developer', 'design');
    await signIn('cperez');

    const svg = await screen.findByRole('img', {
      name: fill(es.design.diagram.alt, { name: 'validateForm', count: 2 }),
    });
    expect(svg.querySelectorAll('.fd-node')).toHaveLength(5);
    expect(svg.querySelector('.fd-decision')).not.toBeNull();
    expect(svg.querySelector('.fd-return')).not.toBeNull();
    const process = svg.querySelector('.fd-process');
    expect(process).not.toBeNull();
    expect(process?.getAttribute('clip-path')?.startsWith('url(#')).toBe(true);
    expect(svg.querySelectorAll('.fd-edge')).toHaveLength(5);
    expect(svg.querySelector('.fd-back')).not.toBeNull();
    expect(document.querySelector('img')).toBeNull();
    expect(svg.textContent).toContain(`if ${HOSTILE}`);
    expect(svg.textContent).toContain(es.design.edge.true);
    expect(svg.textContent).toContain(es.design.edge.loop);
    expect(svg.textContent).toContain("case 'x'");
    // Only the builder's words go through i18n; a missing key would leak its name.
    expect(svg.textContent).not.toContain('design.edge.');
    expect(svg.textContent).toContain(fill(es.design.node.start, { name: 'validateForm' }));
    // No inline style anywhere in the drawing (CSP style-src 'self').
    expect(svg.querySelectorAll('[style]')).toHaveLength(0);
    expect(svg.matches('[style]')).toBe(false);
    // At the design stage itself: the progress banner, not "not yet".
    expect(
      screen.getByText(fill(es.design.nextStep.designTitle_other, { approved: 0, count: 2 })),
    ).toBeInTheDocument();
    expect(screen.queryByText(es.design.nextStep.notYetTitle)).not.toBeInTheDocument();
    expect(screen.getByText(fill(es.design.complexity, { count: 2 }))).toBeInTheDocument();
    expect(screen.getByText(es.design.mermaid.note)).toBeInTheDocument();
    expect(screen.getByText(es.design.diagram.legend)).toBeInTheDocument();
    expect(
      screen.getByText(fill(es.statusbar.step, { step: 5, total: 8, stage: es.statusbar.stage.design })),
    ).toBeInTheDocument();
    expect(screen.getByText(es.stepper.design, { selector: '.stp.now' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: es.nav.workflow })).toHaveAttribute('aria-current', 'page');
  });

  it('lets the developer save an edited Mermaid text, shown as text only', async () => {
    const calls = renderDesign('developer', 'design', {
      [`/api/v1/analyses/${ANALYSIS_ID}/diagram`]: {
        status: 200,
        body: diagram('flowchart TD\n  a["<b>x</b>"] --> b'),
      },
    });
    const user = await signIn('cperez');
    await user.click(await screen.findByRole('button', { name: es.design.mermaid.edit }));
    const text = screen.getByLabelText(es.design.mermaid.textLabel);
    await user.clear(text);
    // user-event treats `[` and `{` as key descriptors; paste the text instead.
    await user.click(text);
    await user.paste('flowchart TD\n  a["<b>x</b>"] --> b');
    await user.click(screen.getByRole('button', { name: es.design.mermaid.save }));

    await waitFor(() => {
      expect(bodyOf(calls, `/api/v1/analyses/${ANALYSIS_ID}/diagram`, 'PUT')).toEqual({
        path: 'src/validators.js',
        function: 'validateForm',
        line: 10,
        text: 'flowchart TD\n  a["<b>x</b>"] --> b',
      });
    });
    expect(await screen.findByText(fill(es.design.mermaid.editedBy, { user: 'cperez' }))).toBeInTheDocument();
    expect(document.querySelector('.codeblock b')).toBeNull();
    expect(document.querySelector('.codeblock')?.textContent).toBe('flowchart TD\n  a["<b>x</b>"] --> b');
    expect(screen.getByRole('button', { name: es.design.mermaid.restore })).toBeInTheDocument();
  });

  it('edits from the saved text and restores by sending an empty text', async () => {
    const edited = 'flowchart TD\n  a --> b';
    const calls = renderDesign('developer', 'design', {
      [DIAGRAM_URL]: { status: 200, body: diagram(edited) },
      [`/api/v1/analyses/${ANALYSIS_ID}/diagram`]: { status: 200, body: diagram(null) },
    });
    const user = await signIn('cperez');
    await user.click(await screen.findByRole('button', { name: es.design.mermaid.edit }));
    expect(screen.getByLabelText(es.design.mermaid.textLabel)).toHaveValue(edited);
    await user.click(screen.getByRole('button', { name: es.design.mermaid.cancel }));

    await user.click(screen.getByRole('button', { name: es.design.mermaid.restore }));
    await waitFor(() => {
      expect(bodyOf(calls, `/api/v1/analyses/${ANALYSIS_ID}/diagram`, 'PUT')).toEqual({
        path: 'src/validators.js',
        function: 'validateForm',
        line: 10,
        text: '',
      });
    });
    await waitFor(() => {
      expect(document.querySelector('.codeblock')?.textContent).toBe(
        'flowchart TD\n    n0(["validateForm"])\n',
      );
    });
    expect(screen.queryByRole('button', { name: es.design.mermaid.restore })).not.toBeInTheDocument();
  });

  it('renders the brief from the payload, hostile text as text, and the empty value named', async () => {
    renderDesign('developer', 'design');
    await signIn('cperez');
    const minimum = await screen.findByText(fill(es.design.brief.minCasesWithMalicious, { count: 3 }));
    const list = minimum.closest('ul');
    expect(list).not.toBeNull();
    expect(list?.textContent).toContain(
      fill(es.design.brief.branch, { line: 11, text: `if ${HOSTILE}`, side: es.design.edge.true }),
    );
    expect(list?.textContent).toContain(
      fill(es.design.brief.boundary, { line: 11, text: 'age >= 18', values: '17, 18, 19' }),
    );
    expect(list?.textContent).toContain(
      fill(es.design.brief.boundary, {
        line: 12,
        text: 'role === "admin"',
        values: `admin, ${es.design.brief.emptyValue}`,
      }),
    );
    expect(list?.textContent).toContain(
      fill(es.design.brief.boundaryEmpty, { line: 13, text: 'x < limit' }),
    );
    expect(list?.textContent).toContain(
      fill(es.design.brief.error.early_return, { line: 11, text: 'return false;' }),
    );
    expect(list?.textContent).toContain(
      fill(es.design.brief.malicious, { line: 12, text: 'Registro sin sanear' }),
    );
    expect(list?.textContent).not.toContain('design.brief.');
    expect(document.querySelector('img')).toBeNull();
    expect(screen.getByText(es.design.cases.empty)).toBeInTheDocument();
    // Nothing to approve yet, and the stage cannot be closed from here.
    expect(screen.getByRole('button', { name: es.design.cases.approve })).toBeDisabled();
    expect(screen.getByRole('button', { name: es.design.advance.label })).toBeDisabled();
    expect(
      screen.getByText(fill(es.design.advance.blocked_other, { approved: 0, count: 2 })),
    ).toBeInTheDocument();
  });

  it('lets the developer write cases, tick what they cover, save and approve', async () => {
    let saved = briefState([]);
    const calls = renderDesign('developer', 'design', {
      [CASES_URL]: () => ({ status: 200, body: saved }),
      [APPROVE_URL]: { status: 200, body: briefState(FULL_CASES, 'cperez') },
    });
    const user = await signIn('cperez');
    await screen.findByRole('button', { name: es.design.cases.add });
    for (const draft of FULL_CASES) {
      await user.click(screen.getByRole('button', { name: es.design.cases.add }));
      const inputs = screen.getAllByPlaceholderText(es.design.cases.placeholder);
      const input = inputs[inputs.length - 1];
      if (input === undefined) throw new Error('no case input');
      await user.click(input);
      await user.paste(draft.title);
      const row = input.closest('li');
      if (row === null) throw new Error('no case row');
      for (const id of draft.covers) {
        const chip = Array.from(row.querySelectorAll('button')).find((b) => b.textContent === id);
        if (chip === undefined) throw new Error(`no chip ${id}`);
        await user.click(chip);
        expect(chip).toHaveAttribute('aria-pressed', 'true');
      }
    }
    // Every item ticked and three cases: only the unsaved state blocks approval.
    expect(screen.getByText(es.design.cases.unsaved)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: es.design.cases.approve })).toBeDisabled();

    saved = briefState(FULL_CASES);
    await user.click(screen.getByRole('button', { name: es.design.cases.save }));
    await waitFor(() => {
      expect(bodyOf(calls, CASES_URL, 'PUT')).toEqual({
        path: 'src/validators.js',
        function: 'validateForm',
        line: 10,
        cases: FULL_CASES,
      });
    });
    expect(await screen.findByText(es.design.cases.saved)).toBeInTheDocument();
    expect(screen.getByText(es.design.cases.complete)).toBeInTheDocument();
    const approve = screen.getByRole('button', { name: es.design.cases.approve });
    expect(approve).toBeEnabled();
    await user.click(approve);
    await waitFor(() => {
      expect(bodyOf(calls, APPROVE_URL, 'POST')).toEqual({
        path: 'src/validators.js',
        function: 'validateForm',
        line: 10,
      });
    });
    expect(await screen.findByText(fill(es.design.cases.approved, { user: 'cperez' }))).toBeInTheDocument();
    expect(screen.getByRole('button', { name: es.design.cases.approve })).toBeDisabled();
    // One of two functions approved: the banner counts it, the stage stays closed.
    expect(
      screen.getByText(fill(es.design.nextStep.designTitle_other, { approved: 1, count: 2 })),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: es.design.advance.label })).toBeDisabled();
    // The hostile case title is a text node, never markup.
    expect(document.querySelector('img')).toBeNull();
    expect(screen.getByRole('button', { name: fill(es.design.cases.removeCase, { n: 1 }) })).toBeInTheDocument();
    expect(
      screen.getByText(fill(es.design.cases.approveHint_other, { count: 3 })),
    ).toBeInTheDocument();
  });

  it('shows what is still uncovered and the server refusal, and reopens after an edit', async () => {
    const calls = renderDesign('developer', 'design', {
      [BRIEF_URL]: { status: 200, body: briefState(FULL_CASES, 'cperez') },
      [STATES_URL]: { status: 200, body: states('cperez', 'cperez') },
      [CASES_URL]: {
        status: 200,
        body: briefState([...FULL_CASES.slice(0, 2), { title: 'C3 · Entrada maliciosa en el registro', covers: [] }]),
      },
      [APPROVE_URL]: {
        status: 422,
        body: { code: 'brief_not_covered', message_key: 'errors.workflow.briefNotCovered' },
      },
    });
    const user = await signIn('cperez');
    expect(await screen.findByText(fill(es.design.cases.approved, { user: 'cperez' }))).toBeInTheDocument();
    // Every function approved: the way to the next stage is open.
    expect(screen.getByRole('button', { name: es.design.advance.label })).toBeEnabled();

    const rows = screen.getAllByPlaceholderText(es.design.cases.placeholder);
    const third = rows[2]?.closest('li');
    if (!third) throw new Error('no third row');
    const m1 = Array.from(third.querySelectorAll('button')).find((b) => b.textContent === 'M1');
    if (m1 === undefined) throw new Error('no chip');
    await user.click(m1);
    expect(screen.getByText(fill(es.design.cases.uncovered, { items: 'M1' }))).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: es.design.cases.save }));
    expect(await screen.findByText(es.design.cases.reopened)).toBeInTheDocument();
    await waitFor(() => {
      expect(bodyOf(calls, CASES_URL, 'PUT')).not.toBeUndefined();
    });
    expect(screen.queryByText(fill(es.design.cases.approved, { user: 'cperez' }))).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: es.design.cases.approve })).toBeDisabled();
    expect(screen.getByRole('button', { name: es.design.advance.label })).toBeDisabled();
  });

  it('keeps approval disabled while the case count is below the minimum', async () => {
    const calls = renderDesign('developer', 'design', {
      [BRIEF_URL]: {
        status: 200,
        body: briefState([
          { title: 'C1 · Todo lo que falla', covers: ['R1', 'E1', 'M1'] },
          { title: 'C2 · Todo lo que pasa', covers: ['R2', 'F1', 'F2', 'F3'] },
        ]),
      },
      [APPROVE_URL]: { status: 200, body: briefState(FULL_CASES, 'cperez') },
    });
    const user = await signIn('cperez');
    expect(await screen.findByText(fill(es.design.cases.tooFew_one, { count: 1 }))).toBeInTheDocument();
    const approve = screen.getByRole('button', { name: es.design.cases.approve });
    expect(approve).toBeDisabled();
    await user.click(approve);
    expect(bodyOf(calls, APPROVE_URL, 'POST')).toBeUndefined();
  });

  it('shows the analyst the cases read-only', async () => {
    renderDesign('analyst', 'design', {
      [BRIEF_URL]: { status: 200, body: briefState(FULL_CASES, 'cperez') },
    });
    await signIn('mmarin');
    expect(await screen.findByText(es.design.cases.readOnly)).toBeInTheDocument();
    expect(await screen.findByText(`C1 · Sin datos → rechaza ${HOSTILE}`)).toBeInTheDocument();
    expect(document.querySelector('img')).toBeNull();
    expect(screen.queryByPlaceholderText(es.design.cases.placeholder)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.design.cases.approve })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.design.advance.label })).not.toBeInTheDocument();
    expect(screen.getByText(fill(es.design.cases.approved, { user: 'cperez' }))).toBeInTheDocument();
  });

  it('hides the edit button from the analyst at design and from the developer off design', async () => {
    renderDesign('analyst', 'design');
    await signIn('mmarin');
    expect(await screen.findByText(es.design.mermaid.note)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.design.mermaid.edit })).not.toBeInTheDocument();
  });

  it('shows the developer the diagrams read-only before and after the design stage', async () => {
    renderDesign('developer', 'plan');
    await signIn('cperez');
    expect(await screen.findByText(es.design.nextStep.notYetTitle)).toBeInTheDocument();
    expect(await screen.findByText(es.design.mermaid.note)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.design.mermaid.edit })).not.toBeInTheDocument();
  });

  it('keeps the developer read-only once the stage has moved past design', async () => {
    renderDesign('developer', 'tests', {
      [STATES_URL]: { status: 200, body: states('cperez', 'cperez') },
    });
    await signIn('cperez');
    expect(await screen.findByText(es.design.mermaid.note)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.design.mermaid.edit })).not.toBeInTheDocument();
    expect(screen.getByText(es.design.nextStep.doneTitle)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.design.cases.save })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.design.advance.label })).not.toBeInTheDocument();
  });

  it('is read-only for the analyst and shows the server refusal for a bad function', async () => {
    renderDesign('analyst', 'design', {
      [DIAGRAM_URL]: {
        status: 422,
        body: { code: 'ast_parse_failed', message_key: 'errors.ast.parseFailed' },
      },
    });
    await signIn('mmarin');
    expect(await screen.findByRole('alert')).toHaveTextContent(es.errors.ast.parseFailed);
    expect(screen.queryByRole('button', { name: es.design.mermaid.edit })).not.toBeInTheDocument();
  });
});
