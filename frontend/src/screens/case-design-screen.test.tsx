/** Stage E5 day 14: the diagram is drawn from the server's layout; edited Mermaid stays text. */
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

function renderDesign(role: 'analyst' | 'developer', stage: string, routes: Routes = {}) {
  globalThis.location.hash = `#/projects/${PROJECT_ID}/analyses/${ANALYSIS_ID}/design`;
  const calls = stubFetch({
    '/api/v1/auth/refresh': NO_SESSION,
    '/api/v1/auth/login': session(role),
    [`/api/v1/projects/${PROJECT_ID}`]: { status: 200, body: PROJECT },
    [`/api/v1/analyses/${ANALYSIS_ID}`]: { status: 200, body: analysis(stage) },
    [`/api/v1/analyses/${ANALYSIS_ID}/test-plan`]: { status: 200, body: PLAN },
    [DIAGRAM_URL]: { status: 200, body: diagram(null) },
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
    // At the design stage itself: the diagrams banner, not "not yet".
    expect(screen.getByText(fill(es.design.nextStep.diagramsTitle, { count: 2 }))).toBeInTheDocument();
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
    renderDesign('developer', 'tests');
    await signIn('cperez');
    expect(await screen.findByText(es.design.mermaid.note)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.design.mermaid.edit })).not.toBeInTheDocument();
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
