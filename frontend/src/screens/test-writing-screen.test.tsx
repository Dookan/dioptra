/**
 * Stage E6: the scaffold is shown as text, the developer's file is saved as
 * text, and the tick beside a case means "you wrote something" — never "it is
 * correct". The analyst sees the screen without the editor.
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
  functions: [{ path: 'src/validators.js', function: 'validateForm', line: 10, ccn: 2 }],
  created_by_username: 'cperez',
  created_at: '2026-09-22T10:00:00Z',
  updated_at: '2026-09-22T10:00:00Z',
};

const SCAFFOLD_TEXT = [
  '// Dioptra · E6 scaffold — validateForm (src/validators.js:10)',
  'import { describe, it } from "vitest";',
  'import { validateForm } from "./src/validators.js";',
  '',
  'describe("validateForm", () => {',
  `  it("C1 · Sin datos → rechaza ${HOSTILE}", () => {`,
  '    // TODO(developer): write this case.',
  '  });',
  '});',
].join('\n');

function scaffold(content: string, written: boolean) {
  return {
    path: 'src/validators.js',
    function: 'validateForm',
    line: 10,
    language: 'javascript',
    runner: 'vitest',
    filename: 'validators.validateform.9d9d2b.dioptra.test.js',
    scaffold: SCAFFOLD_TEXT,
    content,
    stored_at: content === '' ? null : '2026-09-22T13:00:00Z',
    stored_by_username: content === '' ? null : 'cperez',
    parse_error: false,
    cases: [
      { id: 'C1', title: `Sin datos → rechaza ${HOSTILE}`, covers: ['R1', 'E1'], written },
      { id: 'C2', title: 'Con datos válidos', covers: ['R2'], written: false },
    ],
  };
}

const SCAFFOLD_URL = `/api/v1/analyses/${ANALYSIS_ID}/scaffold?path=src%2Fvalidators.js&function=validateForm&line=10`;
const TESTS_URL = `/api/v1/analyses/${ANALYSIS_ID}/tests`;
const STATES_URL = `/api/v1/analyses/${ANALYSIS_ID}/test-files`;

const STATES = [{ ...PLAN.functions[0], cases: 2, written: 0, parse_error: false }];

function fill(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_match, name: string) => String(values[name] ?? ''));
}

function renderTests(role: 'analyst' | 'developer', stage: string, routes: Routes = {}) {
  globalThis.location.hash = `#/projects/${PROJECT_ID}/analyses/${ANALYSIS_ID}/tests`;
  const calls = stubFetch({
    '/api/v1/auth/refresh': NO_SESSION,
    '/api/v1/auth/login': session(role),
    [`/api/v1/projects/${PROJECT_ID}`]: { status: 200, body: PROJECT },
    [`/api/v1/analyses/${ANALYSIS_ID}`]: { status: 200, body: analysis(stage) },
    [`/api/v1/analyses/${ANALYSIS_ID}/test-plan`]: { status: 200, body: PLAN },
    [SCAFFOLD_URL]: { status: 200, body: scaffold('', false) },
    [STATES_URL]: { status: 200, body: STATES },
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

describe('test writing screen', () => {
  it('shows the scaffold and a hostile case title as text, never as markup', async () => {
    renderTests('developer', 'tests');
    await signIn('cperez');
    expect(await screen.findByText(es.tests.scaffoldTitle)).toBeTruthy();
    await waitFor(() => {
      expect(document.querySelector('pre.codeblock')?.textContent).toBe(SCAFFOLD_TEXT);
    });
    // The title is rendered as a text node: no element is created from it.
    expect(screen.getAllByText(`Sin datos → rechaza ${HOSTILE}`).length).toBeGreaterThan(0);
    expect(document.querySelector('img')).toBeNull();
    expect(
      screen.getByText(fill(es.tests.nextStep.writeTitle_other, { written: 0, count: 2 })),
    ).toBeTruthy();
  });

  it('saves the developer file and marks only the cases with a body', async () => {
    const calls = renderTests('developer', 'tests', {
      [TESTS_URL]: { status: 200, body: scaffold(`${SCAFFOLD_TEXT}\n// mine`, true) },
    });
    const user = await signIn('cperez');
    const editor = (await screen.findByLabelText(es.tests.editorLabel)) as HTMLTextAreaElement;
    // The editor opens on the scaffold: the developer edits it, never a blank page.
    await waitFor(() => {
      expect(editor.value).toBe(SCAFFOLD_TEXT);
    });

    await user.type(editor, '\nconst a = 1;');
    await user.click(screen.getByRole('button', { name: es.tests.save }));
    await waitFor(() => {
      expect(screen.getByText(es.tests.saved)).toBeTruthy();
    });
    const put = (calls.mock.calls as unknown as [RequestInfo | URL, RequestInit | undefined][]).find(
      ([url, init]) => String(url) === TESTS_URL && init?.method === 'PUT',
    );
    expect(put).toBeTruthy();
    expect(JSON.parse(String(put?.[1]?.body)).content).toContain('const a = 1;');
    expect(screen.getAllByText(es.tests.caseWritten, { exact: false }).length).toBe(1);
    expect(screen.getAllByText(es.tests.caseEmpty, { exact: false }).length).toBe(1);
  });

  it('gives the analyst the screen without the editor', async () => {
    renderTests('analyst', 'tests');
    await signIn('mmarin');
    expect(await screen.findByText(es.tests.readOnly)).toBeTruthy();
    expect(screen.queryByRole('button', { name: es.tests.save })).toBeNull();
    expect((await screen.findByLabelText(es.tests.editorLabel)).hasAttribute('readonly')).toBe(true);
  });

  it('says the file cannot be read when it does not parse', async () => {
    renderTests('developer', 'tests', {
      [SCAFFOLD_URL]: {
        status: 200,
        body: { ...scaffold('it(', false), parse_error: true },
      },
    });
    await signIn('cperez');
    expect(await screen.findByText(es.tests.parseError)).toBeTruthy();
  });

  it('lands on the verification screen once the stage advances', async () => {
    renderTests('developer', 'tests', {
      [STATES_URL]: { status: 200, body: [{ ...STATES[0], cases: 1, written: 1 }] },
      [`/api/v1/analyses/${ANALYSIS_ID}/stage/advance`]: { status: 200, body: analysis('verification') },
    });
    const user = await signIn('cperez');
    await user.click(await screen.findByRole('button', { name: es.tests.advance.label }));
    await user.type(screen.getByLabelText(es.workflow.advance.reasonLabel), 'Todos los casos escritos.');
    await user.click(screen.getByRole('button', { name: es.tests.advance.label }));
    // The button's arrow promises "ejecutar y medir", and that is where it lands.
    await waitFor(() => {
      expect(globalThis.location.hash).toBe(`#/projects/${PROJECT_ID}/analyses/${ANALYSIS_ID}/verify`);
    });
  });
});
