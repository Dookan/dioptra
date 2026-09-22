/** Stage E8 screen: sections, one edit = one version, signing locks. */
import es from '../locales/es.json';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { App } from '../app';
import { AuthProvider } from '../auth/auth-provider';
import { NO_SESSION, stubFetch, type Routes } from '../test/http';

const PROJECT_ID = '22222222-2222-4222-8222-222222222222';
const ANALYSIS_ID = 'a-1';

const SESSION = {
  status: 200,
  body: {
    access_token: 'an-access-token',
    token_type: 'bearer',
    expires_in: 900,
    user: {
      id: '0f9b2a5e-0000-4000-8000-000000000001',
      username: 'mmarin',
      display_name: 'Moises Marin',
      role: 'analyst',
      must_change_password: false,
    },
  },
};

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
  stage: 'report',
  languages: {},
  frameworks: [],
  lockfiles: [],
  created_at: '2026-09-21T12:00:00Z',
  started_at: null,
  finished_at: null,
  // One medium finding was discarded: the preview must draw what the PDF prints.
  finding_counts: { high: 2, medium: 1, low: 1 },
  report_counts: { high: 2, low: 1 },
  triage: { total: 3, confirmed: 3, false_positive: 0, pending: 0, complete: true },
  tool_runs: [],
};

const SECTIONS = [
  { key: 'introduction', label: 'Introducción', text: 'Párrafo uno.\n\nPárrafo <b>dos</b>.', edited: false },
  { key: 'summary', label: 'Resumen ejecutivo', text: 'El análisis identificó 3 hallazgo(s).', edited: false },
  { key: 'findings_intro', label: 'Hallazgos de vulnerabilidades', text: 'Intro.', edited: false },
  { key: 'dependencies_intro', label: 'Hallazgos sobre paquetes y dependencias', text: 'Deps.', edited: false },
  { key: 'practices', label: 'Errores y prácticas no adecuadas en el código', text: 'Prácticas.', edited: false },
  { key: 'coverage_intro', label: 'Cobertura de herramientas', text: 'Cobertura.', edited: false },
];

const BASELINE = { number: 1, persisted: false, signed: false, sections: SECTIONS, versions: [] };

const VERSION_TWO = {
  number: 2,
  persisted: true,
  signed: false,
  sections: SECTIONS.map((section) =>
    section.key === 'introduction' ? { ...section, text: 'Texto nuevo.', edited: true } : section,
  ),
  versions: [
    {
      number: 1,
      change_summary: 'Informe generado automáticamente',
      areas: 'Todas',
      created_by_username: 'mmarin',
      created_at: '2026-09-22T10:00:00Z',
      signed_by_username: null,
      signed_at: null,
      excluded_findings: null,
      content_hash: null,
    },
    {
      number: 2,
      change_summary: 'Se reescribió la introducción.',
      areas: 'Introducción',
      created_by_username: 'mmarin',
      created_at: '2026-09-22T10:05:00Z',
      signed_by_username: null,
      signed_at: null,
      excluded_findings: null,
      content_hash: null,
    },
  ],
};

/** Interpolate one `{{name}}` of a locale string, so tests never restate the copy. */
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

function renderReport(state: unknown, routes: Routes = {}) {
  globalThis.location.hash = `#/projects/${PROJECT_ID}/analyses/${ANALYSIS_ID}/report`;
  const calls = stubFetch({
    '/api/v1/auth/refresh': NO_SESSION,
    '/api/v1/auth/login': SESSION,
    [`/api/v1/projects/${PROJECT_ID}`]: { status: 200, body: PROJECT },
    [`/api/v1/analyses/${ANALYSIS_ID}`]: { status: 200, body: ANALYSIS },
    [`/api/v1/analyses/${ANALYSIS_ID}/report/current`]: { status: 200, body: state },
    ...routes,
  });
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

describe('report screen', () => {
  it('lists the sections and previews the selected one as text', async () => {
    renderReport(BASELINE);
    await signIn();

    expect(await screen.findByText(es.report.nextStep.readyTitle)).toBeInTheDocument();
    expect(screen.getByText(es.report.versionLineBaseline)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Introducción' })).toBeInTheDocument();
    expect(screen.getByText('Párrafo uno.')).toBeInTheDocument();
    expect(screen.getByText('Párrafo <b>dos</b>.')).toBeInTheDocument();
    expect(document.querySelector('.repout b + p b')).toBeNull();
    expect(screen.getByRole('button', { name: es.report.export.pdf })).toBeEnabled();
    expect(screen.getByText(es.report.versions.none)).toBeInTheDocument();
    expect(screen.getByRole('listitem', { current: 'step' })).toHaveTextContent(es.stepper.report);
  });

  it('draws the executive-summary bars from the report counts, not from every finding', async () => {
    renderReport(BASELINE);
    const user = await signIn();
    await user.click(await screen.findByRole('button', { name: 'Resumen ejecutivo' }));
    const bars = screen.getByRole('list', { name: es.report.summary.bySeverity });
    const rows = within(bars).getAllByRole('listitem');
    expect(rows).toHaveLength(5);
    const counts = rows.map((row) => within(row).getByText(/^\d+$/).textContent);
    expect(counts).toEqual(['0', '2', '0', '1', '0']);
    expect(bars.querySelector('.pfill.medium')).toHaveClass('w0');
    expect(bars.querySelector('.pfill.high')).toHaveClass('w65');
  });

  it('keeps the editor open with the draft when the server rejects the save', async () => {
    renderReport(BASELINE, {
      [`/api/v1/analyses/${ANALYSIS_ID}/report/sections`]: {
        status: 422,
        body: { code: 'report_section_too_long', message_key: 'errors.report.sectionTooLong' },
      },
    });
    const user = await signIn();
    await user.click(await screen.findByRole('button', { name: es.report.edit.start }));
    const text = screen.getByLabelText(es.report.edit.textLabel);
    await user.clear(text);
    await user.type(text, 'Borrador que no debe perderse.');
    await user.type(screen.getByLabelText(es.report.edit.changeLabel), 'Cambio de prueba largo.');
    await user.click(screen.getByRole('button', { name: fill(es.report.edit.save, { number: 2 }) }));

    expect(await screen.findByRole('alert')).toHaveTextContent(es.errors.report.sectionTooLong);
    expect(screen.getByLabelText(es.report.edit.textLabel)).toHaveValue(
      'Borrador que no debe perderse.',
    );
  });

  it('saves an edited section as the next version', async () => {
    const calls = renderReport(BASELINE, {
      [`/api/v1/analyses/${ANALYSIS_ID}/report/sections`]: { status: 200, body: VERSION_TWO },
    });
    const user = await signIn();

    await user.click(await screen.findByRole('button', { name: es.report.edit.start }));
    const text = screen.getByLabelText(es.report.edit.textLabel);
    await user.clear(text);
    await user.type(text, 'Texto nuevo.');
    const save = screen.getByRole('button', { name: fill(es.report.edit.save, { number: 2 }) });
    expect(save).toBeDisabled();
    await user.type(screen.getByLabelText(es.report.edit.changeLabel), 'Se reescribió la introducción.');
    expect(save).toBeEnabled();
    await user.click(save);

    await waitFor(() => {
      expect(bodyOf(calls, `/api/v1/analyses/${ANALYSIS_ID}/report/sections`, 'PUT')).toEqual({
        sections: { introduction: 'Texto nuevo.' },
        change_summary: 'Se reescribió la introducción.',
      });
    });
    expect(await screen.findByText('Texto nuevo.')).toBeInTheDocument();
    expect(screen.getByText('Se reescribió la introducción.')).toBeInTheDocument();
    expect(screen.getAllByText(es.report.versions.draft)).toHaveLength(2);
  });

  it('signs the current version with a reason and shows it locked', async () => {
    const signed = {
      ...VERSION_TWO,
      signed: true,
      versions: VERSION_TWO.versions.map((version) =>
        version.number === 2
          ? {
              ...version,
              signed_by_username: 'mmarin',
              signed_at: '2026-09-22T11:00:00Z',
              excluded_findings: [],
              content_hash: 'a'.repeat(64),
            }
          : version,
      ),
    };
    const calls = renderReport(VERSION_TWO, {
      [`/api/v1/analyses/${ANALYSIS_ID}/report/versions/2/sign`]: { status: 200, body: signed },
    });
    const user = await signIn();

    const submit = await screen.findByRole('button', {
      name: fill(es.report.sign.submit, { number: 2 }),
    });
    expect(submit).toBeDisabled();
    await user.type(screen.getByLabelText(es.report.sign.label), 'Revisado con el equipo.');
    await user.click(submit);

    await waitFor(() => {
      expect(
        bodyOf(calls, `/api/v1/analyses/${ANALYSIS_ID}/report/versions/2/sign`, 'POST'),
      ).toEqual({ justification: 'Revisado con el equipo.' });
    });
    expect(
      await screen.findByText(fill(es.report.nextStep.signedTitle, { number: 2 })),
    ).toBeInTheDocument();
    expect(screen.getByText(es.report.sign.locked)).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: fill(es.report.sign.submit, { number: 2 }) }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(es.report.versions.signedBadge)).toBeInTheDocument();
  });
});
