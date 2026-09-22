/** One project: ingest errors in plain language, downloads only when done. */
import es from '../locales/es.json';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { App } from '../app';
import { AuthProvider } from '../auth/auth-provider';
import { NO_SESSION, stubFetch, type Routes } from '../test/http';

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
  id: '22222222-2222-4222-8222-222222222222',
  name: 'sistema-demo',
  description: null,
  created_at: '2026-09-21T12:00:00Z',
  system: { name: 'sistema-demo', framework: null, database: null, developer: null, installed_at: null },
};

function analysis(status: 'queued' | 'done') {
  return {
    id: 'a-1',
    project_id: PROJECT.id,
    source_kind: 'zip',
    source_ref: 'src.zip',
    status,
    failure_code: null,
    languages: { JavaScript: 3 },
    frameworks: ['Express'],
    lockfiles: ['package-lock.json'],
    created_at: '2026-09-21T12:00:00Z',
    started_at: null,
    finished_at: null,
    finding_counts: { high: 2, medium: 1 },
    report_counts: { high: 2, medium: 1 },
    triage: { total: 3, confirmed: 0, false_positive: 0, pending: 3, complete: false },
    tool_runs: [
      { tool: 'semgrep', category: 'sast', status: 'ran', detail: null, duration_ms: 10 },
      { tool: 'osv-scanner', category: 'sca', status: 'missing', detail: 'no database', duration_ms: null },
    ],
  };
}

function renderProject(routes: Routes) {
  globalThis.location.hash = `#/projects/${PROJECT.id}`;
  const calls = stubFetch({
    '/api/v1/auth/refresh': NO_SESSION,
    '/api/v1/auth/login': SESSION,
    [`/api/v1/projects/${PROJECT.id}`]: { status: 200, body: PROJECT },
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

describe('project screen', () => {
  it('shows the stepper with stage names and the next-step banner', async () => {
    renderProject({ [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [] } });
    await signIn();

    expect(await screen.findByText(es.project.nextStep.codeTitle)).toBeInTheDocument();
    expect(screen.getByText(es.stepper.register)).toBeInTheDocument();
    expect(screen.getByText(es.stepper.verification)).toBeInTheDocument();
    expect(screen.queryByText(/E[1-8]\b/)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: es.project.ingest.uploadSubmit })).toBeDisabled();
  });

  it('translates an ingest rejection into plain language', async () => {
    renderProject({
      [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [] },
      [`/api/v1/projects/${PROJECT.id}/ingest`]: {
        status: 422,
        body: { code: 'zip_slip_detected', message_key: 'errors.ingest.zipSlip' },
      },
    });
    const user = await signIn();

    const input = await screen.findByLabelText(es.project.ingest.zipLabel);
    await user.upload(input, new File(['PK'], 'evil.zip', { type: 'application/zip' }));
    await user.click(screen.getByRole('button', { name: es.project.ingest.uploadSubmit }));

    expect(await screen.findByRole('alert')).toHaveTextContent(es.errors.ingest.zipSlip);
  });

  it('keeps the downloads disabled until the analysis is done', async () => {
    renderProject({
      [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [analysis('queued')] },
    });
    await signIn();

    expect(await screen.findByText(es.analysis.status.queued)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: es.project.download.pdf })).toBeDisabled();
    expect(screen.getByRole('button', { name: es.project.download.sbom })).toBeDisabled();
  });

  it('enables the downloads and shows coverage in plain words when done', async () => {
    renderProject({
      [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [analysis('done')] },
    });
    await signIn();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: es.project.download.pdf })).toBeEnabled();
    });
    expect(screen.getByText(es.analysis.tool.missing)).toBeInTheDocument();
    expect(screen.getByText('Express')).toBeInTheDocument();
    // The next step is the review, and the door to it is a button that says so.
    expect(screen.getByText(es.project.nextStep.triageTitle)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: es.project.findings.review })).toBeInTheDocument();
  });
});
