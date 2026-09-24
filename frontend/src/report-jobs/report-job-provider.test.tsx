/**
 * Phase 8: the PDF is a worker job the person follows from a toast.
 *
 * Driven through the real App and the project screen, because what matters is
 * the whole path: the dialog gates the start, the toast tells the truth about
 * the queue, the button says why it is disabled, a reload recovers the job.
 */
import es from '../locales/es.json';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App } from '../app';
import { AuthProvider } from '../auth/auth-provider';
import { NO_SESSION, stubFetch, type Routes, type StubResponse } from '../test/http';
import { POLL_MS, READY_CLOSE_MS } from './report-job-provider';

const PROJECT = {
  id: '22222222-2222-4222-8222-222222222222',
  name: 'sistema-demo',
  description: null,
  created_at: '2026-09-21T12:00:00Z',
  system: {
    name: 'sistema-demo',
    framework: null,
    database: null,
    developer: null,
    installed_at: null,
  },
};

const ANALYSIS = {
  id: 'a-1',
  project_id: PROJECT.id,
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
  finding_counts: {},
  report_counts: {},
  triage: {
    total: 0,
    confirmed: 0,
    false_positive: 0,
    pending: 0,
    complete: true,
  },
  tool_runs: [],
};

const SESSION: StubResponse = {
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

const START = '/api/v1/analyses/a-1/report/jobs';
const POLL = '/api/v1/report-jobs/j-1';
const DOWNLOAD = '/api/v1/report-jobs/j-1/download';

function job(status: string, extra: Record<string, unknown> = {}) {
  return {
    id: 'j-1',
    analysis_id: 'a-1',
    version: null,
    format: 'pdf',
    status,
    requested_by_username: 'mmarin',
    created_at: '2026-09-23T12:00:00Z',
    started_at: null,
    finished_at: null,
    byte_size: null,
    detail: null,
    ahead: 0,
    elapsed_seconds: 0,
    ...extra,
  };
}

/** Answers in order, repeating the last one. */
function sequence(...answers: StubResponse[]): () => StubResponse {
  let index = 0;
  return () => {
    const answer = answers[Math.min(index, answers.length - 1)];
    index += 1;
    if (answer === undefined) throw new Error('empty sequence');
    return answer;
  };
}

function renderApp(routes: Routes) {
  globalThis.location.hash = `#/projects/${PROJECT.id}`;
  const calls = stubFetch({
    '/api/v1/auth/refresh': NO_SESSION,
    '/api/v1/auth/login': SESSION,
    [`/api/v1/projects/${PROJECT.id}`]: { status: 200, body: PROJECT },
    [`/api/v1/projects/${PROJECT.id}/analyses`]: {
      status: 200,
      body: [ANALYSIS],
    },
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
  const user = userEvent.setup({
    advanceTimers: vi.advanceTimersByTime.bind(vi),
  });
  await user.type(await screen.findByLabelText(es.login.username), 'mmarin');
  await user.type(screen.getByLabelText(es.login.password), 'correct-horse-battery-staple');
  await user.click(screen.getByRole('button', { name: es.login.submit }));
  return user;
}

function requested(calls: ReturnType<typeof stubFetch>, path: string): number {
  return calls.mock.calls.filter(([input]) => String(input) === path).length;
}

function toast(): HTMLElement {
  return screen.getByRole('status', { name: es.reportJob.toast.label });
}

async function tick(ms: number): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

describe('asynchronous PDF export', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('asks first, and cancelling starts nothing', async () => {
    const calls = renderApp({ [START]: { status: 202, body: job('queued') } });
    const user = await signIn();
    const pdf = await screen.findByRole('button', {
      name: es.project.download.pdf,
    });
    await waitFor(() => {
      expect(pdf).toBeEnabled();
    });

    await user.click(pdf);
    const dialog = screen.getByRole('dialog', {
      name: es.reportJob.dialog.title,
    });
    // The load-bearing sentences are the dialog's description, read on open.
    expect(dialog).toHaveAccessibleDescription(
      `${es.reportJob.dialog.body} ${es.reportJob.dialog.oneAtATime}`,
    );
    await user.click(within(dialog).getByRole('button', { name: es.reportJob.dialog.cancel }));

    expect(screen.queryByRole('dialog')).toBeNull();
    expect(requested(calls, START)).toBe(0);
    expect(toast()).toBeEmptyDOMElement();
  });

  it('follows the job from the queue to the download, then closes itself', async () => {
    const calls = renderApp({
      [START]: { status: 202, body: job('queued', { ahead: 2 }) },
      [POLL]: sequence(
        { status: 200, body: job('running', { elapsed_seconds: 65 }) },
        { status: 200, body: job('done', { byte_size: 1234 }) },
      ),
      [DOWNLOAD]: { status: 200, body: '%PDF' },
    });
    const user = await signIn();
    const pdf = await screen.findByRole('button', {
      name: es.project.download.pdf,
    });
    await waitFor(() => {
      expect(pdf).toBeEnabled();
    });
    await user.click(pdf);
    await user.click(screen.getByRole('button', { name: es.reportJob.dialog.confirm }));

    // Queued is said as queued — nothing claims work that is not happening.
    await waitFor(() => {
      expect(toast()).toHaveTextContent(es.reportJob.toast.queuedTitle);
    });
    expect(toast()).toHaveTextContent('Hay 2 reportes antes que el tuyo.');
    // Confirming disabled the button the dialog returns focus to: focus goes
    // to the sentence that says why, never to <body>.
    await waitFor(() => {
      expect(screen.getByText(es.reportJob.blocked)).toHaveFocus();
    });
    // The button is disabled AND says why, beside itself.
    expect(screen.getByRole('button', { name: es.project.download.pdf })).toBeDisabled();
    expect(screen.getByText(es.reportJob.blocked)).toBeInTheDocument();
    // Not dismissible while it blocks the next PDF.
    expect(screen.queryByRole('button', { name: es.reportJob.toast.dismiss })).toBeNull();

    await tick(POLL_MS);
    await waitFor(() => {
      expect(toast()).toHaveTextContent(es.reportJob.toast.runningTitle);
    });
    // Shown, but outside the live region: it is not re-announced every poll.
    const clock = screen.getByText('Lleva 1:05.');
    expect(clock).toHaveAttribute('aria-hidden', 'true');
    expect(toast()).not.toHaveTextContent('Lleva');
    expect(screen.queryByRole('button', { name: es.reportJob.toast.dismiss })).toBeNull();

    await tick(POLL_MS);
    await waitFor(() => {
      expect(toast()).toHaveTextContent(es.reportJob.toast.readyBody);
    });
    expect(requested(calls, DOWNLOAD)).toBe(1);
    expect(screen.getByRole('button', { name: es.project.download.pdf })).toBeEnabled();

    await tick(READY_CLOSE_MS);
    await waitFor(() => {
      expect(toast()).toBeEmptyDOMElement();
    });
    // Downloaded exactly once, and polling stopped with the job.
    expect(requested(calls, DOWNLOAD)).toBe(1);
    expect(requested(calls, POLL)).toBe(2);
  });

  it('a refusal follows the job that is actually in flight', async () => {
    renderApp({
      [START]: {
        status: 409,
        body: {
          code: 'report_job_in_flight',
          message_key: 'errors.report.jobInFlight',
          context: { job: 'j-1' },
        },
      },
      [POLL]: { status: 200, body: job('running', { elapsed_seconds: 3 }) },
    });
    const user = await signIn();
    const pdf = await screen.findByRole('button', {
      name: es.project.download.pdf,
    });
    await waitFor(() => {
      expect(pdf).toBeEnabled();
    });
    await user.click(pdf);
    await user.click(screen.getByRole('button', { name: es.reportJob.dialog.confirm }));

    await waitFor(() => {
      expect(toast()).toHaveTextContent(es.reportJob.toast.runningTitle);
    });
    expect(toast()).toHaveTextContent(es.errors.report.jobInFlight);
  });

  it('a reload recovers the job in flight without a click', async () => {
    renderApp({
      '/api/v1/report-jobs/mine': {
        status: 200,
        body: job('running', { elapsed_seconds: 12 }),
      },
      [POLL]: { status: 200, body: job('running', { elapsed_seconds: 14 }) },
    });
    await signIn();

    await waitFor(() => {
      expect(toast()).toHaveTextContent(es.reportJob.toast.runningTitle);
    });
    expect(await screen.findByRole('button', { name: es.project.download.pdf })).toBeDisabled();
  });

  it('a failure says why in plain words and can be closed', async () => {
    renderApp({
      [START]: { status: 202, body: job('queued') },
      [POLL]: { status: 200, body: job('errored', { detail: 'spool_full' }) },
    });
    const user = await signIn();
    const pdf = await screen.findByRole('button', {
      name: es.project.download.pdf,
    });
    await waitFor(() => {
      expect(pdf).toBeEnabled();
    });
    await user.click(pdf);
    await user.click(screen.getByRole('button', { name: es.reportJob.dialog.confirm }));
    await tick(POLL_MS);

    await waitFor(() => {
      expect(toast()).toHaveTextContent(es.reportJob.reason.spool_full);
    });
    expect(screen.getByRole('button', { name: es.project.download.pdf })).toBeEnabled();
    await user.click(screen.getByRole('button', { name: es.reportJob.toast.dismiss }));
    expect(toast()).toBeEmptyDOMElement();
  });

  it('an unknown failure code still reads as a sentence', async () => {
    renderApp({
      [START]: { status: 202, body: job('queued') },
      [POLL]: { status: 200, body: job('errored', { detail: 'weird' }) },
    });
    const user = await signIn();
    const pdf = await screen.findByRole('button', {
      name: es.project.download.pdf,
    });
    await waitFor(() => {
      expect(pdf).toBeEnabled();
    });
    await user.click(pdf);
    await user.click(screen.getByRole('button', { name: es.reportJob.dialog.confirm }));
    await tick(POLL_MS);
    await waitFor(() => {
      expect(toast()).toHaveTextContent(es.reportJob.reason.unknown);
    });
  });

  async function confirmPdf(user: ReturnType<typeof userEvent.setup>): Promise<void> {
    const pdf = await screen.findByRole('button', {
      name: es.project.download.pdf,
    });
    await waitFor(() => {
      expect(pdf).toBeEnabled();
    });
    await user.click(pdf);
    await user.click(screen.getByRole('button', { name: es.reportJob.dialog.confirm }));
  }

  it('says it is next when nothing is ahead', async () => {
    renderApp({
      [START]: { status: 202, body: job('queued', { ahead: 0 }) },
      [POLL]: { status: 200, body: job('queued') },
    });
    await confirmPdf(await signIn());
    await waitFor(() => {
      expect(toast()).toHaveTextContent(es.reportJob.toast.queuedNext);
    });
  });

  it('a reload delivers a PDF that finished while the tab was closed', async () => {
    const calls = renderApp({
      '/api/v1/report-jobs/mine': {
        status: 200,
        body: job('done', { byte_size: 10 }),
      },
      [DOWNLOAD]: { status: 200, body: '%PDF' },
    });
    await signIn();
    await waitFor(() => {
      expect(toast()).toHaveTextContent(es.reportJob.toast.readyBody);
    });
    expect(requested(calls, DOWNLOAD)).toBe(1);
  });

  it('a refusal sentence clears once the job it pointed at is delivered', async () => {
    renderApp({
      [START]: {
        status: 409,
        body: {
          code: 'report_job_in_flight',
          message_key: 'errors.report.jobInFlight',
          context: { job: 'j-1' },
        },
      },
      [POLL]: sequence({ status: 200, body: job('running') }, { status: 200, body: job('done') }),
      [DOWNLOAD]: { status: 200, body: '%PDF' },
    });
    await confirmPdf(await signIn());
    await waitFor(() => {
      expect(toast()).toHaveTextContent(es.errors.report.jobInFlight);
    });
    await tick(POLL_MS);
    await waitFor(() => {
      expect(toast()).toHaveTextContent(es.reportJob.toast.readyBody);
    });
    expect(toast()).not.toHaveTextContent(es.errors.report.jobInFlight);
  });

  it('answers the click at once, before the server does', async () => {
    // With the queue inline the POST lasts the whole render; on a slow link it
    // is never instant. The toast and the disabled button must not wait for it.
    renderApp({ [POLL]: { status: 200, body: job('running') } });
    const user = await signIn();
    let release: (() => void) | undefined;
    const answered = new Promise<void>((resolve) => {
      release = resolve;
    });
    const stubbed = globalThis.fetch;
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === START) {
        return answered.then(
          () =>
            new Response(JSON.stringify(job('queued')), {
              status: 202,
              headers: { 'Content-Type': 'application/json' },
            }),
        );
      }
      return (stubbed as typeof globalThis.fetch)(input, init);
    });

    await confirmPdf(user);
    expect(toast()).toHaveTextContent(es.reportJob.toast.startingTitle);
    // A request in flight is not a failure: never the error colour.
    expect(screen.getByText(es.reportJob.toast.startingTitle)).not.toHaveClass('bad');
    expect(screen.getByRole('button', { name: es.project.download.pdf })).toBeDisabled();
    expect(screen.getByText(es.reportJob.blocked)).toBeInTheDocument();

    release?.();
    await waitFor(() => {
      expect(toast()).toHaveTextContent(es.reportJob.toast.queuedTitle);
    });
    expect(toast()).not.toHaveTextContent(es.reportJob.toast.startingTitle);
  });

  it('a new request replaces what an earlier failure left on the toast', async () => {
    renderApp({
      [START]: sequence(
        { status: 202, body: job('queued') },
        { status: 202, body: job('queued', { id: 'j-2' }) },
      ),
      [POLL]: { status: 200, body: job('errored', { detail: 'render_failed' }) },
    });
    const user = await signIn();
    await confirmPdf(user);
    await tick(POLL_MS);
    await waitFor(() => {
      expect(toast()).toHaveTextContent(es.reportJob.reason.render_failed);
    });
    expect(screen.getByText(es.reportJob.toast.erroredTitle)).toHaveClass('bad');

    let release: (() => void) | undefined;
    const answered = new Promise<void>((resolve) => {
      release = resolve;
    });
    const stubbed = globalThis.fetch;
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) =>
      String(input) === START
        ? answered.then(() => (stubbed as typeof globalThis.fetch)(input, init))
        : (stubbed as typeof globalThis.fetch)(input, init),
    );
    await confirmPdf(user);
    // The old failure is gone the instant the person asks again.
    expect(toast()).toHaveTextContent(es.reportJob.toast.startingTitle);
    expect(toast()).not.toHaveTextContent(es.reportJob.reason.render_failed);
    release?.();
  });

  it('a refusal with no job to follow is painted as a failure', async () => {
    renderApp({
      [START]: {
        status: 503,
        body: { code: 'report_enqueue_failed', message_key: 'errors.report.enqueueFailed' },
      },
    });
    await confirmPdf(await signIn());
    await waitFor(() => {
      expect(toast()).toHaveTextContent(es.errors.report.enqueueFailed);
    });
    expect(screen.getByText(es.reportJob.toast.erroredTitle)).toHaveClass('bad');
    // It can be closed, and the PDF can be asked for again.
    expect(screen.getByRole('button', { name: es.reportJob.toast.dismiss })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: es.project.download.pdf })).toBeEnabled();
  });
});
