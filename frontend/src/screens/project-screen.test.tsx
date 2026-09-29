/** One project: ingest errors in plain language, downloads only when done. */
import es from '../locales/es.json';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { App } from '../app';
import { AuthProvider } from '../auth/auth-provider';
import { NO_SESSION, stubFetch, type Routes } from '../test/http';

type Role = 'analyst' | 'admin' | 'developer';

function session(role: Role = 'analyst') {
  const username = role === 'developer' ? 'cperez' : role === 'admin' ? 'amedina' : 'mmarin';
  return {
    status: 200,
    body: {
      access_token: 'an-access-token',
      token_type: 'bearer',
      expires_in: 900,
      user: {
        id: '0f9b2a5e-0000-4000-8000-000000000001',
        username,
        display_name: role === 'developer' ? 'Carla Perez' : 'Moises Marin',
        role,
        must_change_password: false,
      },
    },
  };
}


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
    stage: status === 'done' ? 'analysis' : 'code',
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

function renderProject(routes: Routes, role: Role = 'analyst') {
  globalThis.location.hash = `#/projects/${PROJECT.id}`;
  const calls = stubFetch({
    '/api/v1/auth/refresh': NO_SESSION,
    '/api/v1/auth/login': session(role),
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

/** What the page's live regions currently say (the sentences a reader hears). */
function liveTexts(): string[] {
  return screen.queryAllByRole('status').map((node) => node.textContent ?? '');
}

async function signIn(username = 'mmarin') {
  const user = userEvent.setup();
  await user.type(await screen.findByLabelText(es.login.username), username);
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

  it('never offers the upload to a developer, nor tells them to do it', async () => {
    // E1–E2 is the analyst's (docs/roles-and-permissions.md). The server
    // refuses a developer; the screen must not offer what the server denies.
    renderProject({ [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [] } }, 'developer');
    await signIn('cperez');

    expect(await screen.findByText(es.project.ingest.waiting)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.project.ingest.uploadSubmit })).toBeNull();
    expect(screen.queryByRole('button', { name: es.project.ingest.gitSubmit })).toBeNull();
    expect(screen.queryByLabelText(es.project.ingest.zipLabel)).toBeNull();
    expect(screen.queryByLabelText(es.project.ingest.gitLabel)).toBeNull();
    // The banner says what they are waiting for, never "sube el código".
    expect(screen.getByText(es.project.nextStep.codeDeveloperTitle)).toBeInTheDocument();
    expect(screen.queryByText(es.project.nextStep.codeTitle)).toBeNull();
    // The section heading stays, so the developer still knows where they are.
    expect(screen.getByText(es.project.ingest.section)).toBeInTheDocument();
  });

  it('keeps the upload for the admin', async () => {
    renderProject({ [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [] } }, 'admin');
    await signIn('amedina');

    expect(await screen.findByRole('button', { name: es.project.ingest.uploadSubmit })).toBeInTheDocument();
    expect(screen.getByText(es.project.nextStep.codeTitle)).toBeInTheDocument();
    expect(screen.queryByText(es.project.ingest.waiting)).toBeNull();
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

  it('sends the ZIP as the raw body, named in the query, and shows it moving', async () => {
    let answer: (response: { status: number; body: unknown }) => void = () => undefined;
    const calls = renderProject({
      [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [] },
      [`/api/v1/projects/${PROJECT.id}/ingest`]: () =>
        new Promise((resolve) => {
          answer = resolve;
        }),
    });
    const user = await signIn();

    const input = await screen.findByLabelText(es.project.ingest.zipLabel);
    const zip = new File(['PK-some-bytes'], 'código fuente.zip', { type: 'application/zip' });
    await user.upload(input, zip);
    // The live region exists, empty, BEFORE the upload has anything to say.
    const region = screen
      .getAllByRole('status')
      .find((node) => node.classList.contains('srlive') && node.textContent === '');
    expect(region).toBeDefined();
    await user.click(screen.getByRole('button', { name: es.project.ingest.uploadSubmit }));
    await waitFor(() => {
      expect(region?.textContent).toBe(es.project.ingest.received);
    });

    // Every byte sent, the server not answered yet: the screen says so, and
    // the sentence reaches the live region that was mounted before it.
    await waitFor(() => {
      expect(liveTexts()).toContain(es.project.ingest.received);
    });
    // The fake XHR hands `calls` the request init as a second argument the
    // fetch signature does not declare.
    const call = (calls.mock.calls as unknown as [string, unknown][]).find(
      ([path]) => path === `/api/v1/projects/${PROJECT.id}/ingest`,
    );
    const init = call?.[1] as RequestInit & { url: string; headers: Record<string, string> };
    expect(init.method).toBe('POST');
    expect(init.body).toBe(zip);
    expect(init.headers['Content-Type']).toBe('application/zip');
    expect(init.headers.Authorization).toBe('Bearer an-access-token');
    expect(init.url).toContain(`?filename=${encodeURIComponent('código fuente.zip')}`);

    answer({ status: 202, body: analysis('queued') });
    await waitFor(() => {
      expect(screen.queryAllByText(es.project.ingest.received)).toHaveLength(0);
    });
  });

  it('shows the upload mid-way: the live sentence, the floored bar, hidden visuals', async () => {
    renderProject({ [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [] } });
    // An upload that reports 98 % and never answers: the in-between state the
    // default fake (which jumps straight to 100 %) never lets the screen show.
    class HeldXhr {
      readonly upload: { onprogress: ((event: ProgressEvent) => void) | null } = {
        onprogress: null,
      };
      onload = null;
      onerror = null;
      onabort = null;
      open(): void {}
      setRequestHeader(): void {}
      send(): void {
        this.upload.onprogress?.({ lengthComputable: true, loaded: 98, total: 100 } as ProgressEvent);
      }
    }
    const user = await signIn();
    vi.stubGlobal('XMLHttpRequest', HeldXhr);
    await user.upload(
      await screen.findByLabelText(es.project.ingest.zipLabel),
      new File(['PK'], 'big.zip', { type: 'application/zip' }),
    );
    await user.click(screen.getByRole('button', { name: es.project.ingest.uploadSubmit }));

    await waitFor(() => {
      expect(liveTexts()).toContain(es.project.ingest.uploading);
    });
    // 98 % floors to the 95 step: the bar never reads "done" before the text.
    expect(document.querySelector('.panel .progress .pfill')).toHaveClass('w95');
    const visible = screen
      .getAllByText(es.project.ingest.uploading)
      .find((node) => node.getAttribute('role') !== 'status');
    expect(visible?.closest('[aria-hidden="true"]')).not.toBeNull();
    expect(screen.getByText('98 %').closest('[aria-hidden="true"]')).not.toBeNull();
  });

  it('fills the analysis bar with the steps DONE, not the one running', async () => {
    const running = {
      ...analysis('queued'),
      status: 'running',
      started_at: null,
      progress: { step: 'semgrep', index: 2, total: 8 },
    };
    renderProject({
      [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [running] },
    });
    await signIn();
    await waitFor(() => {
      expect(document.querySelector('.card .progress .pfill')).toHaveClass('w15');
    });
  });

  describe('cancelling an analysis (phase 12)', () => {
    const ME = '0f9b2a5e-0000-4000-8000-000000000001';

    it('cancels at the creator\'s one confirmation, no reason, and reads as no error', async () => {
      const queued = { ...analysis('queued'), created_by_id: ME, cancel_requested: false };
      const cancelled = { ...queued, status: 'cancelled', finished_at: '2026-09-28T20:00:00Z' };
      const calls = renderProject({
        [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [queued] },
        '/api/v1/analyses/a-1/cancel': { status: 202, body: cancelled },
      });
      const user = await signIn();

      await user.click(await screen.findByRole('button', { name: es.analysis.cancel.button }));
      const dialog = screen.getByRole('dialog', { name: es.analysis.cancel.title });
      expect(dialog).toHaveTextContent(es.analysis.cancel.body);
      expect(dialog.querySelector('textarea, input')).toBeNull(); // no reason, no second step
      await user.click(within(dialog).getByRole('button', { name: es.analysis.cancel.confirm }));

      expect(await screen.findByText(es.analysis.status.cancelled)).toBeInTheDocument();
      const post = calls.mock.calls.find(([path]) => String(path).endsWith('/a-1/cancel'));
      expect(post?.[1]?.method).toBe('POST');
      expect(post?.[1]?.body).toBeUndefined();
      expect(screen.queryByRole('alert')).toBeNull();
      // Announced by the card's region, which stayed mounted; the visible copy
      // is for the eye; focus lands on the card, never on <body>.
      await waitFor(() => {
        expect(liveTexts().some((text) => text.startsWith('Se canceló este análisis el'))).toBe(
          true,
        );
      });
      const visible = screen
        .getAllByText(/Se canceló este análisis el/)
        .find((node) => node.getAttribute('role') !== 'status');
      expect(visible).toHaveClass('sub');
      expect(visible).toHaveAttribute('aria-hidden', 'true');
      expect(document.activeElement).toBe(document.querySelector('.card .row.first'));
      expect(screen.queryByRole('button', { name: es.analysis.cancel.button })).toBeNull();
    });

    it('offers the button on a running analysis and shows the request', async () => {
      const running = {
        ...analysis('queued'),
        status: 'running',
        created_by_id: ME,
        cancel_requested: false,
        progress: { step: 'semgrep', index: 2, total: 8 },
      };
      renderProject({
        [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [running] },
        '/api/v1/analyses/a-1/cancel': {
          status: 202,
          body: { ...running, cancel_requested: true },
        },
      });
      const user = await signIn();
      await user.click(await screen.findByRole('button', { name: es.analysis.cancel.button }));
      const dialog = screen.getByRole('dialog', { name: es.analysis.cancel.title });
      await user.click(within(dialog).getByRole('button', { name: es.analysis.cancel.confirm }));
      await waitFor(() => {
        expect(liveTexts()).toContain(es.analysis.cancel.requested);
      });
    });

    it('says why the server refused, as an error, and keeps the analysis', async () => {
      const queued = { ...analysis('queued'), created_by_id: ME, cancel_requested: false };
      renderProject({
        [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [queued] },
        '/api/v1/analyses/a-1/cancel': {
          status: 409,
          body: { code: 'analysis_not_cancellable', message_key: 'errors.analysis.notCancellable' },
        },
      });
      const user = await signIn();
      await user.click(await screen.findByRole('button', { name: es.analysis.cancel.button }));
      const dialog = screen.getByRole('dialog', { name: es.analysis.cancel.title });
      await user.click(within(dialog).getByRole('button', { name: es.analysis.cancel.confirm }));
      expect(await screen.findByRole('alert')).toHaveTextContent(
        es.errors.analysis.notCancellable,
      );
      expect(screen.getByText(es.analysis.status.queued)).toBeInTheDocument();
    });

    it('sends one request however often it is confirmed while in flight', async () => {
      const queued = { ...analysis('queued'), created_by_id: ME, cancel_requested: false };
      let answer: (value: { status: number; body: unknown }) => void = () => {};
      const pending = new Promise<{ status: number; body: unknown }>((resolve) => {
        answer = resolve;
      });
      const calls = renderProject({
        [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [queued] },
        '/api/v1/analyses/a-1/cancel': () => pending,
      });
      const user = await signIn();
      for (let round = 0; round < 2; round += 1) {
        await user.click(await screen.findByRole('button', { name: es.analysis.cancel.button }));
        const dialog = screen.getByRole('dialog', { name: es.analysis.cancel.title });
        await user.click(within(dialog).getByRole('button', { name: es.analysis.cancel.confirm }));
      }
      const posts = calls.mock.calls.filter(([path]) => String(path).endsWith('/a-1/cancel'));
      expect(posts).toHaveLength(1);
      answer({ status: 202, body: { ...queued, status: 'cancelled' } });
      expect(await screen.findByText(es.analysis.status.cancelled)).toBeInTheDocument();
    });

    it('going back cancels nothing', async () => {
      const queued = { ...analysis('queued'), created_by_id: ME, cancel_requested: false };
      const calls = renderProject({
        [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [queued] },
      });
      const user = await signIn();
      await user.click(await screen.findByRole('button', { name: es.analysis.cancel.button }));
      const dialog = screen.getByRole('dialog', { name: es.analysis.cancel.title });
      await user.click(within(dialog).getByRole('button', { name: es.analysis.cancel.back }));
      expect(calls.mock.calls.some(([path]) => String(path).endsWith('/cancel'))).toBe(false);
    });

    it('says the running tool is stopping while the worker answers', async () => {
      const stopping = {
        ...analysis('queued'),
        status: 'running',
        created_by_id: ME,
        cancel_requested: true,
        progress: { step: 'semgrep', index: 2, total: 8 },
      };
      renderProject({
        [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [stopping] },
      });
      await signIn();
      await waitFor(() => {
        expect(liveTexts()).toContain(es.analysis.cancel.requested);
      });
      const visible = screen
        .getAllByText(es.analysis.cancel.requested)
        .find((node) => node.getAttribute('role') !== 'status');
      expect(visible?.closest('[aria-hidden="true"]')).not.toBeNull();
    });

    it.each([
      ['another analyst', 'analyst' as Role, 'someone-else', false],
      ['a developer, even the creator', 'developer' as Role, ME, false],
      ['an admin', 'admin' as Role, 'someone-else', true],
    ])('offers the button to %s: %s', async (_who, role, creator, offered) => {
      const queued = { ...analysis('queued'), created_by_id: creator, cancel_requested: false };
      renderProject(
        { [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [queued] } },
        role,
      );
      await signIn(role === 'developer' ? 'cperez' : role === 'admin' ? 'amedina' : 'mmarin');
      await screen.findByText(es.analysis.status.queued);
      expect(screen.queryByRole('button', { name: es.analysis.cancel.button }) !== null).toBe(
        offered,
      );
    });

    it('never offers it once the analysis finished', async () => {
      const done = { ...analysis('done'), created_by_id: ME, cancel_requested: false };
      renderProject({ [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [done] } });
      await signIn();
      await screen.findByText(es.analysis.status.done);
      expect(screen.queryByRole('button', { name: es.analysis.cancel.button })).toBeNull();
    });
  });

  it('mounts the card live region while the analysis is still queued', async () => {
    renderProject({
      [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [analysis('queued')] },
    });
    await signIn();
    await waitFor(() => {
      expect(document.querySelectorAll('.card .srlive[role="status"]')).toHaveLength(1);
    });
    expect(document.querySelector('.card .srlive')?.textContent).toBe('');
  });

  it.each([
    ['zip_slip_detected', es.errors.ingest.zipSlip],
    ['zip_too_large', es.errors.ingest.zipTooLarge],
    ['zip_too_many_entries', es.errors.ingest.tooManyEntries],
    ['zip_bomb', es.errors.ingest.zipBomb],
    ['invalid_archive', es.errors.ingest.invalidArchive],
    ['upload_missing', es.errors.ingest.uploadMissing],
    ['repo_unreachable', es.errors.ingest.repoUnreachable],
    ['no_tool_ran', es.errors.analysis.noToolRan],
    ['analysis_abandoned', es.errors.analysis.abandoned],
    ['analysis_enqueue_failed', es.errors.ingest.enqueueFailed],
  ])('explains the worker failure %s in plain words', async (code, sentence) => {
    const failed = { ...analysis('queued'), status: 'failed', failure_code: code };
    renderProject({
      [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [failed] },
    });
    await signIn();
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(sentence);
    expect(alert).toHaveTextContent(code);
  });

  it('words the coverage details the server stores as machine text (1.5.1)', async () => {
    const run = (tool: string, category: string, status: string, detail: string) => ({
      tool,
      category,
      status,
      detail,
      duration_ms: 10,
    });
    const done = {
      ...analysis('done'),
      tool_runs: [
        run('semgrep', 'sast', 'ran', 'partial: 96 files; syntax=90 memory=6 timeout=0 other=0'),
        run('lizard', 'metrics', 'failed', 'output too large: 300 MiB > 256 MiB'),
        run('cloc', 'metrics', 'failed', 'output truncated and not parsed'),
        run('gitleaks', 'secret', 'failed', 'exit 2: boom'),
        run('osv-scanner', 'sca', 'ran', 'partial: 2 files; syntax=1 memory=0 timeout=0 other=1 and more'),
      ],
    };
    renderProject({ [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [done] } });
    await signIn();
    const partial = es.analysis.toolDetail.partial_other
      .replace('{{count}}', '96')
      .replace('{{syntax}}', '90')
      .replace('{{memory}}', '6')
      .replace('{{timeout}}', '0')
      .replace('{{other}}', '0');
    expect(await screen.findByText(partial)).toBeTruthy();
    const tooLarge = es.analysis.toolDetail.tooLarge
      .replace('{{size}}', '300')
      .replace('{{cap}}', '256');
    expect(screen.getByText(tooLarge)).toBeTruthy();
    expect(screen.getByText(es.analysis.toolDetail.truncated)).toBeTruthy();
    // A tool's own message is not one of ours: shown as it came.
    expect(screen.getByText('exit 2: boom')).toBeTruthy();
    expect(
      screen.getByText('partial: 2 files; syntax=1 memory=0 timeout=0 other=1 and more'),
    ).toBeTruthy();
  });

  it('names the limit when the upload is too large', async () => {
    renderProject({
      [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [] },
      [`/api/v1/projects/${PROJECT.id}/ingest`]: {
        status: 413,
        body: {
          code: 'zip_too_large',
          message_key: 'errors.ingest.uploadTooLarge',
          context: { limit_mib: '1024' },
        },
      },
    });
    const user = await signIn();
    await user.upload(
      await screen.findByLabelText(es.project.ingest.zipLabel),
      new File(['PK'], 'big.zip', { type: 'application/zip' }),
    );
    await user.click(screen.getByRole('button', { name: es.project.ingest.uploadSubmit }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      es.errors.ingest.uploadTooLarge.replace('{{limit_mib}}', '1024'),
    );
  });

  it('reads a proxy 413 with no JSON as too large, not as an internal error', async () => {
    renderProject({
      [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [] },
      [`/api/v1/projects/${PROJECT.id}/ingest`]: { status: 413 },
    });
    const user = await signIn();
    await user.upload(
      await screen.findByLabelText(es.project.ingest.zipLabel),
      new File(['PK'], 'big.zip', { type: 'application/zip' }),
    );
    await user.click(screen.getByRole('button', { name: es.project.ingest.uploadSubmit }));

    expect(await screen.findByRole('alert')).toHaveTextContent(es.errors.ingest.zipTooLarge);
  });

  it('explains in plain words an archive the worker refused', async () => {
    const failed = { ...analysis('queued'), status: 'failed', failure_code: 'zip_bomb' };
    renderProject({
      [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [failed] },
    });
    await signIn();

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(es.errors.ingest.zipBomb);
    expect(alert).toHaveTextContent('zip_bomb');
  });

  it('names the step a running analysis is on, with its place and its clock', async () => {
    const running = {
      ...analysis('queued'),
      status: 'running',
      started_at: new Date(Date.now() - 125_000).toISOString(),
      progress: { step: 'semgrep', index: 2, total: 8 },
    };
    renderProject({
      [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [running] },
    });
    await signIn();

    const sentence = es.analysis.progress.label
      .replace('{{index}}', '2')
      .replace('{{total}}', '8')
      .replace('{{step}}', es.analysis.progress.step.semgrep);
    await waitFor(() => {
      expect(liveTexts()).toContain(sentence);
    });
    // Shown too, but the visible copy and the clock are never announced: the
    // clock changes every second.
    const visible = screen.getAllByText(sentence).find((node) => node.getAttribute('role') !== 'status');
    expect(visible?.closest('[aria-hidden="true"]')).not.toBeNull();
    const clockText = await screen.findByText(/^Lleva 2:0[5-9]$/);
    expect(clockText.closest('[aria-hidden="true"]')).not.toBeNull();
  });

  it('says which acquisition runs: unpacking a ZIP, cloning a repository', async () => {
    const cloning = {
      ...analysis('queued'),
      source_kind: 'git',
      status: 'running',
      started_at: null,
      progress: { step: 'acquire', index: 1, total: 8 },
    };
    renderProject({
      [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [cloning] },
    });
    await signIn();

    const cloningSentence = es.analysis.progress.label
      .replace('{{index}}', '1')
      .replace('{{total}}', '8')
      .replace('{{step}}', es.analysis.progress.step.acquire.git);
    await waitFor(() => {
      expect(liveTexts()).toContain(cloningSentence);
    });
    expect(screen.queryByText(/^Lleva /)).toBeNull();
  });

  it('shows only the count for a step it has no words for', async () => {
    const future = {
      ...analysis('queued'),
      status: 'running',
      progress: { step: 'trivy', index: 5, total: 9 },
    };
    renderProject({
      [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [future] },
    });
    await signIn();

    await waitFor(() => {
      expect(liveTexts()).toContain('Paso 5 de 9');
    });
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

  it('says it is working and refuses a second click while a synchronous download runs', async () => {
    // The PDF is a worker job since phase 8 (report-jobs/*.test.tsx); DOCX,
    // Markdown and the SBOM are still fetched in the request, and a slow link
    // must not read as a frozen screen or invite a second click.
    renderProject({
      [`/api/v1/projects/${PROJECT.id}/analyses`]: { status: 200, body: [analysis('done')] },
    });
    const user = await signIn();

    const docx = await screen.findByRole('button', { name: es.project.download.docx });
    await waitFor(() => {
      expect(docx).toBeEnabled();
    });

    // Hold the report request open; everything else keeps its stub.
    let release: (() => void) | undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const stubbed = globalThis.fetch;
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).includes('/report?format=')) {
        return held.then(() => new Response('PK', { status: 200 }));
      }
      return (stubbed as typeof globalThis.fetch)(input, init);
    });

    await user.click(docx);

    const working = await screen.findByRole('button', { name: es.project.download.working });
    expect(working).toBeDisabled();
    expect(screen.getByRole('button', { name: es.project.download.sbom })).toBeDisabled();

    release?.();
    await waitFor(() => {
      expect(screen.getByRole('button', { name: es.project.download.docx })).toBeEnabled();
    });
  });
});
