/**
 * Follows the person's PDF export across every screen (phase 8).
 *
 * The server renders the PDF in its worker; this provider starts the job,
 * polls it every two seconds, downloads the file when it is ready and shows
 * where things stand in a toast at the bottom right (`mmarin`, survey §7.5).
 *
 * The toast is NOT dismissible while the job is queued or running: it is the
 * only handle on a job that blocks the person's next PDF. It closes itself a
 * few seconds after the download starts, and a failure stays until closed.
 * It never says "preparing" while the job is only waiting in the queue — with
 * one worker, a queued job is not being worked on (survey §7.1).
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError } from '../api/client';
import { saveDownload } from '../api/projects';
import * as api from '../api/report-jobs';
import { useAuth } from '../auth/auth-context';
import { ReportJobContext, type ReportJobState } from './report-job-context';

export const POLL_MS = 2000;
export const READY_CLOSE_MS = 4000;

const KNOWN_REASONS = new Set([
  'render_failed',
  'spool_full',
  'abandoned',
  'enqueue_failed',
  'write_failed',
  'artefact_missing',
]);

function reasonKey(detail: string | null): string {
  return `reportJob.reason.${detail !== null && KNOWN_REASONS.has(detail) ? detail : 'unknown'}`;
}

function clock(seconds: number): string {
  const minutes = Math.floor(seconds / 60);
  return `${String(minutes)}:${String(seconds % 60).padStart(2, '0')}`;
}

function errorKeyOf(error: unknown): string {
  return error instanceof ApiError ? error.messageKey : 'errors.internal';
}

export function ReportJobProvider({ children }: { children: React.ReactNode }): React.ReactNode {
  const { t } = useTranslation();
  const { accessToken } = useAuth();
  const [job, setJob] = useState<api.ReportJob | null>(null);
  const [errorKey, setErrorKey] = useState<string | null>(null);
  // The id whose file was handed to the browser: the toast then says "listo"
  // and no longer blocks the next PDF.
  const [readyId, setReadyId] = useState<string | null>(null);
  const downloading = useRef<string | null>(null);
  // The request itself is in flight. Without this the screen said nothing
  // until the server answered — instant behind a real worker, but the whole
  // render with the queue inline, and never zero on a slow link (reported by
  // mmarin, 2026-09-23). Feedback starts at the click.
  const [starting, setStarting] = useState(false);

  // A reload, or a new login, recovers the job in flight — or the finished
  // one whose download never happened because the tab was closed.
  useEffect(() => {
    if (accessToken === null) return;
    let cancelled = false;
    api
      .getMyReportJob(accessToken)
      .then((mine) => {
        if (!cancelled && mine !== null) setJob((current) => current ?? mine);
      })
      .catch(() => {
        // Nothing to recover is the common case; a failure here must not
        // put an error in front of someone who never asked for a PDF.
      });
    return () => {
      cancelled = true;
    };
  }, [accessToken]);

  // Poll while the job is queued or running.
  useEffect(() => {
    if (accessToken === null || job === null) return;
    if (job.status !== 'queued' && job.status !== 'running') return;
    const timer = setTimeout(() => {
      api
        .getReportJob(accessToken, job.id)
        .then(setJob)
        .catch((error: unknown) => {
          setJob(null);
          setErrorKey(errorKeyOf(error));
        });
    }, POLL_MS);
    return () => {
      clearTimeout(timer);
    };
  }, [accessToken, job]);

  // Download once it is done, exactly once per job.
  useEffect(() => {
    if (accessToken === null || job?.status !== 'done') return;
    if (downloading.current === job.id) return;
    downloading.current = job.id;
    api
      .downloadReportJob(accessToken, job.id)
      .then((file) => {
        saveDownload(file);
        // A refusal shown while this job ran is settled by its success.
        setErrorKey(null);
        setReadyId(job.id);
      })
      .catch((error: unknown) => {
        setJob(null);
        setErrorKey(errorKeyOf(error));
      });
  }, [accessToken, job]);

  // "Listo" closes itself.
  useEffect(() => {
    if (readyId === null) return;
    const timer = setTimeout(() => {
      setJob((current) => (current?.id === readyId ? null : current));
      setReadyId(null);
    }, READY_CLOSE_MS);
    return () => {
      clearTimeout(timer);
    };
  }, [readyId]);

  // An expired job (downloaded elsewhere, or swept) has nothing to show.
  useEffect(() => {
    if (job?.status === 'expired') setJob(null);
  }, [job]);

  const start = useCallback(
    async (analysisId: string, version?: number): Promise<boolean> => {
      if (accessToken === null) return false;
      setErrorKey(null);
      setStarting(true);
      try {
        const created = await api.startReportJob(accessToken, analysisId, version);
        setReadyId(null);
        setJob(created);
        return true;
      } catch (error) {
        // Refused because one is already in flight: follow THAT one, so the
        // toast shows what is actually blocking the person.
        const inFlight =
          error instanceof ApiError && error.code === 'report_job_in_flight'
            ? error.context.job
            : undefined;
        if (inFlight !== undefined) {
          try {
            setJob(await api.getReportJob(accessToken, inFlight));
          } catch {
            // Fall through to the refusal itself.
          }
        }
        setErrorKey(errorKeyOf(error));
        return false;
      } finally {
        setStarting(false);
      }
    },
    [accessToken],
  );

  const dismiss = useCallback(() => {
    setErrorKey(null);
    setJob((current) =>
      current !== null && (current.status === 'queued' || current.status === 'running')
        ? current
        : null,
    );
  }, []);

  const busy =
    starting ||
    (job !== null &&
      (job.status === 'queued' ||
        job.status === 'running' ||
        (job.status === 'done' && readyId !== job.id)));

  const value = useMemo<ReportJobState>(
    () => ({ job, busy, errorKey, start, dismiss }),
    [job, busy, errorKey, start, dismiss],
  );

  let title: string | null = null;
  let body: string | null = null;
  // The elapsed time is shown but NOT announced: inside the live region it
  // would be re-read every poll for minutes (mockup-fidelity, phase-8 panel).
  let elapsed: string | null = null;
  let closable = false;
  // Only a failure is painted in the error colour, never a request in flight.
  let failed = false;
  // Whatever an earlier job left on the toast (an error, a "listo"), a new
  // request replaces it at once: `busy` keeps this from colliding with a job
  // still queued or running, since the button cannot be pressed then.
  if (starting) {
    title = t('reportJob.toast.startingTitle');
  } else if (job !== null && job.status === 'queued') {
    title = t('reportJob.toast.queuedTitle');
    body =
      job.ahead > 0
        ? t('reportJob.toast.queuedAhead', { count: job.ahead })
        : t('reportJob.toast.queuedNext');
  } else if (job !== null && job.status === 'running') {
    title = t('reportJob.toast.runningTitle');
    body = t('reportJob.toast.runningBody');
    elapsed = t('reportJob.toast.elapsed', { time: clock(job.elapsed_seconds) });
  } else if (job !== null && job.status === 'done') {
    title =
      readyId === job.id ? t('reportJob.toast.readyTitle') : t('reportJob.toast.downloadingTitle');
    body = readyId === job.id ? t('reportJob.toast.readyBody') : null;
  } else if (job !== null && job.status === 'errored') {
    title = t('reportJob.toast.erroredTitle');
    body = t(reasonKey(job.detail));
    closable = true;
    failed = true;
  } else if (errorKey !== null) {
    title = t('reportJob.toast.erroredTitle');
    body = t(errorKey);
    closable = true;
    failed = true;
  }
  // A refusal while a job is being followed adds its sentence under the job.
  const refusal = errorKey !== null && job !== null && job.status !== 'errored' ? errorKey : null;
  const visible = title !== null;

  return (
    <ReportJobContext.Provider value={value}>
      {children}
      {/* Only the status sentences are live, and the live region is never
          display:none — a node that enters the accessibility tree and gets its
          text in the same render is the announcement screen readers drop. */}
      <div className={visible ? 'jobtoast' : 'jobtoast empty'}>
        <div role="status" aria-label={t('reportJob.toast.label')}>
          {visible && (
            <>
              <b className={failed ? 'bad' : undefined}>{title}</b>
              {body !== null && <p className="sub">{body}</p>}
              {refusal !== null && <p className="sub">{t(refusal)}</p>}
            </>
          )}
        </div>
        {visible && elapsed !== null && (
          <p className="sub clock" aria-hidden="true">
            {elapsed}
          </p>
        )}
        {visible && closable && (
          <div className="actions">
            <button type="button" className="btn ghost" onClick={dismiss}>
              {t('reportJob.toast.dismiss')}
            </button>
          </div>
        )}
      </div>
    </ReportJobContext.Provider>
  );
}
