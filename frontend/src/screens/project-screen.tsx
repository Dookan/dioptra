/**
 * One project: stage E2 ingest, the analyses it produced, the report downloads
 * and the doors to triage (E3) and the report editor (E8). Mockup anchors:
 * screen 03 "2 · El código" and the `.steps` / `.nextstep` blocks of screens
 * 04–09.
 */
import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';

import { ApiError } from '../api/client';
import * as api from '../api/projects';
import type { Analysis, Project, ReportFormat, Severity } from '../api/projects';
import { PdfExportButton } from '../report-jobs/pdf-export-button';
import { useAuth } from '../auth/auth-context';
import { AdvanceStage } from '../components/advance-stage';
import { AppShell } from '../components/app-shell';
import { stageIndex } from '../components/stages';
import { SeverityBadge, StatusBadge, ToolBadge } from '../components/status-badge';
import { Stepper } from '../components/stepper';
import { widthClass } from '../components/width-class';
import { clock } from '../components/clock';
import type { Route } from '../navigation/use-route';

const POLL_MS = 3000;
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
// The PDF is a worker job (phase 8, PdfExportButton); these three are sub-second.
const FORMATS: ReportFormat[] = ['docx', 'md'];

interface Props {
  route: Route;
  projectId: string;
  onNavigate: (route: Route) => void;
}

/** Banner copy per stage index: code (E2), triage (E3), plan (E4) or later. */
function stageKey(stage: number): 'code' | 'triage' | 'plan' | 'later' {
  if (stage <= 1) return 'code';
  if (stage === 2) return 'triage';
  if (stage === 3) return 'plan';
  return 'later';
}

/**
 * The plain-words reason for a failure code the WORKER records. Since phase 10
 * the ZIP is extracted there, so a hostile or oversized archive is refused on
 * the analysis row rather than in the upload's response — the same sentence
 * the upload used to show, then the code. Unknown codes show only the code.
 */
const FAILURE_KEYS: Readonly<Record<string, string>> = {
  zip_slip_detected: 'errors.ingest.zipSlip',
  zip_too_large: 'errors.ingest.zipTooLarge',
  zip_too_many_entries: 'errors.ingest.tooManyEntries',
  zip_bomb: 'errors.ingest.zipBomb',
  invalid_archive: 'errors.ingest.invalidArchive',
  upload_missing: 'errors.ingest.uploadMissing',
  repo_unreachable: 'errors.ingest.repoUnreachable',
  no_tool_ran: 'errors.analysis.noToolRan',
  analysis_enqueue_failed: 'errors.ingest.enqueueFailed',
};

function failureKey(code: string | null): string | null {
  return code === null ? null : (FAILURE_KEYS[code] ?? null);
}

/** Steps the screen has words for; any other name shows only the count. */
const PROGRESS_STEPS = new Set([
  'acquire',
  'semgrep',
  'gitleaks',
  'osv-scanner',
  'syft',
  'lizard',
  'cloc',
  'normalize',
]);

/** The sentence naming a running analysis' step, or '' when it is not running. */
function progressSentence(t: TFunction, analysis: Analysis): string {
  const progress = analysis.progress;
  if (analysis.status !== 'running' || progress === null) return '';
  if (!PROGRESS_STEPS.has(progress.step)) {
    return t('analysis.progress.count', { index: progress.index, total: progress.total });
  }
  const stepKey =
    progress.step === 'acquire' ? `acquire.${analysis.source_kind}` : progress.step;
  return t('analysis.progress.label', {
    index: progress.index,
    total: progress.total,
    step: t(`analysis.progress.step.${stepKey}`),
  });
}

/**
 * The running analysis, step by step (phase 10). The bar counts steps done;
 * the sentence names the step and the clock says how long it has run,
 * because the steps are nothing like equal (Semgrep was 6 of 8 minutes on a
 * real 593 MiB system) and a bar alone would look frozen. Everything here is
 * `aria-hidden`: the card's own always-mounted live region announces the
 * sentence (`AnalysisCard`), and the clock, which ticks every second, is
 * never announced.
 */
function AnalysisProgressBar({ analysis }: { analysis: Analysis }): React.ReactNode {
  const { t } = useTranslation();
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => {
      clearInterval(timer);
    };
  }, []);
  const progress = analysis.progress;
  if (progress === null) return null;
  const started = analysis.started_at === null ? null : Date.parse(analysis.started_at);
  return (
    <div className="progress wide" aria-hidden="true">
      <div className="plabel">
        <span>{progressSentence(t, analysis)}</span>
        {started !== null && (
          <span className="clock">
            {t('analysis.progress.elapsed', { time: clock((now - started) / 1000) })}
          </span>
        )}
      </div>
      <div className="pbar">
        <div className={`pfill ${widthClass(progress.index - 1, progress.total)}`} />
      </div>
    </div>
  );
}

function stageFor(analyses: Analysis[]): number {
  // The project's stage is the stage of its latest analysis (survey §5);
  // before any analysis exists only Registro is done.
  const latest = analyses[0];
  return latest === undefined ? 1 : stageIndex(latest.stage);
}

function IngestCard({
  projectId,
  onQueued,
}: {
  projectId: string;
  onQueued: (analysis: Analysis) => void;
}): React.ReactNode {
  const { t } = useTranslation();
  const { accessToken } = useAuth();
  const fileId = useId();
  const urlId = useId();
  const fileRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [url, setUrl] = useState('');
  const [error, setError] = useState<{ key: string; context: Record<string, string> } | null>(
    null,
  );
  const [busy, setBusy] = useState(false);
  // Bytes sent of the ZIP in flight (phase 10): a 1 GiB archive is minutes of
  // sending, and the screen must say it is moving.
  const [sent, setSent] = useState<{ loaded: number; total: number } | null>(null);

  async function submit(action: () => Promise<Analysis>): Promise<void> {
    if (accessToken === null) return;
    setError(null);
    setBusy(true);
    try {
      const analysis = await action();
      setFile(null);
      setUrl('');
      if (fileRef.current) fileRef.current.value = '';
      onQueued(analysis);
    } catch (caught) {
      setError(
        caught instanceof ApiError
          ? { key: caught.messageKey, context: caught.context }
          : { key: 'errors.internal', context: {} },
      );
    } finally {
      setBusy(false);
      setSent(null);
    }
  }

  function handleZip(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (file === null || accessToken === null) return;
    setSent({ loaded: 0, total: file.size });
    void submit(() =>
      api.ingestZip(accessToken, projectId, file, (loaded, total) => {
        setSent({ loaded, total });
      }),
    );
  }

  const percent =
    sent === null || sent.total <= 0 ? 0 : Math.min(100, Math.floor((100 * sent.loaded) / sent.total));
  const uploadSentence =
    sent === null
      ? ''
      : percent < 100
        ? t('project.ingest.uploading')
        : t('project.ingest.received');

  function handleGit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (url.trim() === '' || accessToken === null) return;
    void submit(() => api.ingestGit(accessToken, projectId, url.trim()));
  }

  return (
    <section className="panel">
      <h5>{t('project.ingest.section')}</h5>
      <p className="desc">{t('project.ingest.intro')}</p>
      {error !== null && (
        <p className="alert" role="alert">
          {t(error.key, error.context)}
        </p>
      )}
      <form onSubmit={handleZip} noValidate>
        <div className="field">
          <label htmlFor={fileId}>{t('project.ingest.zipLabel')}</label>
          <input
            id={fileId}
            ref={fileRef}
            className="input"
            type="file"
            accept=".zip,application/zip"
            onChange={(event) => {
              setFile(event.target.files?.[0] ?? null);
            }}
          />
        </div>
        <div className="actions">
          <button type="submit" className="btn primary" disabled={busy || file === null}>
            {t('project.ingest.uploadSubmit')}
          </button>
          <span className="hint">{t('project.ingest.duration')}</span>
        </div>
        {/* The live region is ALWAYS mounted and only its text changes: a
            region inserted together with its first sentence is the
            announcement screen readers drop (the phase-8 toast rule). The
            visible bar is aria-hidden, and so is the percentage, which
            changes many times a second. */}
        <span className="srlive" role="status">
          {uploadSentence}
        </span>
        {sent !== null && (
          <div className="progress wide" aria-hidden="true">
            <div className="plabel">
              <span>{uploadSentence}</span>
              {percent < 100 && <span>{t('project.ingest.percent', { percent })}</span>}
            </div>
            <div className="pbar">
              {/* Floored to the bar's 5-point steps, like the number beside it:
                  the bar must never read "done" while the text says 97 %. */}
              <div className={`pfill ${widthClass(percent - (percent % 5), 100)}`} />
            </div>
          </div>
        )}
      </form>
      <form onSubmit={handleGit} noValidate>
        <div className="field">
          <label htmlFor={urlId}>{t('project.ingest.gitLabel')}</label>
          <input
            id={urlId}
            className="input"
            type="url"
            inputMode="url"
            placeholder="https://"
            value={url}
            onChange={(event) => {
              setUrl(event.target.value);
            }}
          />
        </div>
        <div className="actions">
          <button type="submit" className="btn" disabled={busy || url.trim() === ''}>
            {t('project.ingest.gitSubmit')}
          </button>
        </div>
      </form>
      <p className="hint">{t('project.ingest.privacy')}</p>
    </section>
  );
}

function Downloads({ analysis }: { analysis: Analysis }): React.ReactNode {
  const { t } = useTranslation();
  const { accessToken } = useAuth();
  const [errorKey, setErrorKey] = useState<string | null>(null);
  // Which synchronous download is in flight, or null. The PDF is not one of
  // them since phase 8: it is a worker job with its own dialog and toast.
  const [busy, setBusy] = useState<ReportFormat | 'sbom' | null>(null);
  const ready = analysis.status === 'done';

  async function fetchAndSave(
    what: ReportFormat | 'sbom',
    action: () => Promise<api.Download>,
  ): Promise<void> {
    setErrorKey(null);
    setBusy(what);
    try {
      api.saveDownload(await action());
    } catch (error) {
      setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="actions wrap">
      <PdfExportButton
        analysisId={analysis.id}
        label={t('project.download.pdf')}
        className="btn primary"
        disabled={!ready || accessToken === null}
      />
      {FORMATS.map((format) => (
        <button
          key={format}
          type="button"
          className="btn"
          disabled={!ready || accessToken === null || busy !== null}
          onClick={() => {
            if (accessToken !== null) {
              void fetchAndSave(format, () =>
                api.downloadReport(accessToken, analysis.id, format),
              );
            }
          }}
        >
          {busy === format ? t('project.download.working') : t(`project.download.${format}`)}
        </button>
      ))}
      <button
        type="button"
        className="btn"
        disabled={!ready || accessToken === null || busy !== null}
        onClick={() => {
          if (accessToken !== null) {
            void fetchAndSave('sbom', () => api.downloadSbom(accessToken, analysis.id));
          }
        }}
      >
        {busy === 'sbom' ? t('project.download.working') : t('project.download.sbom')}
      </button>
      {errorKey !== null && (
        <span className="alert inline" role="alert">
          {t(errorKey)}
        </span>
      )}
    </div>
  );
}

function AnalysisCard({
  analysis,
  onNavigate,
  onChange,
}: {
  analysis: Analysis;
  onNavigate: (route: Route) => void;
  onChange: (analysis: Analysis) => void;
}): React.ReactNode {
  const { t, i18n } = useTranslation();
  const { user } = useAuth();
  const canStartReview = user?.role === 'analyst' || user?.role === 'admin';
  const languages = Object.entries(analysis.languages);
  const reason = failureKey(analysis.failure_code);
  const total = SEVERITIES.reduce((sum, level) => sum + (analysis.finding_counts[level] ?? 0), 0);
  const when = new Date(analysis.created_at).toLocaleString(i18n.resolvedLanguage, {
    dateStyle: 'medium',
    timeStyle: 'short',
  });

  return (
    <li className="card">
      <div className="row first">
        <StatusBadge status={analysis.status} />
        <span className="chip">{t(`stepper.${analysis.stage}`)}</span>
        <span className="mono">{analysis.source_ref}</span>
        <span className="sub">{when}</span>
      </div>
      {/* Mounted with the card, before the analysis runs, so the first step
          is announced too; the visible bar below is aria-hidden. */}
      <span className="srlive" role="status">
        {progressSentence(t, analysis)}
      </span>
      {analysis.status === 'running' && <AnalysisProgressBar analysis={analysis} />}
      {analysis.status === 'failed' && (
        <p className="alert" role="alert">
          {reason !== null && <>{t(reason)} </>}
          {t('analysis.failedBody')} <span className="mono">{analysis.failure_code ?? ''}</span>
        </p>
      )}
      {(languages.length > 0 || analysis.frameworks.length > 0) && (
        <div className="row">
          <span className="sub">{t('analysis.detected')}</span>
          {languages.map(([language, count]) => (
            <span key={language} className="chip">
              {language} · {count}
            </span>
          ))}
          {analysis.frameworks.map((framework) => (
            <span key={framework} className="chip">
              {framework}
            </span>
          ))}
        </div>
      )}
      {analysis.status === 'done' && (
        <div className="row">
          <span className="sub">{t('analysis.findingsCount', { count: total })}</span>
          {SEVERITIES.filter((level) => (analysis.finding_counts[level] ?? 0) > 0).map((level) => (
            <span key={level} className="row tight">
              <SeverityBadge severity={level} />
              <span className="mono">{analysis.finding_counts[level]}</span>
            </span>
          ))}
        </div>
      )}
      {analysis.tool_runs.length > 0 && (
        <ul className="toolruns" aria-label={t('analysis.coverage')}>
          {analysis.tool_runs.map((run) => (
            <li key={run.tool} className="row tight">
              <span className="mono">{run.tool}</span>
              <ToolBadge status={run.status} />
              {run.detail && <span className="sub">{run.detail}</span>}
            </li>
          ))}
        </ul>
      )}
      {analysis.status === 'done' && (
        <div className="row">
          <span className="sub">
            {analysis.triage.pending > 0
              ? t('project.triage.pending', { count: analysis.triage.pending })
              : t('project.triage.done')}
          </span>
        </div>
      )}
      <Downloads analysis={analysis} />
      {canStartReview && analysis.stage === 'code' && analysis.status === 'done' && (
        <div className="actions">
          <AdvanceStage
            analysis={analysis}
            label={t('project.stage.startReview')}
            ready
            onAdvanced={onChange}
          />
        </div>
      )}
      {analysis.status === 'done' && (
        <div className="actions wrap">
          <button
            type="button"
            className="btn"
            onClick={() => {
              onNavigate({ kind: 'findings', id: analysis.project_id, analysisId: analysis.id });
            }}
          >
            {t('project.findings.review')}
          </button>
          <button
            type="button"
            className="btn ghost"
            onClick={() => {
              onNavigate({ kind: 'report', id: analysis.project_id, analysisId: analysis.id });
            }}
          >
            {t('project.findings.editReport')}
          </button>
        </div>
      )}
    </li>
  );
}

export function ProjectScreen({ route, projectId, onNavigate }: Props): React.ReactNode {
  const { t } = useTranslation();
  const { accessToken, user } = useAuth();
  const [project, setProject] = useState<Project | null>(null);
  const [analyses, setAnalyses] = useState<Analysis[]>([]);
  const [errorKey, setErrorKey] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (accessToken === null) return;
    setAnalyses(await api.listAnalyses(accessToken, projectId));
  }, [accessToken, projectId]);

  useEffect(() => {
    if (accessToken === null) return;
    let cancelled = false;
    Promise.all([api.getProject(accessToken, projectId), api.listAnalyses(accessToken, projectId)])
      .then(([loaded, list]) => {
        if (cancelled) return;
        setProject(loaded);
        setAnalyses(list);
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
        }
      });
    return () => {
      cancelled = true;
    };
  }, [accessToken, projectId]);

  const pending = analyses.some((item) => item.status === 'queued' || item.status === 'running');
  useEffect(() => {
    if (!pending) return;
    const timer = setInterval(() => {
      void refresh().catch(() => undefined);
    }, POLL_MS);
    return () => {
      clearInterval(timer);
    };
  }, [pending, refresh]);

  const stage = stageFor(analyses);
  // Uploading code and starting an analysis is E1–E2: admin or analyst
  // (docs/roles-and-permissions.md). The server already refuses a developer;
  // the screen must not offer it, nor tell them to do it in the banner.
  const canIngest = user?.role === 'analyst' || user?.role === 'admin';
  const step = stageKey(stage);
  const stepKey = !canIngest && step === 'code' ? 'codeDeveloper' : step;

  return (
    <AppShell route={route} onNavigate={onNavigate} context={project?.name}>
      <Stepper current={stage} />
      {errorKey !== null && (
        <p className="alert" role="alert">
          {t(errorKey)}
        </p>
      )}
      {project !== null && (
        <>
          <div className="pagehead">
            <h2>{project.name}</h2>
            <p className="sub">{project.system?.name ?? ''}</p>
          </div>
          <section className="nextstep">
            <div className="txt">
              <b>{t(`project.nextStep.${stepKey}Title`)}</b>
              <div>{t(`project.nextStep.${stepKey}Body`)}</div>
            </div>
          </section>
          <div className="cols side">
            {canIngest ? (
              <IngestCard
                projectId={project.id}
                onQueued={(analysis) => {
                  setAnalyses((current) => [analysis, ...current]);
                }}
              />
            ) : (
              <section className="panel">
                <h5>{t('project.ingest.section')}</h5>
                <p className="desc">{t('project.ingest.waiting')}</p>
              </section>
            )}
            <aside className="panel">
              <h4>{t('project.explain.title')}</h4>
              <ul>
                <li>
                  <b>{t('project.explain.securityLabel')}</b> {t('project.explain.security')}
                </li>
                <li>
                  <b>{t('project.explain.depsLabel')}</b> {t('project.explain.deps')}
                </li>
                <li>
                  <b>{t('project.explain.secretsLabel')}</b> {t('project.explain.secrets')}
                </li>
                <li>
                  <b>{t('project.explain.healthLabel')}</b> {t('project.explain.health')}
                </li>
              </ul>
              <p className="hint">{t('project.ingest.privacy')}</p>
            </aside>
          </div>
          <section>
            <h5 className="section">{t('project.analyses.title')}</h5>
            {analyses.length === 0 ? (
              <p className="hint">{t('project.analyses.empty')}</p>
            ) : (
              <ul className="list" aria-label={t('project.analyses.title')}>
                {analyses.map((analysis) => (
                  <AnalysisCard
                    key={analysis.id}
                    analysis={analysis}
                    onNavigate={onNavigate}
                    onChange={(updated) => {
                      setAnalyses((current) =>
                        current.map((item) => (item.id === updated.id ? updated : item)),
                      );
                    }}
                  />
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </AppShell>
  );
}
