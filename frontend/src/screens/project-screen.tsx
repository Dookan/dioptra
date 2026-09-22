/**
 * One project: stage E2 ingest, the analyses it produced, the report downloads
 * and the doors to triage (E3) and the report editor (E8). Mockup anchors:
 * screen 03 "2 · El código" and the `.steps` / `.nextstep` blocks of screens
 * 04–09.
 */
import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError } from '../api/client';
import * as api from '../api/projects';
import type { Analysis, Project, ReportFormat, Severity } from '../api/projects';
import { useAuth } from '../auth/auth-context';
import { AdvanceStage } from '../components/advance-stage';
import { AppShell } from '../components/app-shell';
import { stageIndex } from '../components/stages';
import { SeverityBadge, StatusBadge, ToolBadge } from '../components/status-badge';
import { Stepper } from '../components/stepper';
import type { Route } from '../navigation/use-route';

const POLL_MS = 3000;
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const FORMATS: ReportFormat[] = ['pdf', 'docx', 'md'];

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
  const [errorKey, setErrorKey] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(action: () => Promise<Analysis>): Promise<void> {
    if (accessToken === null) return;
    setErrorKey(null);
    setBusy(true);
    try {
      const analysis = await action();
      setFile(null);
      setUrl('');
      if (fileRef.current) fileRef.current.value = '';
      onQueued(analysis);
    } catch (error) {
      setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
    } finally {
      setBusy(false);
    }
  }

  function handleZip(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (file === null || accessToken === null) return;
    void submit(() => api.ingestZip(accessToken, projectId, file));
  }

  function handleGit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (url.trim() === '' || accessToken === null) return;
    void submit(() => api.ingestGit(accessToken, projectId, url.trim()));
  }

  return (
    <section className="panel">
      <h5>{t('project.ingest.section')}</h5>
      <p className="desc">{t('project.ingest.intro')}</p>
      {errorKey !== null && (
        <p className="alert" role="alert">
          {t(errorKey)}
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
  const ready = analysis.status === 'done';

  async function fetchAndSave(action: () => Promise<api.Download>): Promise<void> {
    setErrorKey(null);
    try {
      api.saveDownload(await action());
    } catch (error) {
      setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
    }
  }

  return (
    <div className="actions wrap">
      {FORMATS.map((format) => (
        <button
          key={format}
          type="button"
          className={format === 'pdf' ? 'btn primary' : 'btn'}
          disabled={!ready || accessToken === null}
          onClick={() => {
            if (accessToken !== null) {
              void fetchAndSave(() => api.downloadReport(accessToken, analysis.id, format));
            }
          }}
        >
          {t(`project.download.${format}`)}
        </button>
      ))}
      <button
        type="button"
        className="btn"
        disabled={!ready || accessToken === null}
        onClick={() => {
          if (accessToken !== null) {
            void fetchAndSave(() => api.downloadSbom(accessToken, analysis.id));
          }
        }}
      >
        {t('project.download.sbom')}
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
      {analysis.status === 'failed' && (
        <p className="alert" role="alert">
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
  const { accessToken } = useAuth();
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
              <b>{t(`project.nextStep.${stageKey(stage)}Title`)}</b>
              <div>{t(`project.nextStep.${stageKey(stage)}Body`)}</div>
            </div>
          </section>
          <div className="cols side">
            <IngestCard
              projectId={project.id}
              onQueued={(analysis) => {
                setAnalyses((current) => [analysis, ...current]);
              }}
            />
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
