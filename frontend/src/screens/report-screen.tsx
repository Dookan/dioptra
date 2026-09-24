/**
 * Stage E8: the versioned report editor. Mockup anchor: screen 09 "Reporte
 * (E8)" — the sections list with their state on the left (with the export
 * buttons and the version line underneath), the preview of one section on
 * the right with "✎ Editar esta sección".
 *
 * Every save is a snapshot the server numbers; signing locks the current one.
 * Section text is plain paragraphs and is rendered here as text nodes only.
 */
import { useEffect, useId, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError } from '../api/client';
import * as api from '../api/projects';
import type { Analysis, Project, ReportFormat, ReportState, Severity } from '../api/projects';
import { PdfExportButton } from '../report-jobs/pdf-export-button';
import { useAuth } from '../auth/auth-context';
import { AppShell } from '../components/app-shell';
import { stageIndex } from '../components/stages';
import { SeverityBadge } from '../components/status-badge';
import { Stepper } from '../components/stepper';
import { widthClass } from '../components/width-class';
import type { Route } from '../navigation/use-route';

// The PDF is a worker job (phase 8, PdfExportButton); these three are sub-second.
const FORMATS: ReportFormat[] = ['docx', 'md'];
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
/** Mirrors backend/app/workflow/triage.py::MIN_JUSTIFICATION_CHARS — the server is the gate. */
const MIN_JUSTIFICATION = 10;

interface Props {
  route: Extract<Route, { kind: 'report' }>;
  onNavigate: (route: Route) => void;
}

function paragraphs(text: string): string[] {
  return text
    .split(/\n\s*\n/)
    .map((part) => part.trim())
    .filter((part) => part !== '');
}

function SeverityBars({ analysis }: { analysis: Analysis }): React.ReactNode {
  const { t } = useTranslation();
  // The preview must show what the PDF prints: report_counts leaves false positives out.
  const total = SEVERITIES.reduce((sum, level) => sum + (analysis.report_counts[level] ?? 0), 0);
  if (total === 0) return null;
  return (
    <ul className="bars" aria-label={t('report.summary.bySeverity')}>
      {SEVERITIES.map((level) => {
        const count = analysis.report_counts[level] ?? 0;
        return (
          <li key={level} className="barrow">
            <SeverityBadge severity={level} />
            <span className="mono">{count}</span>
            <span className="pbar">
              <span className={`pfill ${level} ${widthClass(count, total)}`} />
            </span>
          </li>
        );
      })}
    </ul>
  );
}

function VersionsTable({ state }: { state: ReportState }): React.ReactNode {
  const { t, i18n } = useTranslation();
  if (state.versions.length === 0) return <p className="hint">{t('report.versions.none')}</p>;
  const format = (iso: string | null): string =>
    iso === null
      ? '—'
      : new Date(iso).toLocaleString(i18n.resolvedLanguage, {
          dateStyle: 'medium',
          timeStyle: 'short',
        });
  return (
    <table className="table">
      <thead>
        <tr>
          <th scope="col">{t('report.versions.number')}</th>
          <th scope="col">{t('report.versions.areas')}</th>
          <th scope="col">{t('report.versions.change')}</th>
          <th scope="col">{t('report.versions.by')}</th>
          <th scope="col">{t('report.versions.signed')}</th>
        </tr>
      </thead>
      <tbody>
        {state.versions.map((version) => (
          <tr key={version.number}>
            <td className="mono">{version.number}</td>
            <td>{version.areas}</td>
            <td>{version.change_summary}</td>
            <td>
              <span className="mono">{version.created_by_username}</span> ·{' '}
              {format(version.created_at)}
            </td>
            <td>
              {version.signed_at === null ? (
                <span className="badge warn">{t('report.versions.draft')}</span>
              ) : (
                <>
                  <span className="badge ok">{t('report.versions.signedBadge')}</span>{' '}
                  <span className="mono">{version.signed_by_username}</span> ·{' '}
                  {format(version.signed_at)}
                </>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function ReportScreen({ route, onNavigate }: Props): React.ReactNode {
  const { t } = useTranslation();
  const { accessToken, user } = useAuth();
  const ids = { text: useId(), change: useId(), sign: useId() };
  const [project, setProject] = useState<Project | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [state, setState] = useState<ReportState | null>(null);
  const [selectedKey, setSelectedKey] = useState<string>('introduction');
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState('');
  const [changeSummary, setChangeSummary] = useState('');
  const [signReason, setSignReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [errorKey, setErrorKey] = useState<string | null>(null);

  useEffect(() => {
    if (accessToken === null) return;
    let cancelled = false;
    Promise.all([
      api.getProject(accessToken, route.id),
      api.getAnalysis(accessToken, route.analysisId),
      api.getReportState(accessToken, route.analysisId),
    ])
      .then(([loadedProject, loadedAnalysis, loadedState]) => {
        if (cancelled) return;
        setProject(loadedProject);
        setAnalysis(loadedAnalysis);
        setState(loadedState);
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
        }
      });
    return () => {
      cancelled = true;
    };
  }, [accessToken, route.id, route.analysisId]);

  const canEdit = user?.role === 'analyst';
  const section = state?.sections.find((item) => item.key === selectedKey) ?? null;

  /** Runs a mutation; resolves true when the server accepted it. */
  async function run(action: () => Promise<ReportState>): Promise<boolean> {
    setBusy(true);
    setErrorKey(null);
    try {
      setState(await action());
      return true;
    } catch (error) {
      setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
      return false;
    } finally {
      setBusy(false);
    }
  }

  function startEditing(): void {
    if (section === null) return;
    setDraft(section.text);
    setChangeSummary('');
    setEditing(true);
  }

  function handleSave(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (accessToken === null || section === null) return;
    const summary = changeSummary.trim();
    if (summary.length < MIN_JUSTIFICATION) return;
    void run(() =>
      api.saveReportSections(accessToken, route.analysisId, { [section.key]: draft }, summary),
    ).then((saved) => {
      if (saved) setEditing(false);
    });
  }

  function handleSign(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (accessToken === null || state === null) return;
    const reason = signReason.trim();
    if (reason.length < MIN_JUSTIFICATION) return;
    void run(() => api.signReportVersion(accessToken, route.analysisId, state.number, reason)).then(
      (signed) => {
        if (signed) setSignReason('');
      },
    );
  }

  async function download(format: ReportFormat): Promise<void> {
    if (accessToken === null) return;
    setErrorKey(null);
    try {
      api.saveDownload(await api.downloadReport(accessToken, route.analysisId, format));
    } catch (error) {
      setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
    }
  }

  const triageDone = analysis?.triage.complete ?? false;

  return (
    <AppShell route={route} onNavigate={onNavigate} context={project?.name} stage={analysis?.stage}>
      {analysis !== null && <Stepper current={stageIndex(analysis.stage)} />}
      {errorKey !== null && (
        <p className="alert" role="alert">
          {t(errorKey)}
        </p>
      )}
      {analysis !== null && state !== null && (
        <>
          <div className="pagehead">
            <h2>{t('report.title')}</h2>
            <p className="sub">{t('report.subtitle', { number: state.number })}</p>
          </div>
          <section className="nextstep">
            <div className="txt">
              <b>
                {state.signed
                  ? t('report.nextStep.signedTitle', { number: state.number })
                  : triageDone
                    ? t('report.nextStep.readyTitle')
                    : t('report.nextStep.triageTitle', { count: analysis.triage.pending })}
              </b>
              <div>
                {state.signed
                  ? t('report.nextStep.signedBody')
                  : triageDone
                    ? t('report.nextStep.readyBody')
                    : t('report.nextStep.triageBody')}
              </div>
            </div>
            {!triageDone && (
              <button
                type="button"
                className="btn"
                onClick={() => {
                  onNavigate({ kind: 'findings', id: route.id, analysisId: route.analysisId });
                }}
              >
                {t('report.nextStep.goToFindings')}
              </button>
            )}
          </section>
          <div className="cols narrow">
            <aside className="panel">
              <h4>{t('report.sections')}</h4>
              <ul className="checklist" aria-label={t('report.sections')}>
                {state.sections.map((item) => {
                  const active = item.key === selectedKey;
                  return (
                    <li key={item.key} className="checkline">
                      <span
                        className={active && editing ? 'ck now' : item.edited ? 'ck done' : 'ck'}
                        aria-hidden="true"
                      >
                        {active && editing ? '✎' : item.edited ? '✓' : '·'}
                      </span>
                      <button
                        type="button"
                        className={active ? 'linkish on' : 'linkish'}
                        aria-current={active ? 'true' : undefined}
                        onClick={() => {
                          setSelectedKey(item.key);
                          setEditing(false);
                        }}
                      >
                        {item.label}
                      </button>
                      {active && editing && (
                        <span className="hint">— {t('report.editing')}</span>
                      )}
                    </li>
                  );
                })}
              </ul>
              <div className="actions wrap">
                <PdfExportButton
                  analysisId={route.analysisId}
                  label={t('report.export.pdf')}
                  className="btn primary"
                  disabled={accessToken === null}
                />
                {FORMATS.map((format) => (
                  <button
                    key={format}
                    type="button"
                    className="btn ghost"
                    disabled={accessToken === null}
                    onClick={() => {
                      void download(format);
                    }}
                  >
                    {t(`report.export.${format}`)}
                  </button>
                ))}
              </div>
              <p className="hint">
                {state.persisted
                  ? t('report.versionLine', {
                      number: state.number,
                      user: state.versions[state.versions.length - 1]?.created_by_username ?? '',
                    })
                  : t('report.versionLineBaseline')}
              </p>
              {canEdit && !state.signed && (
                <form onSubmit={handleSign} noValidate>
                  <div className="field">
                    <label htmlFor={ids.sign}>{t('report.sign.label')}</label>
                    <textarea
                      id={ids.sign}
                      className="input textarea"
                      rows={2}
                      value={signReason}
                      placeholder={t('report.sign.placeholder')}
                      onChange={(event) => {
                        setSignReason(event.target.value);
                      }}
                    />
                  </div>
                  <div className="actions">
                    <button
                      type="submit"
                      className="btn"
                      disabled={busy || signReason.trim().length < MIN_JUSTIFICATION}
                    >
                      {t('report.sign.submit', { number: state.number })}
                    </button>
                  </div>
                  <p className="hint">{t('report.sign.hint')}</p>
                </form>
              )}
              {state.signed && <p className="hint">{t('report.sign.locked')}</p>}
            </aside>
            <section className="panel">
              {section !== null && (
                <>
                  <h4>
                    {t('report.preview')} · {section.label}
                  </h4>
                  {editing ? (
                    <form onSubmit={handleSave} noValidate>
                      <div className="field">
                        <label htmlFor={ids.text}>{t('report.edit.textLabel')}</label>
                        <textarea
                          id={ids.text}
                          className="input textarea tall"
                          value={draft}
                          onChange={(event) => {
                            setDraft(event.target.value);
                          }}
                        />
                        <span className="hint">{t('report.edit.textHint')}</span>
                      </div>
                      <div className="field">
                        <label htmlFor={ids.change}>{t('report.edit.changeLabel')}</label>
                        <input
                          id={ids.change}
                          className="input"
                          value={changeSummary}
                          placeholder={t('report.edit.changePlaceholder')}
                          onChange={(event) => {
                            setChangeSummary(event.target.value);
                          }}
                        />
                      </div>
                      <div className="actions wrap">
                        <button
                          type="submit"
                          className="btn primary"
                          disabled={busy || changeSummary.trim().length < MIN_JUSTIFICATION}
                        >
                          {t('report.edit.save', { number: state.number + 1 })}
                        </button>
                        <button
                          type="button"
                          className="btn ghost"
                          onClick={() => {
                            setEditing(false);
                          }}
                        >
                          {t('report.edit.cancel')}
                        </button>
                        <button
                          type="button"
                          className="btn ghost"
                          onClick={() => {
                            setDraft('');
                          }}
                        >
                          {t('report.edit.restore')}
                        </button>
                      </div>
                    </form>
                  ) : (
                    <>
                      <div className="repout">
                        <div className="rtitle">
                          {t('report.previewTitle', { system: project?.system?.name ?? '' })}
                        </div>
                        <div className="rline" />
                        <b>{section.label}</b>
                        {paragraphs(section.text).map((paragraph, index) => (
                          <p key={`${String(index)}-${paragraph.slice(0, 24)}`}>{paragraph}</p>
                        ))}
                        {section.key === 'summary' && <SeverityBars analysis={analysis} />}
                      </div>
                      {canEdit && (
                        <div className="actions">
                          <button type="button" className="btn ghost" onClick={startEditing}>
                            {t('report.edit.start')}
                          </button>
                          {section.edited && <span className="hint">{t('report.editedHint')}</span>}
                        </div>
                      )}
                    </>
                  )}
                </>
              )}
            </section>
          </div>
          <section>
            <h5 className="section">{t('report.versions.title')}</h5>
            <VersionsTable state={state} />
          </section>
        </>
      )}
    </AppShell>
  );
}
