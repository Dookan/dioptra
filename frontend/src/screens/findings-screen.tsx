/**
 * Stage E3: findings viewer + triage. Mockup anchor: screen 04 "Hallazgos y
 * revisión (E3)" — list of cards on the left, one finding explained in plain
 * language on the right, two buttons that say what they do, and a "next step"
 * banner counting what is left.
 *
 * Every value that came out of the audited tree (title, path, snippet,
 * message) is rendered as a TEXT NODE only — never as markup.
 */
import { useEffect, useId, useMemo, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError } from '../api/client';
import * as api from '../api/projects';
import type { Analysis, Finding, Project, Severity, Verdict } from '../api/projects';
import { useAuth } from '../auth/auth-context';
import { AppShell } from '../components/app-shell';
import { SeverityBadge } from '../components/status-badge';
import { Stepper } from '../components/stepper';
import type { Route } from '../navigation/use-route';
import { widthClass } from '../components/width-class';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
/** Mirrors backend/app/workflow/triage.py::MIN_JUSTIFICATION_CHARS — the server is the gate. */
const MIN_JUSTIFICATION = 10;
const ALL = '';

interface Props {
  route: Extract<Route, { kind: 'findings' }>;
  onNavigate: (route: Route) => void;
}

interface Filters {
  severity: string;
  owasp: string;
  tool: string;
  file: string;
}

function unique(values: (string | null)[]): string[] {
  return [...new Set(values.filter((value): value is string => value !== null && value !== ''))];
}

function matches(finding: Finding, filters: Filters): boolean {
  if (filters.severity !== ALL && finding.severity !== filters.severity) return false;
  if (filters.owasp !== ALL && (finding.owasp ?? '') !== filters.owasp) return false;
  if (filters.tool !== ALL && !finding.tools.includes(filters.tool)) return false;
  return !(filters.file !== ALL && finding.path !== filters.file);
}

function VerdictBadge({ verdict }: { verdict: Verdict | null }): React.ReactNode {
  const { t } = useTranslation();
  if (verdict === null) return null;
  return (
    <span className={verdict === 'confirmed' ? 'badge ok' : 'badge info'}>
      {t(`findings.verdict.${verdict}`)}
    </span>
  );
}

function FilterSelect({
  id,
  label,
  value,
  options,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  options: { value: string; label: string }[];
  onChange: (value: string) => void;
}): React.ReactNode {
  const { t } = useTranslation();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <select
        id={id}
        className="input"
        value={value}
        onChange={(event) => {
          onChange(event.target.value);
        }}
      >
        <option value={ALL}>{t('findings.filters.all')}</option>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
}

function FindingDetail({
  finding,
  canTriage,
  onVerdict,
}: {
  finding: Finding;
  canTriage: boolean;
  onVerdict: (updated: Finding) => void;
}): React.ReactNode {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const justificationId = useId();
  const [justification, setJustification] = useState('');
  const [errorKey, setErrorKey] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Same rule as the server: whitespace collapses before the floor is measured.
  const trimmed = justification.split(/\s+/).filter(Boolean).join(' ');
  const tooShort = trimmed.length < MIN_JUSTIFICATION;

  async function submit(verdict: Verdict): Promise<void> {
    if (accessToken === null || tooShort) return;
    setBusy(true);
    setErrorKey(null);
    try {
      onVerdict(await api.postVerdict(accessToken, finding.id, verdict, trimmed));
      setJustification('');
    } catch (error) {
      setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
    } finally {
      setBusy(false);
    }
  }

  const classification = `${
    finding.cwe === null ? t('project.findings.unknownCwe') : `CWE-${String(finding.cwe)}`
  } · ${finding.owasp ?? t('project.findings.unclassified')}`;
  const verdictWhen =
    finding.verdict_at === null
      ? ''
      : new Date(finding.verdict_at).toLocaleString(i18n.resolvedLanguage, {
          dateStyle: 'medium',
          timeStyle: 'short',
        });

  return (
    <section className="panel" aria-live="polite">
      <div className="row first">
        <h4>{finding.title}</h4>
        <SeverityBadge severity={finding.severity} />
        <span className="chip">{classification}</span>
        <VerdictBadge verdict={finding.verdict} />
      </div>
      <div className="row tight">
        <span className="mono">
          {finding.path}
          {finding.line !== null && ` · ${t('findings.line', { line: finding.line })}`}
        </span>
        <span className="sub">{finding.tools.join(', ')}</span>
      </div>
      <h5>{t('findings.what')}</h5>
      <p className="desc">{finding.description}</p>
      {finding.message !== null && finding.message !== '' && (
        <p className="desc">{finding.message}</p>
      )}
      {finding.snippet !== null && finding.snippet !== '' && (
        <pre className="codeblock">{finding.snippet}</pre>
      )}
      <h5>{t('findings.why')}</h5>
      <p className="desc">{finding.impact}</p>
      <h5>{t('findings.how')}</h5>
      <ul>
        {finding.mitigation.map((step) => (
          <li key={step}>{step}</li>
        ))}
      </ul>
      {finding.verdict !== null && (
        <p className="hint">
          {t('findings.reviewedBy', {
            user: finding.verdict_by_username ?? '',
            when: verdictWhen,
          })}
          {' — '}
          {finding.verdict_justification}
        </p>
      )}
      {canTriage && (
        <form
          noValidate
          onSubmit={(event: FormEvent<HTMLFormElement>) => {
            // Enter in the textarea inserts a newline; the verdict is one of the two buttons.
            event.preventDefault();
          }}
        >
          <div className="field">
            <label htmlFor={justificationId}>{t('findings.justificationLabel')}</label>
            <textarea
              id={justificationId}
              className="input textarea"
              rows={3}
              value={justification}
              placeholder={t('findings.justificationPlaceholder')}
              onChange={(event) => {
                setJustification(event.target.value);
              }}
            />
            <span className="hint">{t('findings.justificationHint', { min: MIN_JUSTIFICATION })}</span>
          </div>
          {errorKey !== null && (
            <p className="alert" role="alert">
              {t(errorKey)}
            </p>
          )}
          <div className="actions wrap">
            <button
              type="button"
              className="btn primary"
              disabled={busy || tooShort}
              onClick={() => {
                void submit('confirmed');
              }}
            >
              {t('findings.confirm')}
            </button>
            <button
              type="button"
              className="btn ghost"
              disabled={busy || tooShort}
              onClick={() => {
                void submit('false_positive');
              }}
            >
              {t('findings.discard')}
            </button>
          </div>
        </form>
      )}
    </section>
  );
}

export function FindingsScreen({ route, onNavigate }: Props): React.ReactNode {
  const { t } = useTranslation();
  const { accessToken, user } = useAuth();
  const ids = { severity: useId(), owasp: useId(), tool: useId(), file: useId() };
  const [project, setProject] = useState<Project | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filters, setFilters] = useState<Filters>({ severity: ALL, owasp: ALL, tool: ALL, file: ALL });
  const [errorKey, setErrorKey] = useState<string | null>(null);

  useEffect(() => {
    if (accessToken === null) return;
    let cancelled = false;
    Promise.all([
      api.getProject(accessToken, route.id),
      api.getAnalysis(accessToken, route.analysisId),
      api.listFindings(accessToken, route.analysisId),
    ])
      .then(([loadedProject, loadedAnalysis, list]) => {
        if (cancelled) return;
        setProject(loadedProject);
        setAnalysis(loadedAnalysis);
        setFindings(list);
        setSelectedId(list[0]?.id ?? null);
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

  const visible = useMemo(
    () => (findings ?? []).filter((finding) => matches(finding, filters)),
    [findings, filters],
  );
  const selected = visible.find((finding) => finding.id === selectedId) ?? visible[0] ?? null;

  const total = findings?.length ?? 0;
  const reviewed = (findings ?? []).filter((finding) => finding.verdict !== null).length;
  const pending = total - reviewed;
  const canTriage = user?.role === 'analyst';

  function applyVerdict(updated: Finding): void {
    setFindings((current) =>
      current === null
        ? current
        : current.map((finding) => (finding.id === updated.id ? updated : finding)),
    );
  }

  const owaspOptions = unique((findings ?? []).map((finding) => finding.owasp)).sort();
  const toolOptions = unique((findings ?? []).flatMap((finding) => finding.tools)).sort();
  const fileOptions = unique((findings ?? []).map((finding) => finding.path)).sort();

  return (
    <AppShell route={route} onNavigate={onNavigate} context={project?.name}>
      <Stepper current={2} />
      {errorKey !== null && (
        <p className="alert" role="alert">
          {t(errorKey)}
        </p>
      )}
      {analysis !== null && findings !== null && (
        <>
          <div className="pagehead">
            <h2>{t('findings.title')}</h2>
            <p className="sub">
              <span className="mono">{analysis.source_ref}</span>
            </p>
          </div>
          <section className="nextstep">
            <div className="txt">
              <b>
                {pending > 0
                  ? t('findings.nextStep.pendingTitle', { count: pending })
                  : t('findings.nextStep.doneTitle')}
              </b>
              <div>
                {pending > 0
                  ? t('findings.nextStep.pendingBody')
                  : t('findings.nextStep.doneBody')}
              </div>
            </div>
            <div className="progress" aria-label={t('findings.progress', { reviewed, total })}>
              <div className="plabel">
                <span>{t('findings.progress', { reviewed, total })}</span>
              </div>
              <div className="pbar">
                <div className={`pfill ${widthClass(reviewed, total)}`} />
              </div>
            </div>
          </section>
          <div className="filters">
            <FilterSelect
              id={ids.severity}
              label={t('findings.filters.severity')}
              value={filters.severity}
              options={SEVERITIES.map((level) => ({ value: level, label: t(`severity.${level}`) }))}
              onChange={(severity) => {
                setFilters((current) => ({ ...current, severity }));
              }}
            />
            <FilterSelect
              id={ids.owasp}
              label={t('findings.filters.owasp')}
              value={filters.owasp}
              options={owaspOptions.map((code) => ({ value: code, label: code }))}
              onChange={(owasp) => {
                setFilters((current) => ({ ...current, owasp }));
              }}
            />
            <FilterSelect
              id={ids.tool}
              label={t('findings.filters.tool')}
              value={filters.tool}
              options={toolOptions.map((tool) => ({ value: tool, label: tool }))}
              onChange={(tool) => {
                setFilters((current) => ({ ...current, tool }));
              }}
            />
            <FilterSelect
              id={ids.file}
              label={t('findings.filters.file')}
              value={filters.file}
              options={fileOptions.map((path) => ({ value: path, label: path }))}
              onChange={(file) => {
                setFilters((current) => ({ ...current, file }));
              }}
            />
          </div>
          {findings.length === 0 ? (
            <p className="hint">{t('project.findings.empty')}</p>
          ) : (
            <div className="cols">
              <ul className="list" aria-label={t('findings.listLabel')}>
                {visible.length === 0 && <li className="hint">{t('findings.filters.none')}</li>}
                {visible.map((finding) => (
                  <li key={finding.id}>
                    <button
                      type="button"
                      className={finding.id === selected?.id ? 'card sel' : 'card'}
                      aria-pressed={finding.id === selected?.id}
                      onClick={() => {
                        setSelectedId(finding.id);
                      }}
                    >
                      <div className="row first">
                        <SeverityBadge severity={finding.severity} />
                        <VerdictBadge verdict={finding.verdict} />
                      </div>
                      <h4>{finding.title}</h4>
                      <div className="mono">
                        {finding.path}
                        {finding.line !== null && ` · ${t('findings.line', { line: finding.line })}`}
                      </div>
                    </button>
                  </li>
                ))}
              </ul>
              {selected !== null && (
                <FindingDetail
                  key={selected.id}
                  finding={selected}
                  canTriage={canTriage}
                  onVerdict={applyVerdict}
                />
              )}
            </div>
          )}
        </>
      )}
    </AppShell>
  );
}
