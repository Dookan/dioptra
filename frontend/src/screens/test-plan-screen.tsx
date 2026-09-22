/**
 * Stage E4: the test plan. Mockup anchor: screen 05 "Plan de pruebas (E4)" —
 * functions ranked by risk with a plain-words reason each, Incluir / Dejar
 * fuera, the coverage exigency as pill radios, the developer's rationale, and
 * "Guardar plan y diseñar los casos →". The ranking comes from the server
 * (`GET …/risk-matrix`); this screen never computes risk.
 */
import { useEffect, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError } from '../api/client';
import * as api from '../api/projects';
import type { Analysis, CoverageCriterion, Project, RiskRow, TestPlan } from '../api/projects';
import { useAuth } from '../auth/auth-context';
import { AdvanceStage } from '../components/advance-stage';
import { AppShell } from '../components/app-shell';
import { stageIndex } from '../components/stages';
import { Stepper } from '../components/stepper';
import type { Route } from '../navigation/use-route';

const CRITERIA: CoverageCriterion[] = ['statements', 'decisions', 'paths'];
/** Mirrors backend/app/workflow/triage.py::MIN_JUSTIFICATION_CHARS — the server is the gate. */
const MIN_RATIONALE = 10;
const LEVEL_TONE: Record<RiskRow['level'], string> = { high: 'err', medium: 'warn', low: 'ok' };

interface Props {
  route: Extract<Route, { kind: 'plan' }>;
  onNavigate: (route: Route) => void;
}

function keyOf(row: { path: string; function: string; line: number | null }): string {
  return `${row.path}::${row.function}::${String(row.line ?? '')}`;
}

function reasonKey(row: RiskRow): string {
  // Plain words, no formula: how complex, and whether it has findings.
  const size = row.ccn >= 10 ? 'complex' : row.ccn >= 5 ? 'medium' : 'simple';
  return row.findings > 0 ? `plan.reason.${size}WithFindings` : `plan.reason.${size}`;
}

export function TestPlanScreen({ route, onNavigate }: Props): React.ReactNode {
  const { t } = useTranslation();
  const { accessToken, user } = useAuth();
  const rationaleId = useId();
  const [project, setProject] = useState<Project | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [rows, setRows] = useState<RiskRow[] | null>(null);
  const [plan, setPlan] = useState<TestPlan | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [criterion, setCriterion] = useState<CoverageCriterion>('decisions');
  const [rationale, setRationale] = useState('');
  const [busy, setBusy] = useState(false);
  const [savedAt, setSavedAt] = useState<string | null>(null);
  const [errorKey, setErrorKey] = useState<string | null>(null);
  // The server names the refused function (path, function, line) as data.
  const [errorContext, setErrorContext] = useState<Record<string, string>>({});

  useEffect(() => {
    if (accessToken === null) return;
    let cancelled = false;
    Promise.all([
      api.getProject(accessToken, route.id),
      api.getAnalysis(accessToken, route.analysisId),
      api.getRiskMatrix(accessToken, route.analysisId),
      api.getTestPlan(accessToken, route.analysisId),
    ])
      .then(([loadedProject, loadedAnalysis, matrix, loadedPlan]) => {
        if (cancelled) return;
        setProject(loadedProject);
        setAnalysis(loadedAnalysis);
        setRows(matrix);
        setPlan(loadedPlan);
        if (loadedPlan !== null) {
          setSelected(new Set(loadedPlan.functions.map(keyOf)));
          setCriterion(loadedPlan.criterion);
          setRationale(loadedPlan.rationale);
        }
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

  const isDeveloper = user?.role === 'developer';
  const atPlan = analysis?.stage === 'plan';
  const pastPlan = analysis !== null && stageIndex(analysis.stage) > stageIndex('plan');
  const beforePlan = analysis !== null && stageIndex(analysis.stage) < stageIndex('plan');
  const canEdit = isDeveloper && atPlan;
  const collapsedRationale = rationale.split(/\s+/).filter(Boolean).join(' ');
  const complete = selected.size > 0 && collapsedRationale.length >= MIN_RATIONALE;

  function toggle(row: RiskRow): void {
    setSelected((current) => {
      const next = new Set(current);
      const key = keyOf(row);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
    setSavedAt(null);
  }

  /** PUT the plan; resolves true when the server accepted it. */
  async function save(): Promise<boolean> {
    if (accessToken === null || rows === null || !complete) return false;
    setBusy(true);
    setErrorKey(null);
    try {
      const functions = rows
        .filter((row) => selected.has(keyOf(row)))
        .map((row) => ({ path: row.path, function: row.function, line: row.line }));
      const stored = await api.saveTestPlan(accessToken, route.analysisId, {
        criterion,
        rationale: collapsedRationale,
        functions,
      });
      setPlan(stored);
      setSavedAt(stored.updated_at);
      return true;
    } catch (error) {
      setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
      setErrorContext(error instanceof ApiError ? error.context : {});
      return false;
    } finally {
      setBusy(false);
    }
  }

  return (
    <AppShell route={route} onNavigate={onNavigate} context={project?.name} stage={analysis?.stage}>
      {analysis !== null && <Stepper current={stageIndex(analysis.stage)} />}
      {errorKey !== null && (
        <p className="alert" role="alert">
          {t(errorKey, errorContext)}
        </p>
      )}
      {analysis !== null && rows !== null && (
        <>
          <div className="pagehead">
            <h2>{t('plan.title')}</h2>
            <p className="sub">{t('plan.subtitle')}</p>
          </div>
          <section className="nextstep">
            <div className="txt">
              <b>
                {beforePlan
                  ? t('plan.nextStep.notYetTitle')
                  : pastPlan
                    ? t('plan.nextStep.lockedTitle')
                    : plan === null
                      ? t('plan.nextStep.emptyTitle')
                      : t('plan.nextStep.savedTitle', { count: plan.functions.length })}
              </b>
              <div>
                {beforePlan
                  ? t('plan.nextStep.notYetBody')
                  : pastPlan
                    ? t('plan.nextStep.lockedBody')
                    : isDeveloper
                      ? t('plan.nextStep.developerBody')
                      : t('plan.nextStep.readerBody')}
              </div>
            </div>
          </section>
          {rows.length === 0 ? (
            <p className="hint">{t('plan.noFunctions')}</p>
          ) : (
            <ol className="ranking" aria-label={t('plan.rankingLabel')}>
              {rows.map((row, index) => {
                const included = selected.has(keyOf(row));
                return (
                  <li key={keyOf(row)} className={included ? 'rowline sel' : 'rowline'}>
                    <span className="prio" aria-hidden="true">
                      {index + 1}
                    </span>
                    <div className="grow">
                      {/* Function names and paths come from the audited tree: text nodes only. */}
                      <b>{row.function}()</b> · <span className="mono">{row.path}</span>
                      {row.line !== null && (
                        <span className="mono"> · {t('findings.line', { line: row.line })}</span>
                      )}
                      <div className="sub">
                        {t(reasonKey(row), { ccn: row.ccn, count: row.findings })}
                      </div>
                    </div>
                    <span className={`badge ${LEVEL_TONE[row.level]}`}>
                      {t(`plan.level.${row.level}`)}
                    </span>
                    {canEdit ? (
                      <button
                        type="button"
                        className={included ? 'btn ghost' : 'btn primary'}
                        aria-pressed={included}
                        onClick={() => {
                          toggle(row);
                        }}
                      >
                        {included ? t('plan.exclude') : t('plan.include')}
                      </button>
                    ) : (
                      included && <span className="badge ok">{t('plan.included')}</span>
                    )}
                  </li>
                );
              })}
            </ol>
          )}
          <section className="panel">
            <h4>{t('plan.criterion.title')}</h4>
            <div className="radios" role="radiogroup" aria-label={t('plan.criterion.title')}>
              {CRITERIA.map((option) => (
                <button
                  key={option}
                  type="button"
                  role="radio"
                  aria-checked={criterion === option}
                  className={criterion === option ? 'radio on' : 'radio'}
                  disabled={!canEdit}
                  onClick={() => {
                    setCriterion(option);
                    setSavedAt(null);
                  }}
                >
                  {t(`plan.criterion.${option}`)}
                </button>
              ))}
            </div>
            <p className="hint">{t(`plan.criterion.${criterion}Hint`)}</p>
            <div className="field">
              <label htmlFor={rationaleId}>{t('plan.rationaleLabel')}</label>
              <textarea
                id={rationaleId}
                className="input textarea"
                rows={3}
                value={rationale}
                placeholder={t('plan.rationalePlaceholder')}
                disabled={!canEdit}
                onChange={(event) => {
                  setRationale(event.target.value);
                  setSavedAt(null);
                }}
              />
              <span className="hint">{t('plan.rationaleHint', { min: MIN_RATIONALE })}</span>
            </div>
            {canEdit && (
              <div className="actions wrap">
                {/* Anchor position (mockup 05): the primary CTA sits under the rationale. */}
                <AdvanceStage
                  analysis={analysis}
                  label={t('plan.saveAndDesign')}
                  ready={complete}
                  blockedHint={t('plan.incomplete', { min: MIN_RATIONALE })}
                  onAdvanced={setAnalysis}
                  beforeAdvance={save}
                />
                <button
                  type="button"
                  className="btn ghost"
                  disabled={busy || !complete}
                  onClick={() => {
                    void save();
                  }}
                >
                  {t('plan.save')}
                </button>
                <span className="hint">
                  {savedAt !== null ? t('plan.saved') : t('plan.rationaleInReport')}
                </span>
              </div>
            )}
          </section>
        </>
      )}
    </AppShell>
  );
}
