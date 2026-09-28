/**
 * Stage E4: the test plan. Mockup anchor: screen 05 "Plan de pruebas (E4)" —
 * functions ranked by risk with a plain-words reason each, Incluir / Dejar
 * fuera, the coverage exigency as pill radios, the developer's rationale, and
 * "Guardar plan y diseñar los casos →". The ranking comes from the server
 * (`GET …/risk-matrix`); this screen never computes risk.
 */
import { useEffect, useId, useRef, useState } from 'react';
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
/** Mirrors backend/app/core/text.py::MIN_JUSTIFICATION_CHARS — the server is the gate. */
const MIN_RATIONALE = 10;
const LEVEL_TONE: Record<RiskRow['level'], string> = { high: 'err', medium: 'warn', low: 'ok' };

interface Props {
  route: Extract<Route, { kind: 'plan' }>;
  onNavigate: (route: Route) => void;
}

interface PlannedKey {
  path: string;
  function: string;
  line: number | null;
}

function keyOf(row: PlannedKey): string {
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
  // How many functions matched before the cap, and the filter that reaches
  // the ones it hides. A real Laravel tree measured 5 000 functions whose
  // top 200 by score were all hand-vendored JavaScript, so the developer
  // could not select a single one of their own (phase-7a walk).
  const [total, setTotal] = useState(0);
  const [filter, setFilter] = useState('');
  const filterId = useId();
  //: The query whose result is on screen, so the debounced effect can tell a
  //: real change from the mount it would otherwise duplicate.
  const lastQuery = useRef('');
  const [plan, setPlan] = useState<TestPlan | null>(null);
  // The selection carries each row's identity, not just its key. It used to be
  // a Set<string> intersected with `rows` at save time, which was harmless while
  // `rows` was always the whole capped matrix — the search box made it the LAST
  // FILTERED PAGE, so ticking a function and then searching again dropped it
  // from the saved plan with nothing on screen saying so, and the server only
  // refuses a fully empty plan (invariant checker, 2026-09-23).
  const [selected, setSelected] = useState<Map<string, PlannedKey>>(new Map());
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
        setRows(matrix.rows);
        setTotal(matrix.total);
        setPlan(loadedPlan);
        if (loadedPlan !== null) {
          setSelected(
            new Map(
              loadedPlan.functions.map((row) => [
                keyOf(row),
                { path: row.path, function: row.function, line: row.line },
              ]),
            ),
          );
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

  // The filter is applied by the SERVER, before the cap — that is the whole
  // point of it, so it cannot be a client-side `rows.filter`. Debounced so a
  // typed word is one request rather than one per keystroke.
  useEffect(() => {
    if (accessToken === null) return;
    const typed = filter.trim();
    // The load effect already fetched the unfiltered matrix, so re-asking for
    // it 250 ms later recomputed a 5 000-function ranking twice per screen
    // open. A REF rather than reading `rows`: `rows` changes on every fetch, so
    // depending on it would re-run this effect forever, and oxlint is right to
    // refuse a guard that reads state the dependency array does not declare.
    if (typed === lastQuery.current) return;
    let cancelled = false;
    const timer = setTimeout(() => {
      api
        .getRiskMatrix(accessToken, route.analysisId, typed || undefined)
        .then((matrix) => {
          if (cancelled) return;
          lastQuery.current = typed;
          setRows(matrix.rows);
          setTotal(matrix.total);
        })
        .catch((error: unknown) => {
          if (!cancelled) {
            setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
          }
        });
    }, 250);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [accessToken, route.analysisId, filter]);

  const isDeveloper = user?.role === 'developer';
  const atPlan = analysis?.stage === 'plan';
  const pastPlan = analysis !== null && stageIndex(analysis.stage) > stageIndex('plan');
  const beforePlan = analysis !== null && stageIndex(analysis.stage) < stageIndex('plan');
  const canEdit = isDeveloper && atPlan;
  const collapsedRationale = rationale.split(/\s+/).filter(Boolean).join(' ');
  const complete = selected.size > 0 && collapsedRationale.length >= MIN_RATIONALE;

  function toggle(row: RiskRow): void {
    setSelected((current) => {
      const next = new Map(current);
      const key = keyOf(row);
      if (next.has(key)) next.delete(key);
      else next.set(key, { path: row.path, function: row.function, line: row.line });
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
      // From the SELECTION, never from `rows`: what is on screen right now is
      // whatever the last filter returned, and a plan must not depend on that.
      const functions = [...selected.values()];
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
          <div className="filterbar">
            <label htmlFor={filterId}>{t('plan.filter.label')}</label>
            <input
              id={filterId}
              className="input"
              type="search"
              value={filter}
              placeholder={t('plan.filter.placeholder')}
              onChange={(event) => {
                setFilter(event.target.value);
              }}
            />
          </div>
          {rows.length > 0 && (
            <p className="sub" role="status">
              {rows.length < total
                ? t('plan.showing.capped', { shown: rows.length, total })
                : filter.trim()
                  ? t('plan.showing.matches', { total })
                  : t('plan.showing.all', { total })}
            </p>
          )}
          {rows.length === 0 ? (
            <p className="hint">{filter ? t('plan.noMatches') : t('plan.noFunctions')}</p>
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
                  onAdvanced={(next) => {
                    // The button's arrow promises the next screen: go there.
                    setAnalysis(next);
                    onNavigate({ kind: 'design', id: route.id, analysisId: route.analysisId });
                  }}
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
