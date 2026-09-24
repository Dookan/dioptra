/**
 * Stage E7: the tests run in the sandbox and the platform re-audits them.
 * Mockup anchor: screen 08 "Verificación (E7)".
 *
 * The screen's job is to make a rejection LEGIBLE. "Rompimos el código a
 * propósito; un buen test debe fallar" is only a lesson if the developer can
 * see which mutant survived, which brief item never ran, and which case
 * asserts nothing — so every failure is shown by name, never as a score.
 */
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError } from '../api/client';
import * as api from '../api/projects';
import type { Analysis, PlannedFunction, Project, TestPlan, VerificationRun } from '../api/projects';
import { useAuth } from '../auth/auth-context';
import { AdvanceStage } from '../components/advance-stage';
import { AppShell } from '../components/app-shell';
import { stageIndex } from '../components/stages';
import { Stepper } from '../components/stepper';
import type { Route } from '../navigation/use-route';

interface Props {
  route: Extract<Route, { kind: 'verify' }>;
  onNavigate: (route: Route) => void;
}

function keyOf(ref: PlannedFunction): string {
  return `${ref.path}::${ref.function}::${String(ref.line ?? '')}`;
}

interface RunCardProps {
  run: VerificationRun;
  /** The developer at E7; `undefined` renders the card read-only. Resolves true when the server accepted. */
  onMarkEquivalent?: (mutantId: string, justification: string) => Promise<boolean>;
  busy?: boolean;
}

function RunCard({ run, onMarkEquivalent, busy = false }: RunCardProps): React.ReactNode {
  const { t } = useTranslation();
  const [marking, setMarking] = useState<string | null>(null);
  const [why, setWhy] = useState('');
  const passed = run.status === 'passed';
  return (
    <li className="caserow">
      <div className="row first">
        <span className={passed ? 'chip ok' : 'chip err'}>
          {passed ? t('verify.passed') : t('verify.failed')}
        </span>
        <span className="grow">
          <b>{run.function}()</b> <span className="sub">{run.path}</span>
        </span>
      </div>
      <p className="sub">
        {t('verify.coverage', {
          statements: run.coverage.statement_percent ?? 0,
          branches: run.coverage.branch_percent ?? 0,
        })}
      </p>
      {/* The percentages above are the MODULE's, the verdict is the planned
          function's. Saying so is the same rule the mutation gap follows:
          declared on every surface, never a silent pass. */}
      {Array.isArray(run.coverage.criterion_lines) && (
        <p className="sub">
          {t('verify.criterionLines', {
            from: run.coverage.criterion_lines[0],
            to: run.coverage.criterion_lines[1],
          })}
        </p>
      )}
      {run.reasons.map((reason) => (
        <p key={reason} className="reason bad">
          {t(`verify.reason.${reason}`)}
        </p>
      ))}
      {run.failed_cases.length > 0 && (
        <p className="sub">
          {t('verify.failedCases')} {run.failed_cases.join(', ')}
        </p>
      )}
      {run.assertion_free_cases.length > 0 && (
        <p className="sub">
          {t('verify.assertionFreeCases')} {run.assertion_free_cases.join(', ')}
        </p>
      )}
      {run.uncovered_items.length > 0 && (
        <div className="covers">
          <span className="sub">{t('verify.uncoveredItems')}</span>
          {run.uncovered_items.map((item) => (
            <span key={item} className="chip err">
              {item}
            </span>
          ))}
        </div>
      )}
      {run.mutation_measured === false && (
        // A declared gap, never a silent pass: without this line an empty
        // survivor list reads as "nothing survived" (docs/workflow-gates.md).
        <p className="sub warn">{t('verify.mutationNotMeasured')}</p>
      )}
      {run.surviving_mutants.length > 0 && (
        <>
          <p className="sub">
            {t('verify.survivorsTitle', { count: run.surviving_mutants.length })}
          </p>
          <ul className="caselist">
            {run.surviving_mutants.slice(0, 20).map((mutant) => (
              <li key={mutant.id}>
                <span className="mono sub">
                  {mutant.line === '' ? '' : `${t('verify.line')} ${mutant.line} · `}
                  {mutant.mutant}
                </span>
                {onMarkEquivalent !== undefined && marking !== mutant.id && (
                  <>
                    {' '}
                    <button
                      type="button"
                      className="btn ghost small"
                      onClick={() => {
                        setMarking(mutant.id);
                        setWhy('');
                      }}
                    >
                      {t('verify.markEquivalent')}
                    </button>
                  </>
                )}
                {onMarkEquivalent !== undefined && marking === mutant.id && (
                  <div className="field">
                    <p className="hint">{t('verify.equivalentNote')}</p>
                    <label htmlFor={`eq-${mutant.id}`}>{t('verify.equivalentReasonLabel')}</label>
                    <textarea
                      id={`eq-${mutant.id}`}
                      className="input textarea"
                      value={why}
                      onChange={(event) => {
                        setWhy(event.target.value);
                      }}
                    />
                    <div className="actions">
                      <button
                        type="button"
                        className="btn"
                        disabled={busy || why.trim().length < 10}
                        onClick={() => {
                          void onMarkEquivalent(mutant.id, why).then((accepted) => {
                            // A refusal keeps the form open with the typed reason.
                            if (accepted) setMarking(null);
                          });
                        }}
                      >
                        {t('verify.markEquivalent')}
                      </button>
                      <button
                        type="button"
                        className="btn ghost"
                        onClick={() => {
                          setMarking(null);
                        }}
                      >
                        {t('verify.cancel')}
                      </button>
                    </div>
                  </div>
                )}
              </li>
            ))}
          </ul>
        </>
      )}
      {run.equivalent_mutants.length > 0 && (
        <>
          <p className="sub">{t('verify.equivalentTitle', { count: run.equivalent_mutants.length })}</p>
          <ul className="caselist">
            {run.equivalent_mutants.slice(0, 20).map((mutant) => (
              <li key={mutant.id} className="mono sub">
                {mutant.line === '' ? '' : `${t('verify.line')} ${mutant.line} · `}
                {mutant.mutant}
              </li>
            ))}
          </ul>
        </>
      )}
      {run.detail !== null && run.detail !== '' && <pre className="codeblock">{run.detail}</pre>}
    </li>
  );
}

export function VerificationScreen({ route, onNavigate }: Props): React.ReactNode {
  const { t } = useTranslation();
  const { accessToken, user } = useAuth();
  const [project, setProject] = useState<Project | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [plan, setPlan] = useState<TestPlan | null>(null);
  const [runs, setRuns] = useState<VerificationRun[]>([]);
  const [busy, setBusy] = useState(false);
  const [errorKey, setErrorKey] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reason, setReason] = useState('');

  function load(token: string): Promise<void> {
    return Promise.all([
      api.getProject(token, route.id),
      api.getAnalysis(token, route.analysisId),
      api.getTestPlan(token, route.analysisId),
      api.getVerification(token, route.analysisId),
    ]).then(([loadedProject, loadedAnalysis, loadedPlan, loadedRuns]) => {
      setProject(loadedProject);
      setAnalysis(loadedAnalysis);
      setPlan(loadedPlan);
      setRuns(loadedRuns);
    });
  }

  useEffect(() => {
    if (accessToken === null) return;
    let cancelled = false;
    load(accessToken).catch((error: unknown) => {
      if (!cancelled) setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accessToken, route.id, route.analysisId]);

  const atVerification = analysis?.stage === 'verification';
  const before = analysis !== null && stageIndex(analysis.stage) < stageIndex('verification');
  const canRun = user?.role === 'developer' && atVerification;
  const functions = plan?.functions ?? [];
  const byKey = new Map(runs.map((run) => [keyOf(run), run]));
  const passed = runs.filter((run) => run.status === 'passed').length;
  const allPassed = functions.length > 0 && functions.every((f) => byKey.get(keyOf(f))?.status === 'passed');
  const anyFailed = runs.some((run) => run.status !== 'passed');

  /** Runs an action and reloads; resolves true only when the server accepted it. */
  async function act(action: () => Promise<unknown>, noticeKey: string): Promise<boolean> {
    if (accessToken === null) return false;
    setBusy(true);
    setErrorKey(null);
    setNotice(null);
    try {
      await action();
      await load(accessToken);
      setNotice(noticeKey);
      return true;
    } catch (error) {
      setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
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
          {t(errorKey)}
        </p>
      )}
      {analysis !== null && (
        <>
          <div className="pagehead">
            <h2>{t('verify.title')}</h2>
            <p className="sub">{t('verify.subtitle')}</p>
          </div>
          <section className={anyFailed ? 'nextstep warn' : 'nextstep'}>
            <div className="txt">
              <b>
                {before
                  ? t('verify.nextStep.notYetTitle')
                  : runs.length === 0
                    ? t('verify.nextStep.neverRunTitle')
                    : t('verify.nextStep.resultTitle', { passed, count: functions.length })}
              </b>
              <div>
                {before
                  ? t('verify.nextStep.notYetBody')
                  : runs.length === 0
                    ? t('verify.nextStep.neverRunBody')
                    : t('verify.nextStep.resultBody')}
              </div>
            </div>
            {atVerification && user?.role === 'developer' && (
              <AdvanceStage
                analysis={analysis}
                label={t('verify.advance.label')}
                ready={allPassed}
                blockedHint={t('verify.advance.blocked')}
                onAdvanced={(next) => {
                  // The button's arrow promises the next screen: go there.
                  setAnalysis(next);
                  onNavigate({ kind: 'report', id: route.id, analysisId: route.analysisId });
                }}
              />
            )}
          </section>
          <div className="cols side">
            <section className="panel">
              <h4>{t('verify.runsTitle')}</h4>
              {runs.length === 0 ? (
                <p className="hint">{t('verify.noRuns')}</p>
              ) : (
                <ul className="caselist">
                  {runs.map((run) => (
                    <RunCard
                      key={keyOf(run)}
                      run={run}
                      busy={busy}
                      onMarkEquivalent={
                        canRun
                          ? (mutantId, justification) =>
                              act(
                                () =>
                                  api.markMutantEquivalent(
                                    accessToken ?? '',
                                    route.analysisId,
                                    run,
                                    mutantId,
                                    justification,
                                  ),
                                'verify.equivalentMarked',
                              )
                          : undefined
                      }
                    />
                  ))}
                </ul>
              )}
            </section>
            <section className="panel">
              <h4>{t('verify.actionsTitle')}</h4>
              <p className="hint">{t('verify.actionsNote')}</p>
              {canRun && (
                <button
                  type="button"
                  className="btn primary"
                  disabled={busy}
                  onClick={() =>
                    void act(
                      () => api.startVerification(accessToken ?? '', route.analysisId),
                      'verify.started',
                    )
                  }
                >
                  {t('verify.run')}
                </button>
              )}
              {canRun && anyFailed && (
                <>
                  <h4>{t('verify.reopenTitle')}</h4>
                  <p className="hint">{t('verify.reopenNote')}</p>
                  <div className="field">
                    <label htmlFor="verify-reason">{t('verify.reasonLabel')}</label>
                    <textarea
                      id="verify-reason"
                      className="input textarea"
                      value={reason}
                      onChange={(event) => {
                        setReason(event.target.value);
                      }}
                    />
                  </div>
                  <button
                    type="button"
                    className="btn"
                    disabled={busy || reason.trim().length < 10}
                    onClick={() =>
                      void act(
                        () => api.reopenDesign(accessToken ?? '', route.analysisId, reason),
                        'verify.reopened',
                      )
                    }
                  >
                    {t('verify.reopen')}
                  </button>
                </>
              )}
              {notice !== null && <p className="hint ok">{t(notice)}</p>}
              {!canRun && <p className="hint">{t('verify.readOnly')}</p>}
            </section>
          </div>
        </>
      )}
    </AppShell>
  );
}
