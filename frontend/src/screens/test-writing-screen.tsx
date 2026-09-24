/**
 * Stage E6: the developer writes the tests over the deterministic scaffold.
 * Mockup anchor: screen 07 "Escribir los tests (E6)" — left column: the
 * scaffold the platform generated, with the case list and what each case must
 * demonstrate; right column: the developer's file, plain text, saved as text.
 *
 * The screen says out loud what the platform will not do: it never writes an
 * assertion. The tick beside each case means "you wrote something here", not
 * "it is correct" — that is E7's measurement.
 */
import { useEffect, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError } from '../api/client';
import * as api from '../api/projects';
import type {
  Analysis,
  PlannedFunction,
  Project,
  Scaffold,
  TestPlan,
  WritingState,
} from '../api/projects';
import { useAuth } from '../auth/auth-context';
import { AdvanceStage } from '../components/advance-stage';
import { AppShell } from '../components/app-shell';
import { stageIndex } from '../components/stages';
import { Stepper } from '../components/stepper';
import type { Route } from '../navigation/use-route';

interface Props {
  route: Extract<Route, { kind: 'tests' }>;
  onNavigate: (route: Route) => void;
}

function keyOf(ref: PlannedFunction): string {
  return `${ref.path}::${ref.function}::${String(ref.line ?? '')}`;
}

export function TestWritingScreen({ route, onNavigate }: Props): React.ReactNode {
  const { t } = useTranslation();
  const { accessToken, user } = useAuth();
  const selectId = useId();
  const editorId = useId();
  const [project, setProject] = useState<Project | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [plan, setPlan] = useState<TestPlan | null>(null);
  const [states, setStates] = useState<WritingState[]>([]);
  const [selected, setSelected] = useState<PlannedFunction | null>(null);
  const [scaffold, setScaffold] = useState<Scaffold | null>(null);
  const [draft, setDraft] = useState('');
  const [busy, setBusy] = useState(false);
  const [errorKey, setErrorKey] = useState<string | null>(null);
  const [fileErrorKey, setFileErrorKey] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    if (accessToken === null) return;
    let cancelled = false;
    Promise.all([
      api.getProject(accessToken, route.id),
      api.getAnalysis(accessToken, route.analysisId),
      api.getTestPlan(accessToken, route.analysisId),
      api.getWritingStates(accessToken, route.analysisId),
    ])
      .then(([loadedProject, loadedAnalysis, loadedPlan, loadedStates]) => {
        if (cancelled) return;
        setProject(loadedProject);
        setAnalysis(loadedAnalysis);
        setPlan(loadedPlan);
        setStates(loadedStates);
        setSelected(loadedPlan?.functions[0] ?? null);
      })
      .catch((error: unknown) => {
        if (!cancelled) setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
      });
    return () => {
      cancelled = true;
    };
  }, [accessToken, route.id, route.analysisId]);

  useEffect(() => {
    if (accessToken === null || selected === null) return;
    let cancelled = false;
    setScaffold(null);
    setFileErrorKey(null);
    setNotice(null);
    api
      .getScaffold(accessToken, route.analysisId, selected)
      .then((loaded) => {
        if (cancelled) return;
        setScaffold(loaded);
        setDraft(loaded.content === '' ? loaded.scaffold : loaded.content);
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setFileErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
        }
      });
    return () => {
      cancelled = true;
    };
  }, [accessToken, route.analysisId, selected]);

  const atTests = analysis?.stage === 'tests';
  const beforeTests = analysis !== null && stageIndex(analysis.stage) < stageIndex('tests');
  const afterTests = analysis !== null && stageIndex(analysis.stage) > stageIndex('tests');
  const canEdit = user?.role === 'developer' && atTests;
  const functions = plan?.functions ?? [];
  const position =
    selected === null ? 0 : functions.findIndex((f) => keyOf(f) === keyOf(selected)) + 1;
  const totalCases = states.reduce((sum, state) => sum + state.cases, 0);
  const totalWritten = states.reduce((sum, state) => sum + state.written, 0);
  const allWritten = totalCases > 0 && totalWritten === totalCases;
  const dirty = scaffold !== null && draft !== (scaffold.content === '' ? scaffold.scaffold : scaffold.content);

  async function save(): Promise<void> {
    if (accessToken === null || selected === null) return;
    setBusy(true);
    setFileErrorKey(null);
    setNotice(null);
    try {
      const saved = await api.saveTests(accessToken, route.analysisId, selected, draft);
      setScaffold(saved);
      setDraft(saved.content);
      setNotice('tests.saved');
      setStates((current) =>
        current.map((state) =>
          keyOf(state) === keyOf(selected)
            ? {
                ...state,
                cases: saved.cases.length,
                written: saved.cases.filter((c) => c.written).length,
                parse_error: saved.parse_error,
              }
            : state,
        ),
      );
    } catch (error) {
      setFileErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
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
            <h2>{t('tests.title')}</h2>
            <p className="sub">{t('tests.subtitle')}</p>
          </div>
          <section className="nextstep">
            <div className="txt">
              <b>
                {beforeTests
                  ? t('tests.nextStep.notYetTitle')
                  : functions.length === 0
                    ? t('tests.nextStep.noPlanTitle')
                    : afterTests
                      ? t('tests.nextStep.doneTitle')
                      : t('tests.nextStep.writeTitle', {
                          written: totalWritten,
                          count: totalCases,
                        })}
              </b>
              <div>
                {beforeTests
                  ? t('tests.nextStep.notYetBody')
                  : functions.length === 0
                    ? t('tests.nextStep.noPlanBody')
                    : afterTests
                      ? t('tests.nextStep.doneBody')
                      : t('tests.nextStep.writeBody')}
              </div>
            </div>
            {atTests && user?.role === 'developer' && functions.length > 0 && (
              <AdvanceStage
                analysis={analysis}
                label={t('tests.advance.label')}
                ready={allWritten}
                blockedHint={t('tests.advance.blocked', {
                  written: totalWritten,
                  count: totalCases,
                })}
                onAdvanced={(next) => {
                  // The button's arrow promises the next screen: go there.
                  setAnalysis(next);
                  onNavigate({ kind: 'verify', id: route.id, analysisId: route.analysisId });
                }}
              />
            )}
          </section>
          {functions.length > 0 && (
            <div className="cols tests">
              <section className="panel">
                <div className="field">
                  <label htmlFor={selectId}>{t('tests.functionLabel')}</label>
                  <select
                    id={selectId}
                    className="input"
                    value={selected === null ? '' : keyOf(selected)}
                    onChange={(event) => {
                      setSelected(functions.find((f) => keyOf(f) === event.target.value) ?? null);
                    }}
                  >
                    {functions.map((f) => (
                      <option key={keyOf(f)} value={keyOf(f)}>
                        {f.function}() · {f.path}
                      </option>
                    ))}
                  </select>
                  <p className="mono sub">
                    {t('tests.position', { position, total: functions.length })}
                  </p>
                </div>
                {scaffold !== null && (
                  <>
                    <h4>{t('tests.casesTitle')}</h4>
                    <ul className="caselist">
                      {scaffold.cases.map((c) => (
                        <li key={c.id}>
                          <span className={c.written ? 'chip ok' : 'chip'}>{c.id}</span> {c.title}
                          <div className="covers">
                            <span className="sub">
                              {c.written ? t('tests.caseWritten') : t('tests.caseEmpty')}
                            </span>
                            {c.covers.length > 0 && (
                              <span className="sub">
                                {t('tests.caseCovers')} {c.covers.join(', ')}
                              </span>
                            )}
                          </div>
                        </li>
                      ))}
                    </ul>
                  </>
                )}
                <button
                  type="button"
                  className="btn ghost"
                  onClick={() => {
                    onNavigate({ kind: 'design', id: route.id, analysisId: route.analysisId });
                  }}
                >
                  {t('tests.backToDesign')}
                </button>
              </section>
              <section className="panel">
                <h4>{t('tests.scaffoldTitle')}</h4>
                {scaffold !== null && (
                  <>
                    <p className="hint">
                      {t('tests.scaffoldNote', {
                        filename: scaffold.filename,
                        runner: scaffold.runner,
                      })}
                    </p>
                    <pre className="codeblock tall">{scaffold.scaffold}</pre>
                  </>
                )}
                <h4>{t('tests.yourFileTitle')}</h4>
                <p className="hint">{t('tests.yourFileNote')}</p>
                {fileErrorKey !== null && (
                  <p className="alert" role="alert">
                    {t(fileErrorKey)}
                  </p>
                )}
                {scaffold?.parse_error === true && (
                  <p className="alert" role="alert">
                    {t('tests.parseError')}
                  </p>
                )}
                <div className="field">
                  <label htmlFor={editorId}>{t('tests.editorLabel')}</label>
                  <textarea
                    id={editorId}
                    className="input textarea tall mono"
                    value={draft}
                    readOnly={!canEdit}
                    onChange={(event) => {
                      setDraft(event.target.value);
                    }}
                  />
                </div>
                {canEdit && (
                  <div className="row">
                    <button
                      type="button"
                      className="btn primary"
                      disabled={busy || !dirty}
                      onClick={() => void save()}
                    >
                      {t('tests.save')}
                    </button>
                    {scaffold !== null && (
                      <button
                        type="button"
                        className="btn small"
                        disabled={busy}
                        onClick={() => {
                          setDraft(scaffold.scaffold);
                        }}
                      >
                        {t('tests.reset')}
                      </button>
                    )}
                  </div>
                )}
                {notice !== null && <p className="hint ok">{t(notice)}</p>}
                {scaffold?.stored_by_username != null && (
                  <p className="mono sub">
                    {t('tests.storedBy', { username: scaffold.stored_by_username })}
                  </p>
                )}
                {!canEdit && <p className="hint">{t('tests.readOnly')}</p>}
              </section>
            </div>
          )}
        </>
      )}
    </AppShell>
  );
}
