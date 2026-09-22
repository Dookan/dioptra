/**
 * Stage E5, day 14: the flow diagram of each planned function. Mockup anchor:
 * screen 06 "Diseño de casos (E5)" — left column: the function, its diagram,
 * the editable Mermaid text and the note that the brief comes from the code;
 * right column: the developer's cases (day 15 — a banner says so).
 */
import { useEffect, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError } from '../api/client';
import * as api from '../api/projects';
import type { Analysis, Diagram, PlannedFunction, Project, TestPlan } from '../api/projects';
import { useAuth } from '../auth/auth-context';
import { AppShell } from '../components/app-shell';
import { FlowDiagram } from '../components/flow-diagram';
import { stageIndex } from '../components/stages';
import { Stepper } from '../components/stepper';
import type { Route } from '../navigation/use-route';

interface Props {
  route: Extract<Route, { kind: 'design' }>;
  onNavigate: (route: Route) => void;
}

function keyOf(ref: PlannedFunction): string {
  return `${ref.path}::${ref.function}::${String(ref.line ?? '')}`;
}

export function CaseDesignScreen({ route, onNavigate }: Props): React.ReactNode {
  const { t } = useTranslation();
  const { accessToken, user } = useAuth();
  const selectId = useId();
  const textId = useId();
  const [project, setProject] = useState<Project | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [plan, setPlan] = useState<TestPlan | null>(null);
  const [selected, setSelected] = useState<PlannedFunction | null>(null);
  const [diagram, setDiagram] = useState<Diagram | null>(null);
  const [draft, setDraft] = useState('');
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [errorKey, setErrorKey] = useState<string | null>(null);
  const [diagramErrorKey, setDiagramErrorKey] = useState<string | null>(null);

  useEffect(() => {
    if (accessToken === null) return;
    let cancelled = false;
    Promise.all([
      api.getProject(accessToken, route.id),
      api.getAnalysis(accessToken, route.analysisId),
      api.getTestPlan(accessToken, route.analysisId),
    ])
      .then(([loadedProject, loadedAnalysis, loadedPlan]) => {
        if (cancelled) return;
        setProject(loadedProject);
        setAnalysis(loadedAnalysis);
        setPlan(loadedPlan);
        setSelected(loadedPlan?.functions[0] ?? null);
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

  useEffect(() => {
    if (accessToken === null || selected === null) return;
    let cancelled = false;
    setDiagram(null);
    setDiagramErrorKey(null);
    setEditing(false);
    api
      .getDiagram(accessToken, route.analysisId, selected)
      .then((loaded) => {
        if (!cancelled) setDiagram(loaded);
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setDiagramErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
        }
      });
    return () => {
      cancelled = true;
    };
  }, [accessToken, route.analysisId, selected]);

  const atDesign = analysis?.stage === 'design';
  const beforeDesign = analysis !== null && stageIndex(analysis.stage) < stageIndex('design');
  const canEdit = user?.role === 'developer' && atDesign;
  const functions = plan?.functions ?? [];
  const position = selected === null ? 0 : functions.findIndex((f) => keyOf(f) === keyOf(selected)) + 1;

  async function save(text: string): Promise<void> {
    if (accessToken === null || selected === null) return;
    setBusy(true);
    setDiagramErrorKey(null);
    try {
      setDiagram(await api.saveDiagramText(accessToken, route.analysisId, selected, text));
      setEditing(false);
    } catch (error) {
      setDiagramErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
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
            <h2>{t('design.title')}</h2>
            <p className="sub">{t('design.subtitle')}</p>
          </div>
          <section className="nextstep">
            <div className="txt">
              <b>
                {beforeDesign
                  ? t('design.nextStep.notYetTitle')
                  : plan === null || functions.length === 0
                    ? t('design.nextStep.noPlanTitle')
                    : t('design.nextStep.diagramsTitle', { count: functions.length })}
              </b>
              <div>{beforeDesign ? t('design.nextStep.notYetBody') : t('design.nextStep.diagramsBody')}</div>
            </div>
          </section>
          {functions.length > 0 && (
            <div className="cols design">
              <section className="panel">
                <div className="field">
                  <label htmlFor={selectId}>{t('design.functionLabel')}</label>
                  <select
                    id={selectId}
                    className="input"
                    value={selected === null ? '' : keyOf(selected)}
                    onChange={(event) => {
                      const next = functions.find((f) => keyOf(f) === event.target.value) ?? null;
                      setSelected(next);
                    }}
                  >
                    {functions.map((f) => (
                      <option key={keyOf(f)} value={keyOf(f)}>
                        {f.function}() · {f.path}
                      </option>
                    ))}
                  </select>
                </div>
                {selected !== null && (
                  <>
                    <h4>{selected.function}()</h4>
                    <div className="mono">
                      {selected.path}
                      {selected.line !== null && ` · ${t('findings.line', { line: selected.line })}`}
                      {' · '}
                      {t('design.position', { position, total: functions.length })}
                    </div>
                  </>
                )}
                {diagramErrorKey !== null && (
                  <p className="alert" role="alert">
                    {t(diagramErrorKey)}
                  </p>
                )}
                {diagram === null && diagramErrorKey === null && (
                  <p className="hint">{t('design.diagram.loading')}</p>
                )}
                {diagram !== null && (
                  <>
                    <div className="row tight">
                      <span className="chip">{t('design.complexity', { count: diagram.complexity })}</span>
                      <span className="chip">{diagram.language}</span>
                      {diagram.graph.params.length > 0 && (
                        <span className="sub">{diagram.graph.params.join(', ')}</span>
                      )}
                    </div>
                    <div className="diagram-frame">
                      <FlowDiagram diagram={diagram} />
                    </div>
                    <p className="hint diagram-legend">{t('design.diagram.legend')}</p>
                    <h5>{t('design.mermaid.title')}</h5>
                    {editing ? (
                      <>
                        <div className="field">
                          <label htmlFor={textId}>{t('design.mermaid.textLabel')}</label>
                          <textarea
                            id={textId}
                            className="input textarea tall mono"
                            value={draft}
                            onChange={(event) => {
                              setDraft(event.target.value);
                            }}
                          />
                        </div>
                        <div className="actions wrap">
                          <button
                            type="button"
                            className="btn primary"
                            disabled={busy}
                            onClick={() => {
                              void save(draft);
                            }}
                          >
                            {t('design.mermaid.save')}
                          </button>
                          <button
                            type="button"
                            className="btn ghost"
                            onClick={() => {
                              setEditing(false);
                            }}
                          >
                            {t('design.mermaid.cancel')}
                          </button>
                        </div>
                      </>
                    ) : (
                      <>
                        {/* Text node only: the developer's Mermaid is never rendered as markup. */}
                        <pre className="codeblock">{diagram.edited_text ?? diagram.mermaid}</pre>
                        {diagram.edited_text !== null && (
                          <p className="hint">
                            {t('design.mermaid.editedBy', { user: diagram.edited_by_username ?? '' })}
                          </p>
                        )}
                        {canEdit && (
                          <div className="actions wrap">
                            <button
                              type="button"
                              className="btn ghost"
                              onClick={() => {
                                setDraft(diagram.edited_text ?? diagram.mermaid);
                                setEditing(true);
                              }}
                            >
                              {t('design.mermaid.edit')}
                            </button>
                            {diagram.edited_text !== null && (
                              <button
                                type="button"
                                className="btn ghost"
                                disabled={busy}
                                onClick={() => {
                                  void save('');
                                }}
                              >
                                {t('design.mermaid.restore')}
                              </button>
                            )}
                          </div>
                        )}
                      </>
                    )}
                    <p className="hint">{t('design.mermaid.note')}</p>
                  </>
                )}
              </section>
              <section className="panel">
                <h4>{t('design.cases.title')}</h4>
                <p className="desc">{t('design.cases.intro')}</p>
                <p className="hint">{t('design.cases.pending')}</p>
              </section>
            </div>
          )}
        </>
      )}
    </AppShell>
  );
}
