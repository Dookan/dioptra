/**
 * Stage E5: the flow diagram (day 14), the brief and the cases (day 15) of each
 * planned function. Mockup anchor: screen 06 "Diseño de casos (E5)" — left
 * column: the function, its diagram, the editable Mermaid text, the note that
 * the brief comes from the code and "La consigna te pide"; right column: the
 * developer's cases in their own words, each declaring which brief items it
 * covers, then approval and the way to the next stage.
 */
import { useEffect, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError } from '../api/client';
import * as api from '../api/projects';
import type {
  Analysis,
  BriefItem,
  BriefState,
  CaseDraft,
  DesignState,
  Diagram,
  PlannedFunction,
  Project,
  TestPlan,
} from '../api/projects';
import { useAuth } from '../auth/auth-context';
import { AdvanceStage } from '../components/advance-stage';
import { AppShell } from '../components/app-shell';
import { FlowDiagram } from '../components/flow-diagram';
import { stageIndex } from '../components/stages';
import { Stepper } from '../components/stepper';
import type { Route } from '../navigation/use-route';

/** Edge labels the builder emits as words; anything else (a `case …`) is source text. */
const EDGE_WORDS = new Set(['true', 'false', 'loop', 'except', 'default']);

interface Props {
  route: Extract<Route, { kind: 'design' }>;
  onNavigate: (route: Route) => void;
}

function keyOf(ref: PlannedFunction): string {
  return `${ref.path}::${ref.function}::${String(ref.line ?? '')}`;
}

function sameCases(a: CaseDraft[], b: CaseDraft[]): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function uncovered(items: BriefItem[], cases: CaseDraft[]): string[] {
  const covered = new Set(cases.flatMap((c) => c.covers));
  return items.filter((item) => !covered.has(item.id)).map((item) => item.id);
}

function BriefLine({ item }: { item: BriefItem }): React.ReactNode {
  const { t } = useTranslation();
  const line = item.line ?? 0;
  let text: string;
  switch (item.kind) {
    case 'branch':
      text = t('design.brief.branch', {
        line,
        text: item.text,
        side: EDGE_WORDS.has(item.detail) ? t(`design.edge.${item.detail}`) : item.detail,
      });
      break;
    case 'boundary':
      text =
        item.values.length === 0
          ? t('design.brief.boundaryEmpty', { line, text: item.text })
          : t('design.brief.boundary', {
              line,
              text: item.text,
              values: item.values.map((v) => (v === '' ? t('design.brief.emptyValue') : v)).join(', '),
            });
      break;
    case 'error':
      text = t(`design.brief.error.${item.detail}`, { line, text: item.text });
      break;
    default:
      text = t('design.brief.malicious', { line, text: item.text });
  }
  return (
    <li>
      <span className="chip">{item.id}</span> {text}
    </li>
  );
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
  const [briefState, setBriefState] = useState<BriefState | null>(null);
  const [briefErrorKey, setBriefErrorKey] = useState<string | null>(null);
  const [drafts, setDrafts] = useState<CaseDraft[]>([]);
  const [casesBusy, setCasesBusy] = useState(false);
  const [casesErrorKey, setCasesErrorKey] = useState<string | null>(null);
  const [casesNotice, setCasesNotice] = useState<string | null>(null);
  const [states, setStates] = useState<DesignState[]>([]);

  useEffect(() => {
    if (accessToken === null) return;
    let cancelled = false;
    Promise.all([
      api.getProject(accessToken, route.id),
      api.getAnalysis(accessToken, route.analysisId),
      api.getTestPlan(accessToken, route.analysisId),
      api.getDesignStates(accessToken, route.analysisId),
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
    setBriefState(null);
    setBriefErrorKey(null);
    setCasesErrorKey(null);
    setCasesNotice(null);
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
    api
      .getBrief(accessToken, route.analysisId, selected)
      .then((loaded) => {
        if (cancelled) return;
        setBriefState(loaded);
        setDrafts(loaded.cases);
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setBriefErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
        }
      });
    return () => {
      cancelled = true;
    };
  }, [accessToken, route.analysisId, selected]);

  const atDesign = analysis?.stage === 'design';
  const beforeDesign = analysis !== null && stageIndex(analysis.stage) < stageIndex('design');
  const afterDesign = analysis !== null && stageIndex(analysis.stage) > stageIndex('design');
  const canEdit = user?.role === 'developer' && atDesign;
  const functions = plan?.functions ?? [];
  const position = selected === null ? 0 : functions.findIndex((f) => keyOf(f) === keyOf(selected)) + 1;
  const approvedCount = states.filter((s) => s.approved_at !== null).length;
  const allApproved = functions.length > 0 && approvedCount === functions.length;
  const brief = briefState?.brief ?? null;
  const missing = brief === null ? [] : uncovered(brief.items, drafts);
  const shortBy = brief === null ? 0 : Math.max(0, brief.min_cases - drafts.length);
  const dirty = briefState !== null && !sameCases(drafts, briefState.cases);
  const approved = briefState !== null && briefState.approved_at !== null;
  const hasMalicious = brief !== null && brief.items.some((item) => item.kind === 'malicious');

  function applyBrief(next: BriefState): void {
    setBriefState(next);
    setDrafts(next.cases);
    if (selected !== null) {
      setStates((current) =>
        current.map((state) =>
          keyOf(state) === keyOf(selected)
            ? {
                ...state,
                cases: next.cases.length,
                approved_at: next.approved_at,
                approved_by_username: next.approved_by_username,
              }
            : state,
        ),
      );
    }
  }

  async function saveCases(): Promise<void> {
    if (accessToken === null || selected === null || briefState === null) return;
    setCasesBusy(true);
    setCasesErrorKey(null);
    setCasesNotice(null);
    try {
      const wasApproved = briefState.approved_at !== null;
      applyBrief(await api.saveCases(accessToken, route.analysisId, selected, drafts));
      setCasesNotice(wasApproved ? 'design.cases.reopened' : 'design.cases.saved');
    } catch (error) {
      setCasesErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
    } finally {
      setCasesBusy(false);
    }
  }

  async function approve(): Promise<void> {
    if (accessToken === null || selected === null) return;
    setCasesBusy(true);
    setCasesErrorKey(null);
    setCasesNotice(null);
    try {
      applyBrief(await api.approveCases(accessToken, route.analysisId, selected));
    } catch (error) {
      setCasesErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
    } finally {
      setCasesBusy(false);
    }
  }

  function updateDraft(index: number, patch: Partial<CaseDraft>): void {
    setDrafts((current) => current.map((c, i) => (i === index ? { ...c, ...patch } : c)));
  }

  function toggleCover(index: number, itemId: string): void {
    const covers = drafts[index]?.covers ?? [];
    updateDraft(index, {
      covers: covers.includes(itemId) ? covers.filter((id) => id !== itemId) : [...covers, itemId],
    });
  }

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
                    : afterDesign
                      ? t('design.nextStep.doneTitle')
                      : t('design.nextStep.designTitle', {
                          approved: approvedCount,
                          count: functions.length,
                        })}
              </b>
              <div>
                {beforeDesign
                  ? t('design.nextStep.notYetBody')
                  : afterDesign
                    ? t('design.nextStep.doneBody')
                    : t('design.nextStep.designBody')}
              </div>
            </div>
            {atDesign && user?.role === 'developer' && functions.length > 0 && (
              <AdvanceStage
                analysis={analysis}
                label={t('design.advance.label')}
                ready={allApproved}
                blockedHint={t('design.advance.blocked', {
                  approved: approvedCount,
                  count: functions.length,
                })}
                onAdvanced={(next) => {
                  // The button's arrow promises the next screen: go there.
                  setAnalysis(next);
                  onNavigate({ kind: 'tests', id: route.id, analysisId: route.analysisId });
                }}
              />
            )}
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
                <h5>{t('design.brief.title')}</h5>
                {briefErrorKey !== null && (
                  <p className="alert" role="alert">
                    {t(briefErrorKey)}
                  </p>
                )}
                {brief === null && briefErrorKey === null && (
                  <p className="hint">{t('design.brief.loading')}</p>
                )}
                {brief !== null && (
                  <ul className="brief">
                    <li>
                      <b>
                        {hasMalicious
                          ? t('design.brief.minCasesWithMalicious', { count: brief.min_cases })
                          : t('design.brief.minCases', { count: brief.min_cases })}
                      </b>
                    </li>
                    {brief.items.length === 0 && <li>{t('design.brief.none')}</li>}
                    {brief.items.map((item) => (
                      <BriefLine key={item.id} item={item} />
                    ))}
                  </ul>
                )}
              </section>
              <section className="panel">
                <h4>{t('design.cases.title')}</h4>
                <p className="desc">{t('design.cases.intro')}</p>
                {!canEdit && <p className="hint">{t('design.cases.readOnly')}</p>}
                {brief !== null && drafts.length === 0 && <p className="hint">{t('design.cases.empty')}</p>}
                {brief !== null && (
                  <ol className="caselist">
                    {drafts.map((draft, index) => (
                      <li key={index} className="caserow">
                        <div className="row tight">
                          <span className="mono">C{index + 1}</span>
                          {canEdit ? (
                            <input
                              className="input grow"
                              aria-label={t('design.cases.caseLabel', { n: index + 1 })}
                              placeholder={t('design.cases.placeholder')}
                              value={draft.title}
                              onChange={(event) => {
                                updateDraft(index, { title: event.target.value });
                              }}
                            />
                          ) : (
                            <span className="grow">{draft.title}</span>
                          )}
                          {canEdit && (
                            <button
                              type="button"
                              className="btn ghost small"
                              aria-label={t('design.cases.removeCase', { n: index + 1 })}
                              onClick={() => {
                                setDrafts((current) => current.filter((_c, i) => i !== index));
                              }}
                            >
                              {t('design.cases.remove')}
                            </button>
                          )}
                        </div>
                        <div className="covers">
                          <span className="sub">{t('design.cases.covers')}</span>
                          {brief.items.map((item) =>
                            canEdit ? (
                              <button
                                key={item.id}
                                type="button"
                                className={draft.covers.includes(item.id) ? 'chip toggle on' : 'chip toggle'}
                                aria-pressed={draft.covers.includes(item.id)}
                                onClick={() => {
                                  toggleCover(index, item.id);
                                }}
                              >
                                {item.id}
                              </button>
                            ) : (
                              draft.covers.includes(item.id) && (
                                <span key={item.id} className="chip">
                                  {item.id}
                                </span>
                              )
                            ),
                          )}
                        </div>
                      </li>
                    ))}
                  </ol>
                )}
                {brief !== null && canEdit && (
                  <>
                    <div className="actions wrap">
                      <button
                        type="button"
                        className="btn ghost"
                        disabled={casesBusy}
                        onClick={() => {
                          setDrafts((current) => [...current, { title: '', covers: [] }]);
                        }}
                      >
                        {t('design.cases.add')}
                      </button>
                      <button
                        type="button"
                        className="btn primary"
                        disabled={casesBusy || !dirty}
                        onClick={() => {
                          void saveCases();
                        }}
                      >
                        {t('design.cases.save')}
                      </button>
                    </div>
                    <p className="hint">
                      {missing.length > 0
                        ? t('design.cases.uncovered', { items: missing.join(', ') })
                        : shortBy > 0
                          ? t('design.cases.tooFew', { count: shortBy })
                          : dirty
                            ? t('design.cases.unsaved')
                            : t('design.cases.complete')}
                    </p>
                    {casesNotice !== null && <p className="hint ok">{t(casesNotice)}</p>}
                    {casesErrorKey !== null && (
                      <p className="alert" role="alert">
                        {t(casesErrorKey)}
                      </p>
                    )}
                    <div className="actions">
                      <button
                        type="button"
                        className="btn primary"
                        disabled={casesBusy || dirty || approved || missing.length > 0 || shortBy > 0}
                        onClick={() => {
                          void approve();
                        }}
                      >
                        {t('design.cases.approve')}
                      </button>
                    </div>
                    <p className="hint">{t('design.cases.approveHint', { count: drafts.length })}</p>
                  </>
                )}
                {approved && (
                  <p className="hint ok">
                    {t('design.cases.approved', { user: briefState?.approved_by_username ?? '' })}
                  </p>
                )}
              </section>
            </div>
          )}
        </>
      )}
    </AppShell>
  );
}
