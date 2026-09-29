/** Project, analysis and finding endpoints. Mirrors backend/app/projects/schemas.py. */
import {
  ApiError,
  apiDownload,
  apiFetch,
  apiUploadFile,
  type Download,
  type UploadProgress,
} from './client';

export type { Download };

export interface SystemProfile {
  name: string;
  framework: string | null;
  database: string | null;
  developer: string | null;
  installed_at: string | null;
}

export interface Project {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
  system: SystemProfile | null;
}

export interface ProjectCreate {
  name: string;
  description?: string;
  system: {
    name: string;
    framework?: string;
    database?: string;
    developer?: string;
    installed_at?: string;
  };
}

export type AnalysisStatus = 'queued' | 'running' | 'done' | 'failed' | 'cancelled';
export type ToolStatus = 'ran' | 'failed' | 'missing' | 'timeout';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Verdict = 'confirmed' | 'false_positive';
export type Stage =
  | 'register'
  | 'code'
  | 'analysis'
  | 'plan'
  | 'design'
  | 'tests'
  | 'verification'
  | 'report';
export type CoverageCriterion = 'statements' | 'decisions' | 'paths';

/** Stage E3 progress; `complete` is computed by the server (the gate). */
export interface Triage {
  total: number;
  confirmed: number;
  false_positive: number;
  pending: number;
  complete: boolean;
}

export interface ToolRun {
  tool: string;
  category: string;
  status: ToolStatus;
  detail: string | null;
  duration_ms: number | null;
}

/**
 * Where a running analysis is: the step's name and its place among the
 * pipeline's steps. It counts steps, not time — one tool is most of a run.
 */
export interface AnalysisProgress {
  step: string;
  index: number;
  total: number;
}

export interface Analysis {
  id: string;
  project_id: string;
  source_kind: 'zip' | 'git';
  source_ref: string;
  status: AnalysisStatus;
  failure_code: string | null;
  /** Workflow stage; only the server moves it (POST …/stage/advance). */
  stage: Stage;
  languages: Record<string, number>;
  frameworks: string[];
  lockfiles: string[];
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  /** Only while running: the pipeline step the worker is on (phase 10). */
  progress: AnalysisProgress | null;
  /** A person asked this running analysis to stop; its worker is on it (phase 12). */
  cancel_requested: boolean;
  /** Who sent the code; they and an admin may cancel (the server decides). */
  created_by_id: string | null;
  /** Every finding by severity, verdicts ignored. */
  finding_counts: Partial<Record<Severity, number>>;
  /** What the report prints: false positives left out. */
  report_counts: Partial<Record<Severity, number>>;
  tool_runs: ToolRun[];
  triage: Triage;
}

export interface Finding {
  id: string;
  ordinal: number;
  category: string;
  tools: string[];
  rule_id: string;
  cwe: number | null;
  owasp: string | null;
  title: string;
  severity: Severity;
  cvss_score: number | null;
  path: string;
  line: number | null;
  snippet: string | null;
  message: string | null;
  references: string[];
  /** Institutional prose for the CWE — the text the report prints. */
  description: string;
  impact: string;
  mitigation: string[];
  /** In a dependency directory: shown and reported, but not the analyst's to
   *  adjudicate — the E3 gate never waits for it and the server refuses a
   *  verdict on it (`finding_not_triageable`). */
  third_party: boolean;
  verdict: Verdict | null;
  verdict_justification: string | null;
  verdict_by_username: string | null;
  verdict_at: string | null;
}

export type ReportFormat = 'pdf' | 'html' | 'md' | 'docx';

export interface RiskRow {
  path: string;
  function: string;
  line: number | null;
  ccn: number;
  nloc: number;
  findings: number;
  max_severity: Severity | null;
  score: number;
  level: 'high' | 'medium' | 'low';
}

export interface PlannedFunction {
  path: string;
  function: string;
  line: number | null;
  ccn?: number;
}

export interface FlowNode {
  id: string;
  kind: 'start' | 'end' | 'process' | 'decision' | 'loop' | 'return' | 'throw';
  label: string;
  line: number | null;
}

export interface FlowEdge {
  source: string;
  target: string;
  label: string;
}

export interface PlacedNode extends FlowNode {
  x: number;
  y: number;
  width: number;
  height: number;
  /** The label wrapped by the server to fit its shape (`diagrams.label_lines`). */
  lines: string[];
}

export interface PlacedEdge extends FlowEdge {
  points: [number, number][];
  back: boolean;
}

export interface Diagram {
  path: string;
  function: string;
  line: number | null;
  language: string;
  complexity: number;
  /** Interchange / editing format; the picture is drawn from `layout`. */
  mermaid: string;
  graph: { name: string; params: string[]; nodes: FlowNode[]; edges: FlowEdge[] };
  layout: { width: number; height: number; nodes: PlacedNode[]; edges: PlacedEdge[] };
  edited_text: string | null;
  edited_by_username: string | null;
  edited_at: string | null;
}

export interface BriefItem {
  id: string;
  kind: 'branch' | 'boundary' | 'error' | 'malicious';
  line: number | null;
  /** Source text or finding title — hostile, rendered as text. */
  text: string;
  /** branch: edge label; error: throw | handler | early_return; malicious: rule id. */
  detail: string;
  values: string[];
  finding_id: string | null;
}

export interface Brief {
  function: string;
  path: string;
  line: number;
  language: string;
  params: string[];
  complexity: number;
  min_cases: number;
  items: BriefItem[];
}

export interface CaseDraft {
  title: string;
  covers: string[];
}

export interface BriefState {
  brief: Brief;
  cases: CaseDraft[];
  approved_at: string | null;
  approved_by_username: string | null;
}

export interface DesignState {
  path: string;
  function: string;
  line: number | null;
  cases: number;
  approved_at: string | null;
  approved_by_username: string | null;
}

export interface TestPlan {
  analysis_id: string;
  criterion: CoverageCriterion;
  rationale: string;
  functions: PlannedFunction[];
  created_by_username: string;
  created_at: string;
  updated_at: string;
}

export interface ReportVersion {
  number: number;
  change_summary: string;
  areas: string;
  created_by_username: string;
  created_at: string;
  signed_by_username: string | null;
  signed_at: string | null;
  /** Findings frozen out of a signed version; null on a draft. */
  excluded_findings: string[] | null;
  content_hash: string | null;
}

export interface ReportSection {
  key: string;
  label: string;
  text: string;
  edited: boolean;
}

export interface ReportState {
  number: number;
  persisted: boolean;
  signed: boolean;
  sections: ReportSection[];
  versions: ReportVersion[];
}

export function listProjects(accessToken: string): Promise<Project[]> {
  return apiFetch<Project[]>('/projects', { accessToken });
}

export function getProject(accessToken: string, id: string): Promise<Project> {
  return apiFetch<Project>(`/projects/${encodeURIComponent(id)}`, { accessToken });
}

export function createProject(accessToken: string, payload: ProjectCreate): Promise<Project> {
  return apiFetch<Project>('/projects', { method: 'POST', accessToken, body: payload });
}

export function listAnalyses(accessToken: string, projectId: string): Promise<Analysis[]> {
  return apiFetch<Analysis[]>(`/projects/${encodeURIComponent(projectId)}/analyses`, {
    accessToken,
  });
}

export function getAnalysis(accessToken: string, id: string): Promise<Analysis> {
  return apiFetch<Analysis>(`/analyses/${encodeURIComponent(id)}`, { accessToken });
}

/** Cancel a queued analysis, or ask a running one to stop (phase 12). No reason. */
export function cancelAnalysis(accessToken: string, analysisId: string): Promise<Analysis> {
  return apiFetch<Analysis>(`/analyses/${encodeURIComponent(analysisId)}/cancel`, {
    method: 'POST',
    accessToken,
  });
}

export function listFindings(accessToken: string, analysisId: string): Promise<Finding[]> {
  return apiFetch<Finding[]>(`/analyses/${encodeURIComponent(analysisId)}/findings`, {
    accessToken,
  });
}

/**
 * Stage E2 from a ZIP: the archive is the raw body and its name a query
 * parameter (phase 10 — the server streams it to disk after checking the
 * session, and the worker extracts it). A header could not carry a name with
 * accents; the query string can.
 */
export function ingestZip(
  accessToken: string,
  projectId: string,
  file: File,
  onProgress?: UploadProgress,
): Promise<Analysis> {
  const name = encodeURIComponent(file.name);
  return apiUploadFile<Analysis>(
    `/projects/${encodeURIComponent(projectId)}/ingest?filename=${name}`,
    file,
    accessToken,
    onProgress,
  );
}

export function ingestGit(accessToken: string, projectId: string, url: string): Promise<Analysis> {
  return apiFetch<Analysis>(`/projects/${encodeURIComponent(projectId)}/ingest/git`, {
    method: 'POST',
    accessToken,
    body: { url },
  });
}

export function postVerdict(
  accessToken: string,
  findingId: string,
  verdict: Verdict,
  justification: string,
): Promise<Finding> {
  return apiFetch<Finding>(`/findings/${encodeURIComponent(findingId)}/verdict`, {
    method: 'POST',
    accessToken,
    body: { verdict, justification },
  });
}

export function advanceStage(
  accessToken: string,
  analysisId: string,
  justification: string,
): Promise<Analysis> {
  return apiFetch<Analysis>(`/analyses/${encodeURIComponent(analysisId)}/stage/advance`, {
    method: 'POST',
    accessToken,
    body: { justification },
  });
}

export interface RiskMatrix {
  rows: RiskRow[];
  /** How many functions matched BEFORE the cap: the screen has to be able to
   *  say "200 de 5000". On a real Laravel tree the 200 highest-scoring were all
   *  hand-vendored JavaScript and the developer could reach none of their own
   *  code, with nothing on screen saying so (phase-7a walk, 2026-09-23). */
  total: number;
  /** The filter the server applied, normalised. */
  query: string;
}

/** The ranked rows AND what the cap left out — see `RiskMatrix`. */
export function getRiskMatrix(
  accessToken: string,
  analysisId: string,
  query?: string,
): Promise<RiskMatrix> {
  const search = query ? `?q=${encodeURIComponent(query)}` : '';
  return apiFetch<RiskMatrix>(
    `/analyses/${encodeURIComponent(analysisId)}/risk-matrix${search}`,
    { accessToken },
  );
}

/** Resolves null when no plan exists yet (404 is a state here, not an error). */
export async function getTestPlan(accessToken: string, analysisId: string): Promise<TestPlan | null> {
  try {
    return await apiFetch<TestPlan>(`/analyses/${encodeURIComponent(analysisId)}/test-plan`, {
      accessToken,
    });
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null;
    throw error;
  }
}

export function saveTestPlan(
  accessToken: string,
  analysisId: string,
  plan: { criterion: CoverageCriterion; rationale: string; functions: PlannedFunction[] },
): Promise<TestPlan> {
  return apiFetch<TestPlan>(`/analyses/${encodeURIComponent(analysisId)}/test-plan`, {
    method: 'PUT',
    accessToken,
    body: plan,
  });
}

export function getDiagram(
  accessToken: string,
  analysisId: string,
  ref: PlannedFunction,
): Promise<Diagram> {
  const query = new URLSearchParams({ path: ref.path, function: ref.function });
  if (ref.line !== null) query.set('line', String(ref.line));
  return apiFetch<Diagram>(
    `/analyses/${encodeURIComponent(analysisId)}/diagram?${query.toString()}`,
    { accessToken },
  );
}

export function saveDiagramText(
  accessToken: string,
  analysisId: string,
  ref: PlannedFunction,
  text: string,
): Promise<Diagram> {
  return apiFetch<Diagram>(`/analyses/${encodeURIComponent(analysisId)}/diagram`, {
    method: 'PUT',
    accessToken,
    body: { path: ref.path, function: ref.function, line: ref.line, text },
  });
}

export function getBrief(
  accessToken: string,
  analysisId: string,
  ref: PlannedFunction,
): Promise<BriefState> {
  const query = new URLSearchParams({ path: ref.path, function: ref.function });
  if (ref.line !== null) query.set('line', String(ref.line));
  return apiFetch<BriefState>(
    `/analyses/${encodeURIComponent(analysisId)}/brief?${query.toString()}`,
    { accessToken },
  );
}

export function getDesignStates(accessToken: string, analysisId: string): Promise<DesignState[]> {
  return apiFetch<DesignState[]>(`/analyses/${encodeURIComponent(analysisId)}/case-designs`, {
    accessToken,
  });
}

export function saveCases(
  accessToken: string,
  analysisId: string,
  ref: PlannedFunction,
  cases: CaseDraft[],
): Promise<BriefState> {
  return apiFetch<BriefState>(`/analyses/${encodeURIComponent(analysisId)}/cases`, {
    method: 'PUT',
    accessToken,
    body: { path: ref.path, function: ref.function, line: ref.line, cases },
  });
}

export function approveCases(
  accessToken: string,
  analysisId: string,
  ref: PlannedFunction,
): Promise<BriefState> {
  return apiFetch<BriefState>(`/analyses/${encodeURIComponent(analysisId)}/cases/approve`, {
    method: 'POST',
    accessToken,
    body: { path: ref.path, function: ref.function, line: ref.line },
  });
}

export interface ScaffoldCase {
  id: string;
  title: string;
  covers: string[];
  written: boolean;
}

export interface Scaffold {
  path: string;
  function: string;
  line: number | null;
  language: string;
  runner: string;
  filename: string;
  scaffold: string;
  content: string;
  stored_at: string | null;
  stored_by_username: string | null;
  parse_error: boolean;
  cases: ScaffoldCase[];
}

export interface WritingState extends PlannedFunction {
  cases: number;
  written: number;
  parse_error: boolean;
}

export function getScaffold(
  accessToken: string,
  analysisId: string,
  ref: PlannedFunction,
): Promise<Scaffold> {
  const query = new URLSearchParams({ path: ref.path, function: ref.function });
  if (ref.line !== null) query.set('line', String(ref.line));
  return apiFetch<Scaffold>(
    `/analyses/${encodeURIComponent(analysisId)}/scaffold?${query.toString()}`,
    { accessToken },
  );
}

export function saveTests(
  accessToken: string,
  analysisId: string,
  ref: PlannedFunction,
  content: string,
): Promise<Scaffold> {
  return apiFetch<Scaffold>(`/analyses/${encodeURIComponent(analysisId)}/tests`, {
    method: 'PUT',
    accessToken,
    body: { path: ref.path, function: ref.function, line: ref.line, content },
  });
}

export function getWritingStates(
  accessToken: string,
  analysisId: string,
): Promise<WritingState[]> {
  return apiFetch<WritingState[]>(`/analyses/${encodeURIComponent(analysisId)}/test-files`, {
    accessToken,
  });
}

export interface VerificationRun extends PlannedFunction {
  status: 'passed' | 'failed' | 'errored';
  reasons: string[];
  coverage: {
    statement_percent?: number;
    branch_percent?: number;
    missing_lines?: number[];
    partial_branch_lines?: number[];
    covered_branches?: number;
    total_branches?: number;
    /** The lines the E4 criterion was judged over — the planned function's own.
     *  The percentages above are the whole module's, so a surface that prints
     *  one must be able to say which. `null` when the span could not be
     *  resolved and the whole module was judged (the stricter fallback). */
    criterion_lines?: [number, number] | null;
  };
  uncovered_items: string[];
  surviving_mutants: { id: string; line: string; mutant: string }[];
  /** Survivors the developer excused as equivalent before this run. */
  equivalent_mutants: { id: string; line: string; mutant: string }[];
  assertion_free_cases: string[];
  failed_cases: string[];
  /**
   * False when the mutation tool could never have produced a mutant for this
   * function (a free PHP function under Infection, which only mutates code
   * inside a class). The screen says so: an empty survivor list then means
   * "not measured", not "nothing survived".
   */
  mutation_measured: boolean;
  detail: string | null;
  duration_ms: number;
  created_by_username: string;
  created_at: string;
}

export function getVerification(
  accessToken: string,
  analysisId: string,
): Promise<VerificationRun[]> {
  return apiFetch<VerificationRun[]>(`/analyses/${encodeURIComponent(analysisId)}/verification`, {
    accessToken,
  });
}

export function startVerification(accessToken: string, analysisId: string): Promise<Analysis> {
  return apiFetch<Analysis>(`/analyses/${encodeURIComponent(analysisId)}/verify`, {
    method: 'POST',
    accessToken,
    body: {},
  });
}

export function reopenDesign(
  accessToken: string,
  analysisId: string,
  justification: string,
): Promise<VerificationRun[]> {
  return apiFetch<VerificationRun[]>(`/analyses/${encodeURIComponent(analysisId)}/reopen-design`, {
    method: 'POST',
    accessToken,
    body: { justification },
  });
}

export function markMutantEquivalent(
  accessToken: string,
  analysisId: string,
  ref: PlannedFunction,
  mutantId: string,
  justification: string,
): Promise<VerificationRun[]> {
  return apiFetch<VerificationRun[]>(`/analyses/${encodeURIComponent(analysisId)}/mutants/equivalent`, {
    method: 'POST',
    accessToken,
    body: {
      path: ref.path,
      function: ref.function,
      line: ref.line,
      mutant_id: mutantId,
      justification,
    },
  });
}

export function getReportState(accessToken: string, analysisId: string): Promise<ReportState> {
  return apiFetch<ReportState>(`/analyses/${encodeURIComponent(analysisId)}/report/current`, {
    accessToken,
  });
}

export function saveReportSections(
  accessToken: string,
  analysisId: string,
  sections: Record<string, string>,
  changeSummary: string,
): Promise<ReportState> {
  return apiFetch<ReportState>(`/analyses/${encodeURIComponent(analysisId)}/report/sections`, {
    method: 'PUT',
    accessToken,
    body: { sections, change_summary: changeSummary },
  });
}

export function signReportVersion(
  accessToken: string,
  analysisId: string,
  number: number,
  justification: string,
): Promise<ReportState> {
  return apiFetch<ReportState>(
    `/analyses/${encodeURIComponent(analysisId)}/report/versions/${String(number)}/sign`,
    { method: 'POST', accessToken, body: { justification } },
  );
}

export function downloadReport(
  accessToken: string,
  analysisId: string,
  format: ReportFormat,
  version?: number,
): Promise<Download> {
  const query = version === undefined ? '' : `&version=${String(version)}`;
  return apiDownload(
    `/analyses/${encodeURIComponent(analysisId)}/report?format=${format}${query}`,
    accessToken,
    `reporte.${format}`,
  );
}

export function downloadSbom(accessToken: string, analysisId: string): Promise<Download> {
  return apiDownload(`/analyses/${encodeURIComponent(analysisId)}/sbom`, accessToken, 'sbom.cdx.json');
}

/** Hands a fetched file to the browser. No-op where object URLs do not exist (tests). */
export function saveDownload(download: Download): void {
  if (typeof URL.createObjectURL !== 'function') return;
  const url = URL.createObjectURL(download.blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = download.filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
