/** Project, analysis and finding endpoints. Mirrors backend/app/projects/schemas.py. */
import { apiDownload, apiFetch, apiUpload, type Download } from './client';

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

export type AnalysisStatus = 'queued' | 'running' | 'done' | 'failed';
export type ToolStatus = 'ran' | 'failed' | 'missing' | 'timeout';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Verdict = 'confirmed' | 'false_positive';

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

export interface Analysis {
  id: string;
  project_id: string;
  source_kind: 'zip' | 'git';
  source_ref: string;
  status: AnalysisStatus;
  failure_code: string | null;
  languages: Record<string, number>;
  frameworks: string[];
  lockfiles: string[];
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
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
  verdict: Verdict | null;
  verdict_justification: string | null;
  verdict_by_username: string | null;
  verdict_at: string | null;
}

export type ReportFormat = 'pdf' | 'html' | 'md' | 'docx';

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

export function listFindings(accessToken: string, analysisId: string): Promise<Finding[]> {
  return apiFetch<Finding[]>(`/analyses/${encodeURIComponent(analysisId)}/findings`, {
    accessToken,
  });
}

export function ingestZip(accessToken: string, projectId: string, file: File): Promise<Analysis> {
  const form = new FormData();
  form.append('file', file, file.name);
  return apiUpload<Analysis>(`/projects/${encodeURIComponent(projectId)}/ingest`, form, accessToken);
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
