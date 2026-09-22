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
  finding_counts: Partial<Record<Severity, number>>;
  tool_runs: ToolRun[];
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
}

export type ReportFormat = 'pdf' | 'html' | 'md' | 'docx';

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

export function downloadReport(
  accessToken: string,
  analysisId: string,
  format: ReportFormat,
): Promise<Download> {
  return apiDownload(
    `/analyses/${encodeURIComponent(analysisId)}/report?format=${format}`,
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
