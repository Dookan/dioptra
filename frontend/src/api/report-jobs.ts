/**
 * Asynchronous PDF export (phase 8, tasks/phase8-survey.md).
 *
 * The server renders a PDF in its worker; the screen starts a job, polls it
 * and downloads the file once it is ready. HTML, Markdown and DOCX stay
 * synchronous (`downloadReport` in ./projects).
 */
import { apiDownload, apiFetch, type Download } from './client';

export type ReportJobStatus = 'queued' | 'running' | 'done' | 'errored' | 'expired';

export interface ReportJob {
  id: string;
  analysis_id: string;
  version: number | null;
  format: string;
  status: ReportJobStatus;
  requested_by_username: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  byte_size: number | null;
  /** A machine code (`render_failed`, `spool_full`, `abandoned`…), never copy. */
  detail: string | null;
  /** In-flight jobs requested before this one; 0 unless queued. */
  ahead: number;
  elapsed_seconds: number;
}

export function startReportJob(
  accessToken: string,
  analysisId: string,
  version?: number,
): Promise<ReportJob> {
  return apiFetch<ReportJob>(`/analyses/${encodeURIComponent(analysisId)}/report/jobs`, {
    method: 'POST',
    accessToken,
    body: version === undefined ? {} : { version },
  });
}

export function getReportJob(accessToken: string, jobId: string): Promise<ReportJob> {
  return apiFetch<ReportJob>(`/report-jobs/${encodeURIComponent(jobId)}`, { accessToken });
}

/** The caller's newest job worth showing after a reload, or null. */
export function getMyReportJob(accessToken: string): Promise<ReportJob | null> {
  return apiFetch<ReportJob | null>('/report-jobs/mine', { accessToken });
}

export function downloadReportJob(accessToken: string, jobId: string): Promise<Download> {
  return apiDownload(
    `/report-jobs/${encodeURIComponent(jobId)}/download`,
    accessToken,
    'reporte.pdf',
  );
}
