/** Software inventory endpoints. Mirrors backend/app/inventory/router.py. */
import { apiDownload, apiFetch, apiUpload, type Download } from './client';

export interface InventoryTotals {
  projects: number;
  components: number;
  vulnerable_components: number;
  open_cves: number;
  not_affected: number;
  outdated: number;
  uncomparable: number;
  by_severity: Record<string, number>;
  capped: boolean;
}

export interface LicenseCount {
  name: string;
  count: number;
}

export interface ProjectInventoryRow {
  project_id: string;
  project_name: string;
  analysis_id: string;
  ordinal: number;
  analysed_at: string;
  components: number;
  outdated: number;
  open_cves: number;
  vulnerable_components: number;
  trend: number | null;
  previous_analysis_id: string | null;
}

export type VexState = 'exploitable' | 'not_affected' | 'in_triage';

export interface OpenCveRow {
  project_id: string;
  project_name: string;
  analysis_id: string;
  component: string;
  version: string | null;
  ecosystem: string | null;
  vulnerability_id: string;
  cve: string;
  score: number | null;
  severity: string | null;
  fixed_in: string | null;
  summary: string | null;
  vex_state: VexState;
  justification: string | null;
  verdict_by: string | null;
}

export interface CryptoRow {
  primitive: string;
  algorithm: string;
  weak: boolean;
  occurrences: number;
  path: string;
  line: number | null;
}

export interface SyncRun {
  source: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  records_stored: number;
  records_skipped: number;
  requested_by: string | null;
}

export interface VulnDbState {
  last_update: string | null;
  sync_enabled: boolean;
  interval_hours: number;
  runs: SyncRun[];
}

export interface Inventory {
  totals: InventoryTotals;
  licenses: LicenseCount[];
  unlicensed: number;
  projects: ProjectInventoryRow[];
  open: OpenCveRow[];
  crypto: CryptoRow[];
  crypto_weak: number;
  vulndb: VulnDbState;
}

export function getInventory(accessToken: string): Promise<Inventory> {
  return apiFetch<Inventory>('/inventory', { accessToken });
}

export function requestSync(accessToken: string, justification: string): Promise<void> {
  return apiFetch<void>('/inventory/vulndb/sync', {
    method: 'POST',
    accessToken,
    body: { justification },
  });
}

export function importDump(
  accessToken: string,
  file: File,
  justification: string,
): Promise<{ token: string }> {
  const form = new FormData();
  form.append('file', file, file.name);
  form.append('justification', justification);
  return apiUpload<{ token: string }>('/inventory/vulndb/import', form, accessToken);
}

export type InventoryDocument = 'sbom' | 'cbom' | 'vex' | 'csv';

export function downloadInventoryDocument(
  accessToken: string,
  analysisId: string,
  kind: InventoryDocument,
): Promise<Download> {
  const id = encodeURIComponent(analysisId);
  const path =
    kind === 'sbom'
      ? `/analyses/${id}/sbom`
      : kind === 'csv'
        ? `/inventory/analyses/${id}/components.csv`
        : `/inventory/analyses/${id}/${kind}`;
  const fallback = kind === 'csv' ? 'componentes.csv' : `${kind}.cdx.json`;
  return apiDownload(path, accessToken, fallback);
}
