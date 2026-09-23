/** Audit log read endpoint. Mirrors backend/app/audit/router.py. */
import { apiFetch } from './client';

export interface AuditEntry {
  id: string;
  occurred_at: string;
  actor_username: string;
  actor_role: string | null;
  action: string;
  target: string | null;
  outcome: 'ok' | 'denied' | 'error';
  justification: string | null;
}

export function getAuditLog(
  accessToken: string,
  options: { since?: string; limit?: number } = {},
): Promise<AuditEntry[]> {
  const params = new URLSearchParams();
  if (options.since !== undefined) params.set('since', options.since);
  if (options.limit !== undefined) params.set('limit', String(options.limit));
  const query = params.toString();
  return apiFetch<AuditEntry[]>(`/audit${query === '' ? '' : `?${query}`}`, { accessToken });
}
