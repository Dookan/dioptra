/** Analysis / severity / tool status badges, colored through tokens only. */
import { useTranslation } from 'react-i18next';

import type { AnalysisStatus, Severity, ToolStatus } from '../api/projects';

const ANALYSIS_TONE: Record<AnalysisStatus, string> = {
  queued: 'info',
  running: 'warn',
  done: 'ok',
  failed: 'err',
};

const SEVERITY_TONE: Record<Severity, string> = {
  critical: 'err',
  high: 'err',
  medium: 'warn',
  low: 'info',
  info: 'info',
};

const TOOL_TONE: Record<ToolStatus, string> = {
  ran: 'ok',
  failed: 'err',
  missing: 'warn',
  timeout: 'err',
};

export function StatusBadge({ status }: { status: AnalysisStatus }): React.ReactNode {
  const { t } = useTranslation();
  return <span className={`badge ${ANALYSIS_TONE[status]}`}>{t(`analysis.status.${status}`)}</span>;
}

export function SeverityBadge({ severity }: { severity: Severity }): React.ReactNode {
  const { t } = useTranslation();
  return <span className={`badge ${SEVERITY_TONE[severity]}`}>{t(`severity.${severity}`)}</span>;
}

export function ToolBadge({ status }: { status: ToolStatus }): React.ReactNode {
  const { t } = useTranslation();
  return <span className={`badge ${TOOL_TONE[status]}`}>{t(`analysis.tool.${status}`)}</span>;
}
