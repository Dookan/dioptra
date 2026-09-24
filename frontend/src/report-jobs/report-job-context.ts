/** The one PDF job a person may have in flight, shared by every screen. */
import { createContext, useContext } from 'react';

import type { ReportJob } from '../api/report-jobs';

export interface ReportJobState {
  /** The job being followed, or null when there is none. */
  job: ReportJob | null;
  /** True while a PDF of this person is queued, running or downloading. */
  busy: boolean;
  /** i18n key of the last refusal or failure, shown in the toast. */
  errorKey: string | null;
  /** Start a PDF export. Resolves false when the server refused it. */
  start: (analysisId: string, version?: number) => Promise<boolean>;
  /** Close a finished or failed toast. Not offered while the job runs. */
  dismiss: () => void;
}

export const ReportJobContext = createContext<ReportJobState | null>(null);

export function useReportJobs(): ReportJobState {
  const state = useContext(ReportJobContext);
  if (state === null) {
    throw new Error('useReportJobs must be used inside <ReportJobProvider>');
  }
  return state;
}
