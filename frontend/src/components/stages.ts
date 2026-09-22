/** Workflow stages in order. Names, never E-codes (docs/ui-model.md → principle 1). */
export const STAGES = [
  'register',
  'code',
  'analysis',
  'plan',
  'design',
  'tests',
  'verification',
  'report',
] as const;

export type Stage = (typeof STAGES)[number];

/** Position of a stage (0-based); unknown names fall back to the first stage. */
export function stageIndex(stage: string): number {
  const index = STAGES.indexOf(stage as Stage);
  return index < 0 ? 0 : index;
}
