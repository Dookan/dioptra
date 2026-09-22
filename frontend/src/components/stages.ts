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
