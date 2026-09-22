/** Stage names → positions; an unknown name never yields -1 (it would break the stepper). */
import { describe, expect, it } from 'vitest';

import { STAGES, stageIndex } from './stages';

describe('stageIndex', () => {
  it('maps every stage name to its position', () => {
    expect(stageIndex('register')).toBe(0);
    expect(stageIndex('plan')).toBe(3);
    expect(stageIndex('report')).toBe(STAGES.length - 1);
  });

  it('falls back to the first stage for an unknown name', () => {
    expect(stageIndex('nonsense')).toBe(0);
    expect(stageIndex('')).toBe(0);
  });
});
