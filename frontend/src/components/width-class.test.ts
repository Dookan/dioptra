/** Stepped width classes: never NaN, never outside w0…w100, always a multiple of 5. */
import { describe, expect, it } from 'vitest';

import { widthClass } from './width-class';

describe('widthClass', () => {
  it('handles empty and negative inputs without NaN', () => {
    expect(widthClass(0, 0)).toBe('w0');
    expect(widthClass(1, 0)).toBe('w0');
    expect(widthClass(-1, 5)).toBe('w0');
    expect(widthClass(0, 7)).toBe('w0');
  });

  it('rounds to the nearest five percent and clamps at 100', () => {
    expect(widthClass(1, 2)).toBe('w50');
    expect(widthClass(2, 3)).toBe('w65');
    expect(widthClass(1, 3)).toBe('w35');
    expect(widthClass(5, 2)).toBe('w100');
    expect(widthClass(7, 7)).toBe('w100');
  });
});
