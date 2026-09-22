// Real function copied verbatim from frontend/src/components/width-class.ts (2026-09-22).
// Hand-counted in tests/test_brief.py; do not edit — the numbers there depend on these lines.
export function widthClass(part: number, whole: number): string {
  if (whole <= 0 || part <= 0) return 'w0';
  const percent = Math.min(100, Math.max(0, (100 * part) / whole));
  return `w${String(Math.round(percent / 5) * 5)}`;
}
