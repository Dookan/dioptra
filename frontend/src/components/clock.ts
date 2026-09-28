/** Elapsed seconds as `m:ss` — the toast's clock and the analysis progress (phase 10). */
export function clock(seconds: number): string {
  const whole = Math.max(0, Math.floor(seconds));
  const minutes = Math.floor(whole / 60);
  return `${String(minutes)}:${String(whole % 60).padStart(2, '0')}`;
}
