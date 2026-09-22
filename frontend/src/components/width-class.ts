/**
 * Progress widths as stepped CSS classes (`w0` … `w100`, by 5).
 *
 * The app ships under `style-src 'self'` (docker/nginx.conf): an inline
 * `style` attribute is blocked, so a percentage has to become a class.
 */
export function widthClass(part: number, whole: number): string {
  if (whole <= 0 || part <= 0) return 'w0';
  const percent = Math.min(100, Math.max(0, (100 * part) / whole));
  return `w${String(Math.round(percent / 5) * 5)}`;
}
