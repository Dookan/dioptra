/** Avatar initials: two letters from the display name (docs/ui-model.md → Rules). */
export function initials(displayName: string): string {
  return displayName
    .split(' ')
    .slice(0, 2)
    .map((part) => part.charAt(0).toUpperCase())
    .join('');
}
