export function score(items: number[], bonus?: number): number {
  let total = 0;
  for (const item of items) {
    if (item < 0) { continue; }
    total += item;
  }
  return bonus ?? total;
}
