/**
 * Which role may open which screen — the ONE map the tabs bar and the router
 * read (phase 6, decision 5). It mirrors docs/roles-and-permissions.md; it
 * does not rewrite it.
 *
 * This is presentation, never enforcement: every endpoint behind these screens
 * refuses the same roles on the server, and the backend tests prove it with no
 * UI in the loop. What the map buys is that a role never sees a tab it cannot
 * use, and a forbidden hash shows a plain refusal instead of a screen that
 * would only collect 403s.
 *
 * Typed as a Record over every route kind ON PURPOSE: a new route that has not
 * decided its roles does not compile. Every kind but `users` lists the three
 * roles because the matrix's "view" rows are deliberate (the developer needs
 * the findings, the analyst and the admin the plan and the tests they judge).
 */
import type { Role } from '../api/auth';
import type { Route } from './use-route';

const EVERYONE: readonly Role[] = ['admin', 'analyst', 'developer'];

export const ROUTE_ROLES: Record<Route['kind'], readonly Role[]> = {
  home: EVERYONE,
  projects: EVERYONE,
  project: EVERYONE,
  findings: EVERYONE,
  plan: EVERYONE,
  design: EVERYONE,
  tests: EVERYONE,
  verify: EVERYONE,
  report: EVERYONE,
  inventory: EVERYONE,
  audit: EVERYONE,
  users: ['admin'],
};

export function mayOpen(kind: Route['kind'], role: Role): boolean {
  return ROUTE_ROLES[kind].includes(role);
}
