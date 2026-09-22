/**
 * Hash routing without a router dependency.
 *
 * Five destinations; a routing library would be a new dependency (license +
 * rationale) for a switch statement. The hash keeps every screen bookmarkable
 * and survives a reload. Revisit when the workflow screens of P3 need nested
 * routes.
 */
import { useCallback, useEffect, useState } from 'react';

export type Route =
  | { kind: 'home' }
  | { kind: 'projects' }
  | { kind: 'project'; id: string }
  | { kind: 'findings'; id: string; analysisId: string }
  | { kind: 'plan'; id: string; analysisId: string }
  | { kind: 'design'; id: string; analysisId: string }
  | { kind: 'report'; id: string; analysisId: string };

export type AnalysisRoute = Extract<Route, { analysisId: string }>;

const PROJECT = /^#\/projects\/([A-Za-z0-9-]+)$/;
const ANALYSIS =
  /^#\/projects\/([A-Za-z0-9-]+)\/analyses\/([A-Za-z0-9-]+)\/(findings|plan|design|report)$/;

const ANALYSIS_KINDS: Record<string, 'findings' | 'plan' | 'design' | 'report'> = {
  findings: 'findings',
  plan: 'plan',
  design: 'design',
  report: 'report',
};

export function parseHash(hash: string): Route {
  if (hash === '#/projects') return { kind: 'projects' };
  const nested = ANALYSIS.exec(hash);
  if (nested?.[1] !== undefined && nested[2] !== undefined) {
    const kind = ANALYSIS_KINDS[nested[3] ?? ''] ?? 'findings';
    return { kind, id: nested[1], analysisId: nested[2] };
  }
  const match = PROJECT.exec(hash);
  if (match?.[1] !== undefined) return { kind: 'project', id: match[1] };
  return { kind: 'home' };
}

export function hrefFor(route: Route): string {
  switch (route.kind) {
    case 'home':
      return '#/';
    case 'projects':
      return '#/projects';
    case 'project':
      return `#/projects/${route.id}`;
    case 'findings':
    case 'plan':
    case 'design':
    case 'report':
      return `#/projects/${route.id}/analyses/${route.analysisId}/${route.kind}`;
  }
}

export function useRoute(): { route: Route; navigate: (route: Route) => void } {
  const [route, setRoute] = useState<Route>(() => parseHash(globalThis.location?.hash ?? ''));

  useEffect(() => {
    const onChange = (): void => {
      setRoute(parseHash(globalThis.location.hash));
    };
    globalThis.addEventListener('hashchange', onChange);
    return () => {
      globalThis.removeEventListener('hashchange', onChange);
    };
  }, []);

  const navigate = useCallback((next: Route) => {
    globalThis.location.hash = hrefFor(next);
    setRoute(next);
  }, []);

  return { route, navigate };
}
