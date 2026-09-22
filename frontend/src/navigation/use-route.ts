/**
 * Hash routing without a router dependency.
 *
 * Phase 1 has three destinations; a routing library would be a new dependency
 * (license + rationale) for a switch statement. The hash keeps the project
 * screen bookmarkable and survives a reload. Revisit when the workflow screens
 * of P3 need nested routes.
 */
import { useCallback, useEffect, useState } from 'react';

export type Route = { kind: 'home' } | { kind: 'projects' } | { kind: 'project'; id: string };

const PROJECT = /^#\/projects\/([A-Za-z0-9-]+)$/;

export function parseHash(hash: string): Route {
  if (hash === '#/projects') return { kind: 'projects' };
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
