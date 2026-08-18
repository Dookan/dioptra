/** Fetch stub: routes are declared per test, anything else is a hard failure. */
import { vi } from 'vitest';

export interface StubResponse {
  status: number;
  body?: unknown;
}

export type Routes = Record<string, StubResponse | (() => StubResponse)>;

export function stubFetch(routes: Routes) {
  const calls = vi.fn((input: RequestInfo | URL) => {
    const path = String(input);
    const route = routes[path];
    if (route === undefined) {
      throw new Error(`unstubbed request: ${path}`);
    }
    const { status, body } = typeof route === 'function' ? route() : route;
    return Promise.resolve(
      new Response(body === undefined ? null : JSON.stringify(body), {
        status,
        headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      }),
    );
  });
  vi.stubGlobal('fetch', calls);
  return calls;
}

export const NO_SESSION: StubResponse = {
  status: 401,
  body: { code: 'invalid_token', message_key: 'errors.auth.invalidToken' },
};
