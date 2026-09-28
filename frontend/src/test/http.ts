/** Fetch stub: routes are declared per test, anything else is a hard failure. */
import { vi } from 'vitest';

export interface StubResponse {
  status: number;
  body?: unknown;
}

export type Routes = Record<string, StubResponse | (() => StubResponse | Promise<StubResponse>)>;

/**
 * Requests every authenticated screen makes whatever the test is about: the
 * report-job provider asks, once, whether the person has a PDF in flight
 * (phase 8). A test that cares declares the route itself and wins.
 */
const AMBIENT: Routes = {
  '/api/v1/report-jobs/mine': { status: 200, body: null },
};

export function stubFetch(routes: Routes) {
  const calls = vi.fn((input: RequestInfo | URL, _init?: RequestInit) => {
    const path = String(input);
    // Looked up, never spread: some tests pass a Proxy whose `get` matches by
    // prefix, and spreading one copies nothing.
    const route = routes[path] ?? AMBIENT[path];
    if (route === undefined) {
      throw new Error(`unstubbed request: ${path}`);
    }
    // A route may answer later (a Promise): a test holds a request open to
    // look at the screen while it is in flight (the ZIP upload's bar).
    return Promise.resolve(typeof route === 'function' ? route() : route).then(
      ({ status, body }) =>
        new Response(body === undefined ? null : JSON.stringify(body), {
          status,
          headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
        }),
    );
  });
  vi.stubGlobal('fetch', calls);
  vi.stubGlobal('XMLHttpRequest', fakeXhrOver(calls));
  return calls;
}

/**
 * XMLHttpRequest over the same route table (phase 10: the ZIP upload uses XHR
 * for its progress events). Every request is also recorded on `calls`, with
 * the query string, so a test sees one log whichever API the screen used.
 * The upload reports two progress events — half, then all — before the answer.
 */
function fakeXhrOver(calls: (input: string, init?: RequestInit) => Promise<Response>) {
  return class FakeXhr {
    status = 0;
    responseText = '';
    onload: (() => void) | null = null;
    onerror: (() => void) | null = null;
    onabort: (() => void) | null = null;
    readonly upload: { onprogress: ((event: ProgressEvent) => void) | null } = {
      onprogress: null,
    };
    readonly headers: Record<string, string> = {};
    private method = 'GET';
    private url = '';

    open(method: string, url: string): void {
      this.method = method;
      this.url = url;
    }

    setRequestHeader(name: string, value: string): void {
      this.headers[name] = value;
    }

    send(body: Blob | null): void {
      const total = body?.size ?? 0;
      const progress = (loaded: number) => {
        this.upload.onprogress?.({ lengthComputable: true, loaded, total } as ProgressEvent);
      };
      void (async () => {
        progress(Math.floor(total / 2));
        progress(total);
        let response: Response;
        try {
          const path = this.url.split('?', 1)[0] ?? this.url;
          // The full URL rides along so a test can check the query string.
          response = await calls(path, {
            method: this.method,
            headers: this.headers,
            body,
            url: this.url,
          } as RequestInit);
        } catch {
          this.onerror?.();
          return;
        }
        this.status = response.status;
        this.responseText = await response.text();
        this.onload?.();
      })();
    }
  };
}

export const NO_SESSION: StubResponse = {
  status: 401,
  body: { code: 'invalid_token', message_key: 'errors.auth.invalidToken' },
};
