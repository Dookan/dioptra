/**
 * Thin fetch wrapper around the platform API.
 *
 * The backend answers every failure with `{code, message_key}` — a stable i18n
 * key, never display copy — so the UI decides the wording and the language.
 */

export const API_BASE = '/api/v1';

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly messageKey: string;

  constructor(status: number, code: string, messageKey: string, options?: ErrorOptions) {
    super(`${String(status)} ${code}`, options);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.messageKey = messageKey;
  }
}

interface ErrorBody {
  code?: unknown;
  message_key?: unknown;
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  body?: unknown;
  accessToken?: string | null;
  signal?: AbortSignal;
}

export async function apiFetch<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, accessToken, signal } = options;
  const headers = new Headers();
  if (body !== undefined) headers.set('Content-Type', 'application/json');
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`);

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      // The refresh token is an HttpOnly cookie; it must ride along.
      credentials: 'same-origin',
      signal,
    });
  } catch (cause) {
    throw new ApiError(0, 'network_unreachable', 'errors.network', { cause });
  }

  if (!response.ok) {
    throw new ApiError(response.status, ...(await readErrorBody(response)));
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

async function readErrorBody(response: Response): Promise<[string, string]> {
  try {
    const body = (await response.json()) as ErrorBody;
    if (typeof body.code === 'string' && typeof body.message_key === 'string') {
      return [body.code, body.message_key];
    }
  } catch {
    // A non-JSON body means something other than the API answered (a proxy,
    // a gateway). Fall through to the generic key rather than guessing.
  }
  return ['internal_error', 'errors.internal'];
}

/**
 * Multipart upload. The body is a FormData so the browser sets the boundary;
 * everything else (auth, error contract) matches `apiFetch`.
 */
export async function apiUpload<T>(
  path: string,
  form: FormData,
  accessToken: string | null,
): Promise<T> {
  const headers = new Headers();
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`);
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method: 'POST',
      headers,
      body: form,
      credentials: 'same-origin',
    });
  } catch (cause) {
    throw new ApiError(0, 'network_unreachable', 'errors.network', { cause });
  }
  if (!response.ok) {
    throw new ApiError(response.status, ...(await readErrorBody(response)));
  }
  return (await response.json()) as T;
}

export interface Download {
  blob: Blob;
  filename: string;
}

/**
 * Authenticated file download. A plain link cannot carry the bearer token, so
 * the file is fetched as a blob and handed to the browser by the caller.
 */
export async function apiDownload(
  path: string,
  accessToken: string | null,
  fallbackName: string,
): Promise<Download> {
  const headers = new Headers();
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`);
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { headers, credentials: 'same-origin' });
  } catch (cause) {
    throw new ApiError(0, 'network_unreachable', 'errors.network', { cause });
  }
  if (!response.ok) {
    throw new ApiError(response.status, ...(await readErrorBody(response)));
  }
  const disposition = response.headers.get('Content-Disposition') ?? '';
  const match = /filename="([^"]+)"/.exec(disposition);
  return { blob: await response.blob(), filename: match?.[1] ?? fallbackName };
}
