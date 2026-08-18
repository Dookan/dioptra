/** Auth endpoints, typed. Mirrors backend/app/auth/schemas.py. */
import { apiFetch } from './client';

export type Role = 'admin' | 'analyst' | 'developer';

export interface UserProfile {
  id: string;
  username: string;
  display_name: string;
  role: Role;
  must_change_password: boolean;
}

export interface SessionResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: UserProfile;
}

export function login(username: string, password: string): Promise<SessionResponse> {
  return apiFetch<SessionResponse>('/auth/login', {
    method: 'POST',
    body: { username, password },
  });
}

/** Exchanges the HttpOnly refresh cookie for a fresh access token. */
export function refresh(): Promise<SessionResponse> {
  return apiFetch<SessionResponse>('/auth/refresh', { method: 'POST' });
}

export function logout(): Promise<void> {
  return apiFetch<void>('/auth/logout', { method: 'POST' });
}

export function changePassword(
  accessToken: string,
  currentPassword: string,
  newPassword: string,
): Promise<void> {
  return apiFetch<void>('/auth/password', {
    method: 'POST',
    accessToken,
    body: { current_password: currentPassword, new_password: newPassword },
  });
}
