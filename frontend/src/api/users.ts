/** Account administration, admin only. Mirrors backend/app/auth/admin_router.py. */
import type { Role } from './auth';
import { apiFetch } from './client';

export interface Account {
  id: string;
  username: string;
  display_name: string;
  email: string | null;
  role: Role;
  disabled: boolean;
  must_change_password: boolean;
  last_login_at: string | null;
  locked_until: string | null;
  created_at: string;
}

export interface NewAccount {
  username: string;
  display_name: string;
  email: string | null;
  role: Role;
  password: string;
}

export function listAccounts(accessToken: string): Promise<Account[]> {
  return apiFetch<Account[]>('/users', { accessToken });
}

/** No justification: creating an account is the Hard Rule's recorded exception. */
export function createAccount(accessToken: string, payload: NewAccount): Promise<Account> {
  return apiFetch<Account>('/users', { method: 'POST', accessToken, body: payload });
}

export function changeRole(
  accessToken: string,
  id: string,
  role: Role,
  justification: string,
): Promise<Account> {
  return apiFetch<Account>(`/users/${id}/role`, {
    method: 'PATCH',
    accessToken,
    body: { role, justification },
  });
}

export function setDisabled(
  accessToken: string,
  id: string,
  disabled: boolean,
  justification: string,
): Promise<Account> {
  return apiFetch<Account>(`/users/${id}/status`, {
    method: 'PATCH',
    accessToken,
    body: { disabled, justification },
  });
}

export function resetPassword(
  accessToken: string,
  id: string,
  password: string,
  justification: string,
): Promise<Account> {
  return apiFetch<Account>(`/users/${id}/password-reset`, {
    method: 'POST',
    accessToken,
    body: { password, justification },
  });
}
