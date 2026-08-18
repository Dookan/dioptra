/** The session contract shared by the provider and its consumers. */
import { createContext, useContext } from 'react';

import type { UserProfile } from '../api/auth';

export type SessionStatus = 'loading' | 'anonymous' | 'authenticated' | 'password-change';

export interface AuthState {
  status: SessionStatus;
  user: UserProfile | null;
  /** Kept in memory only: a token in localStorage is a token any script can read. */
  accessToken: string | null;
  signIn: (username: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
}

export const AuthContext = createContext<AuthState | null>(null);

export function useAuth(): AuthState {
  const state = useContext(AuthContext);
  if (state === null) {
    throw new Error('useAuth must be used inside <AuthProvider>');
  }
  return state;
}
