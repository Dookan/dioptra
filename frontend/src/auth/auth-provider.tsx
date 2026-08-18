/** Holds the session for the whole app. */
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';

import * as authApi from '../api/auth';
import type { SessionResponse, UserProfile } from '../api/auth';
import { AuthContext, type AuthState, type SessionStatus } from './auth-context';

function statusFor(user: UserProfile): SessionStatus {
  return user.must_change_password ? 'password-change' : 'authenticated';
}

export function AuthProvider({ children }: { children: ReactNode }): ReactNode {
  const [status, setStatus] = useState<SessionStatus>('loading');
  const [user, setUser] = useState<UserProfile | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);

  const adopt = useCallback((session: SessionResponse) => {
    setAccessToken(session.access_token);
    setUser(session.user);
    setStatus(statusFor(session.user));
  }, []);

  const clear = useCallback(() => {
    setAccessToken(null);
    setUser(null);
    setStatus('anonymous');
  }, []);

  useEffect(() => {
    // On boot the access token is gone (it never leaves memory), but the
    // refresh cookie may still be valid — so a reload does not force a login.
    let cancelled = false;
    authApi
      .refresh()
      .then((session) => {
        if (!cancelled) adopt(session);
      })
      .catch(() => {
        if (!cancelled) clear();
      });
    return () => {
      cancelled = true;
    };
  }, [adopt, clear]);

  const signIn = useCallback(
    async (username: string, password: string) => {
      adopt(await authApi.login(username, password));
    },
    [adopt],
  );

  const signOut = useCallback(async () => {
    try {
      await authApi.logout();
    } catch {
      // A sign-out that cannot reach the server still ends the session here;
      // the refresh token expires on its own, and reporting the failure would
      // only invite the user to stay signed in.
    } finally {
      clear();
    }
  }, [clear]);

  const changePassword = useCallback(
    async (currentPassword: string, newPassword: string) => {
      if (accessToken === null) throw new Error('no active session');
      await authApi.changePassword(accessToken, currentPassword, newPassword);
      // The change revoked every refresh token, this one included.
      clear();
    },
    [accessToken, clear],
  );

  const value = useMemo<AuthState>(
    () => ({ status, user, accessToken, signIn, signOut, changePassword }),
    [status, user, accessToken, signIn, signOut, changePassword],
  );

  return <AuthContext value={value}>{children}</AuthContext>;
}
