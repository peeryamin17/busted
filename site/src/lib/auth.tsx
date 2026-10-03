import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

export interface SessionUser {
  id: string;
  email: string;
  name: string | null;
  avatar: string | null;
  plan: string;
}

export interface SessionCredits {
  usedThisMonth: number;
  monthlyQuota: number | null;
  remaining: number | null;
}

interface AuthState {
  user: SessionUser | null;
  credits: SessionCredits | null;
  loading: boolean;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthState>({
  user: null,
  credits: null,
  loading: true,
  signOut: async () => {},
});

/**
 * Session probe against our own backend, reached through the site's
 * /api proxy (see vercel.json / vite.config.ts) so the httpOnly
 * bs_session cookie stays same-site in the browser. 200 means signed
 * in; anything else — 401, network trouble, backend asleep — means
 * signed out.
 */
async function probeSession(): Promise<{
  user: SessionUser;
  credits: SessionCredits | null;
} | null> {
  try {
    const res = await fetch('/api/me', { credentials: 'include' });
    if (!res.ok) return null;
    const data = (await res.json()) as {
      user: SessionUser;
      credits?: SessionCredits;
    };
    return { user: data.user, credits: data.credits ?? null };
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [credits, setCredits] = useState<SessionCredits | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    probeSession().then((session) => {
      if (!alive) return;
      setUser(session?.user ?? null);
      setCredits(session?.credits ?? null);
      setLoading(false);
    });
    return () => {
      alive = false;
    };
  }, []);

  const signOut = useCallback(async () => {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
      });
    } catch {
      /* the local state clears either way */
    }
    setUser(null);
    setCredits(null);
  }, []);

  const value = useMemo(
    () => ({ user, credits, loading, signOut }),
    [user, credits, loading, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  return useContext(AuthContext);
}
