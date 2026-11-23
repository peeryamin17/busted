import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { probeSession } from './probeSession';

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
  /** True when the probe could not reach the backend at all. */
  waking: boolean;
  wakingDetail: string | null;
  retry: () => void;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthState>({
  user: null,
  credits: null,
  loading: true,
  waking: false,
  wakingDetail: null,
  retry: () => {},
  signOut: async () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [credits, setCredits] = useState<SessionCredits | null>(null);
  const [loading, setLoading] = useState(true);
  const [waking, setWaking] = useState(false);
  const [wakingDetail, setWakingDetail] = useState<string | null>(null);

  const probe = useCallback(async () => {
    setLoading(true);
    const result = await probeSession();
    if (result.status === 'authenticated') {
      setUser(result.user);
      setCredits(result.credits);
      setWaking(false);
      setWakingDetail(null);
    } else if (result.status === 'backend_waking') {
      setUser(null);
      setCredits(null);
      setWaking(true);
      setWakingDetail(result.detail);
    } else {
      setUser(null);
      setCredits(null);
      setWaking(false);
      setWakingDetail(null);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    void probe();
  }, [probe]);

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
    setWaking(false);
    setWakingDetail(null);
  }, []);

  const value = useMemo(
    () => ({ user, credits, loading, waking, wakingDetail, retry: probe, signOut }),
    [user, credits, loading, waking, wakingDetail, probe, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  return useContext(AuthContext);
}
