import { useEffect, useState } from 'react';

/**
 * A tiny pathname router — pushState + popstate, no dependency.
 * The host rewrites every path to index.html (see vercel.json), so
 * client routes survive direct loads and refreshes.
 */
export function navigate(to: string) {
  if (window.location.pathname === to && !window.location.hash) return;
  window.history.pushState({}, '', to);
  window.dispatchEvent(new PopStateEvent('popstate'));
  window.scrollTo({ top: 0, behavior: 'auto' });
}

export function usePathname(): string {
  const [path, setPath] = useState(() => window.location.pathname);
  useEffect(() => {
    const onPop = () => setPath(window.location.pathname);
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);
  return path;
}

/** True when the (frontend-only) sign-in flow has been completed this session. */
export function isSignedIn(): boolean {
  try {
    return sessionStorage.getItem('bugseek-signed-in') === '1';
  } catch {
    return false;
  }
}

export function markSignedIn() {
  try {
    sessionStorage.setItem('bugseek-signed-in', '1');
  } catch {
    /* private mode — the chip just won't persist across pages */
  }
}
