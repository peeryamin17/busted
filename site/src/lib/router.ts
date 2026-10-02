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
