import { useEffect } from 'react';

/**
 * Legacy /welcome path. The post-sign-in home is now /app; this page only
 * forwards members there so old bookmarks and callbacks keep working.
 */
export function Welcome() {
  useEffect(() => {
    window.history.replaceState({}, '', '/app');
    window.dispatchEvent(new PopStateEvent('popstate'));
    window.scrollTo({ top: 0, behavior: 'auto' });
  }, []);

  return <div className="min-h-screen bg-ink" />;
}
