import { useEffect } from 'react';
import { useAuth } from '../lib/auth';
import { MemberSite } from './MemberSite';

function replaceTo(to: string) {
  window.history.replaceState({}, '', to);
  window.dispatchEvent(new PopStateEvent('popstate'));
  window.scrollTo({ top: 0, behavior: 'auto' });
}

/** In-design hold screen while the session probe is in flight. */
function MemberLoading() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-ink px-4">
      <img src="/bug.svg" alt="" className="h-12 w-12 animate-pulse" />
      <p className="mt-5 font-mono text-[10px] tracking-[0.3em] text-slate2">
        CHECKING YOUR KEY
      </p>
    </div>
  );
}

/**
 * The guarded members' home at /app. Until the session probe answers,
 * only the hold screen renders — the member experience never flashes
 * for signed-out visitors, who are handed to /signin instead.
 */
export function MemberApp() {
  const { user, loading } = useAuth();

  useEffect(() => {
    if (!loading && !user) replaceTo('/signin');
  }, [loading, user]);

  if (loading || !user) return <MemberLoading />;
  return <MemberSite />;
}
