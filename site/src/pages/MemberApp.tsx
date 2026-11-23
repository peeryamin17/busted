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
 * only the hold screen renders, the member experience never flashes
 * for signed-out visitors, who are handed to /signin instead. A probe
 * that could not reach the backend at all shows a waking-up banner
 * with a retry, never a redirect: a cold Render backend is not a
 * signed-out user.
 */
export function MemberApp() {
  const { user, loading, waking, wakingDetail, retry } = useAuth();

  useEffect(() => {
    if (!loading && !user && !waking) replaceTo('/signin');
  }, [loading, user, waking]);

  if (loading) return <MemberLoading />;
  if (waking && !user) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-ink px-4">
        <img src="/bug.svg" alt="" className="h-12 w-12 animate-pulse" />
        <p className="mt-5 font-mono text-[10px] tracking-[0.3em] text-slate2">
          BACKEND WAKING UP
        </p>
        <p className="mt-3 max-w-sm text-center text-sm leading-relaxed text-body/85">
          The backend did not answer just now — it may be waking from a
          cold start. Your session is untouched; try again in a moment.
        </p>
        {wakingDetail && (
          <p className="mt-2 font-mono text-[11px] text-slate2">{wakingDetail}</p>
        )}
        <button
          type="button"
          onClick={retry}
          className="mt-6 inline-flex items-center gap-2 rounded-full bg-bone px-6 py-3 font-display text-sm font-bold tracking-tight text-ink transition-transform duration-300 hover:scale-[1.03]"
        >
          Try again
        </button>
      </div>
    );
  }
  if (!user) return <MemberLoading />;
  return <MemberSite />;
}
