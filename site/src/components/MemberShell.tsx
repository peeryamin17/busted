import { useAuth, useUser } from '@clerk/clerk-react';
import { Loader2 } from 'lucide-react';
import { useEffect, type ReactNode } from 'react';
import { CLERK_ENABLED } from '../lib/clerk';
import { navigate } from '../lib/router';
import { LiquidGlassButton } from './fx/LiquidGlassButton';
import { SonarGrid } from './fx/SonarGrid';

export interface MemberIdentity {
  displayName: string;
  firstName: string;
  email?: string;
}

const LINKED_KEY = 'bugseek-clerk-linked';

function MemberGate({ label }: { label: string }) {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-ink px-4 text-center text-body">
      <img src="/bug.svg" alt="" className="h-12 w-12" />
      <Loader2 className="mt-7 h-6 w-6 animate-spin text-white" aria-hidden />
      <p className="mt-4 font-mono text-[11px] tracking-[0.3em] text-slate2">{label}</p>
    </div>
  );
}

function AuthUnavailable() {
  return (
    <div className="relative flex min-h-screen flex-col items-center justify-center bg-ink px-4 text-center text-body">
      <SonarGrid />
      <div className="relative z-10 max-w-md">
        <img src="/bug.svg" alt="" className="mx-auto h-14 w-14" />
        <p className="mt-7 font-mono text-[11px] tracking-[0.3em] text-slate2">MEMBERS ONLY</p>
        <h1 className="mt-4 font-display text-4xl font-bold tracking-tight text-bone">
          Authentication isn't switched on yet.
        </h1>
        <p className="mt-4 leading-relaxed text-body/85">
          This part of BugSeek opens after Google sign-in. Once authentication is
          configured for this deployment, members will land here automatically.
        </p>
        <div className="mt-8 flex flex-wrap justify-center gap-3">
          <LiquidGlassButton
            href="/signin"
            onClick={(e) => {
              e.preventDefault();
              navigate('/signin');
            }}
          >
            Go to sign in
          </LiquidGlassButton>
          <LiquidGlassButton
            href="/"
            variant="glass"
            onClick={(e) => {
              e.preventDefault();
              navigate('/');
            }}
          >
            Back to entrance
          </LiquidGlassButton>
        </div>
      </div>
    </div>
  );
}

/**
 * The member gate. Clerk hooks live only inside GuardedMemberShell, which
 * is mounted only when a Clerk provider exists. Signed-out visitors are
 * sent to /signin; signed-in members get their Google identity passed to
 * the page so BugSeek can greet them by name.
 */
export function MemberShell({ children }: { children: (identity: MemberIdentity) => ReactNode }) {
  if (!CLERK_ENABLED) return <AuthUnavailable />;
  return <GuardedMemberShell>{children}</GuardedMemberShell>;
}

function GuardedMemberShell({ children }: { children: (identity: MemberIdentity) => ReactNode }) {
  const { isLoaded, isSignedIn, getToken } = useAuth();
  const { user } = useUser();

  useEffect(() => {
    if (isLoaded && !isSignedIn) navigate('/signin');
  }, [isLoaded, isSignedIn]);

  // Link the Clerk identity to a BugSeek backend user (find-or-create),
  // once per session. Non-fatal: the member site still renders if the
  // backend is offline, and linking is retried on a later visit.
  useEffect(() => {
    if (!isLoaded || !isSignedIn || !user) return;
    let already = false;
    try {
      already = sessionStorage.getItem(LINKED_KEY) === '1';
    } catch {
      /* private mode — link again; the backend call is idempotent */
    }
    if (already) return;

    let cancelled = false;
    (async () => {
      try {
        const token = await getToken();
        const email = user.primaryEmailAddress?.emailAddress;
        if (!token || !email || cancelled) return;
        const base = import.meta.env.VITE_BACKEND_URL ?? 'http://localhost:3000';
        const res = await fetch(`${base}/api/auth/clerk/link`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ email }),
        });
        if (res.ok) {
          try {
            sessionStorage.setItem(LINKED_KEY, '1');
          } catch {
            /* private mode — harmless to link again next time */
          }
        }
      } catch (err) {
        console.warn('BugSeek backend link skipped (backend offline?):', err);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [isLoaded, isSignedIn, user, getToken]);

  if (!isLoaded) return <MemberGate label="CHECKING YOUR GOOGLE ACCOUNT" />;
  if (!isSignedIn) return <MemberGate label="REDIRECTING TO SIGN IN" />;
  if (!user) return <MemberGate label="LOADING YOUR PROFILE" />;

  const fullName = user.fullName?.trim() ?? '';
  const email = user.primaryEmailAddress?.emailAddress;
  const firstName = user.firstName?.trim() || fullName.split(/\s+/)[0] || email?.split('@')[0] || 'hunter';
  const displayName = firstName || 'hunter';

  return <>{children({ displayName, firstName, email })}</>;
}
