import { useEffect, useState } from 'react';
import { AuthenticateWithRedirectCallback } from '@clerk/clerk-react';
import { Loader2 } from 'lucide-react';
import { Preloader } from './components/fx/Preloader';
import { usePathname, navigate } from './lib/router';
import { CLERK_ENABLED } from './lib/clerk';
import { SignIn } from './pages/SignIn';
import { PublicLanding } from './pages/PublicLanding';
import { MemberSite } from './pages/MemberSite';
import { ConnectSite } from './pages/ConnectSite';

const INTRO_KEY = 'bugseek-intro';

function introSeen(): boolean {
  try {
    return sessionStorage.getItem(INTRO_KEY) === '1';
  } catch {
    return true; // if storage is unavailable, never trap the user behind it
  }
}

/** Old post-login path: keep bookmarks working, send members to /app. */
function WelcomeRedirect() {
  useEffect(() => {
    window.history.replaceState({}, '', '/app');
    window.dispatchEvent(new PopStateEvent('popstate'));
    window.scrollTo({ top: 0, behavior: 'auto' });
  }, []);

  return <div className="min-h-screen bg-ink" />;
}

/**
 * /sso-callback — where Clerk sends the browser back after Google.
 * A quiet black holding page: Clerk's callback handler completes the
 * sign-in (invisibly) and moves on to the member site.
 */
function SsoCallback() {
  // Without Clerk configured there is no handshake to complete — the
  // Clerk callback component would throw without a provider. Go home.
  useEffect(() => {
    if (!CLERK_ENABLED) navigate('/');
  }, []);
  if (!CLERK_ENABLED) {
    return <div className="min-h-screen bg-ink" />;
  }
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-ink px-4 text-center text-body">
      <img src="/bug.svg" alt="" className="h-12 w-12" />
      <Loader2 className="mt-7 h-6 w-6 animate-spin text-white" aria-hidden />
      <p className="mt-4 font-display text-lg font-semibold tracking-tight text-bone">
        Signing you in…
      </p>
      <p className="mt-1.5 text-sm text-body/70">Completing the handshake with Google.</p>
      <AuthenticateWithRedirectCallback />
    </div>
  );
}

export default function App() {
  const path = usePathname();
  const [showIntro, setShowIntro] = useState(() => !introSeen());

  const finishIntro = () => {
    try {
      sessionStorage.setItem(INTRO_KEY, '1');
    } catch {
      /* private mode — the intro will simply replay next visit */
    }
    setShowIntro(false);
  };

  // Arriving at the member site with a hash (e.g. /app#download) —
  // scroll to the anchor once the sections exist.
  useEffect(() => {
    if ((path === '/' || path === '/app') && window.location.hash) {
      const hash = window.location.hash;
      const t = window.setTimeout(() => {
        document.querySelector(hash)?.scrollIntoView();
      }, 60);
      return () => window.clearTimeout(t);
    }
  }, [path]);

  return (
    <>
      {showIntro && path !== '/sso-callback' && <Preloader onDone={finishIntro} />}
      {path === '/signin' ? (
        <SignIn mode="signin" />
      ) : path === '/signup' ? (
        <SignIn mode="signup" />
      ) : path === '/sso-callback' ? (
        <SsoCallback />
      ) : path === '/welcome' ? (
        <WelcomeRedirect />
      ) : path === '/app/connect' ? (
        <ConnectSite />
      ) : path === '/app' ? (
        <MemberSite />
      ) : (
        <PublicLanding />
      )}
    </>
  );
}
