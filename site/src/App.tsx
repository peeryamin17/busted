import { useEffect, useState, type ReactNode } from 'react';
import { Preloader } from './components/fx/Preloader';
import { AuthProvider } from './lib/auth';
import { usePathname } from './lib/router';
import { Landing } from './pages/Landing';
import { MemberApp } from './pages/MemberApp';
import { SignIn } from './pages/SignIn';

const INTRO_KEY = 'bugseek-intro';

function introSeen(): boolean {
  try {
    return sessionStorage.getItem(INTRO_KEY) === '1';
  } catch {
    return true; // if storage is unavailable, never trap the user behind it
  }
}

/** Swap the current path for another without a page load. */
function RedirectTo({ to }: { to: string }) {
  useEffect(() => {
    window.history.replaceState({}, '', to);
    window.dispatchEvent(new PopStateEvent('popstate'));
    window.scrollTo({ top: 0, behavior: 'auto' });
  }, [to]);

  return <div className="min-h-screen bg-ink" />;
}

/**
 * Route table:
 *   /            the public teaser (hero, ticker, a door) — the full
 *                site lives inside, behind sign-in
 *   /signin      the Google sign-in page
 *   /signup      → /signin (one door for new and returning members)
 *   /app         the guarded members' home (the whole main site)
 *   anything else (old /app/connect, /welcome, …) → /
 */
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

  // Arriving at the site with a hash (e.g. /#download) — scroll to the
  // anchor once the sections exist.
  useEffect(() => {
    if (path === '/' && window.location.hash) {
      const hash = window.location.hash;
      const t = window.setTimeout(() => {
        document.querySelector(hash)?.scrollIntoView();
      }, 60);
      return () => window.clearTimeout(t);
    }
  }, [path]);

  let page: ReactNode;
  if (path === '/') page = <Landing />;
  else if (path === '/signin') page = <SignIn />;
  else if (path === '/signup') page = <RedirectTo to="/signin" />;
  else if (path === '/app') page = <MemberApp />;
  else page = <RedirectTo to="/" />;

  return (
    <AuthProvider>
      {showIntro && <Preloader onDone={finishIntro} />}
      {page}
    </AuthProvider>
  );
}
