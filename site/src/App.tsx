import { useEffect, useState } from 'react';
import { Preloader } from './components/fx/Preloader';
import { usePathname } from './lib/router';
import { MemberSite } from './pages/MemberSite';

const INTRO_KEY = 'bugseek-intro';

function introSeen(): boolean {
  try {
    return sessionStorage.getItem(INTRO_KEY) === '1';
  } catch {
    return true; // if storage is unavailable, never trap the user behind it
  }
}

/**
 * The site is fully public now: every old gated path (sign-in, sign-up,
 * the member routes) simply lands on the front page.
 */
function RedirectHome() {
  useEffect(() => {
    window.history.replaceState({}, '', '/');
    window.dispatchEvent(new PopStateEvent('popstate'));
    window.scrollTo({ top: 0, behavior: 'auto' });
  }, []);

  return <div className="min-h-screen bg-ink" />;
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

  return (
    <>
      {showIntro && <Preloader onDone={finishIntro} />}
      {path === '/' ? <MemberSite /> : <RedirectHome />}
    </>
  );
}
