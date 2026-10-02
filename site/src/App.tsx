import { useEffect, useState } from 'react';
import { AuthenticateWithRedirectCallback } from '@clerk/clerk-react';
import { Loader2 } from 'lucide-react';
import { Nav } from './components/Nav';
import { Hero } from './components/Hero';
import { Ticker } from './components/Ticker';
import { Bento } from './components/Bento';
import { Swarm } from './components/Swarm';
import { HowItWorks } from './components/HowItWorks';
import { Pricing } from './components/Pricing';
import { Faq } from './components/Faq';
import { Download } from './components/Download';
import { Footer } from './components/Footer';
import { CrowdCanvas } from './components/fx/CrowdCanvas';
import { SonarGrid } from './components/fx/SonarGrid';
import { Preloader } from './components/fx/Preloader';
import { usePathname } from './lib/router';
import { SignIn } from './pages/SignIn';
import { Welcome } from './pages/Welcome';

const INTRO_KEY = 'bugseek-intro';

function introSeen(): boolean {
  try {
    return sessionStorage.getItem(INTRO_KEY) === '1';
  } catch {
    return true; // if storage is unavailable, never trap the user behind it
  }
}

function Home() {
  return (
    <div className="min-h-screen bg-ink text-body">
      <a
        href="#what"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-[60] focus:rounded-lg focus:bg-mint focus:px-4 focus:py-2 focus:text-ink"
      >
        Skip to content
      </a>
      <SonarGrid />
      <Nav home />
      <main className="relative z-10">
        <Hero />
        <Ticker />
        <Bento />
        <Swarm />
        <HowItWorks />
        <Pricing />
        <Faq />
        <Download />
      </main>
      <div className="relative z-10">
        <CrowdCanvas />
      </div>
      <Footer home />
    </div>
  );
}

/**
 * /sso-callback — where Clerk sends the browser back after Google.
 * A quiet black holding page: Clerk's callback handler completes the
 * sign-in (invisibly) and moves on to /welcome.
 */
function SsoCallback() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-ink px-4 text-center text-body">
      <img src="/bug.svg" alt="" className="h-12 w-12" />
      <Loader2 className="mt-7 h-6 w-6 animate-spin text-white" aria-hidden />
      <p className="mt-4 font-display text-lg font-semibold tracking-tight text-bone">
        Signing you in…
      </p>
      <p className="mt-1.5 text-sm text-body/70">Completing the handshake with Google.</p>
      <AuthenticateWithRedirectCallback afterSignInUrl="/welcome" afterSignUpUrl="/welcome" />
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

  // Arriving home with a hash (e.g. /#download from another route) —
  // scroll to the anchor once the sections exist.
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
      {showIntro && path !== '/sso-callback' && <Preloader onDone={finishIntro} />}
      {path === '/signin' ? (
        <SignIn />
      ) : path === '/sso-callback' ? (
        <SsoCallback />
      ) : path === '/welcome' ? (
        <Welcome />
      ) : (
        <Home />
      )}
    </>
  );
}
