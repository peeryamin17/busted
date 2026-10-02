import { useEffect, useState } from 'react';
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
import { Preloader } from './components/fx/Preloader';
import { isSignedIn, usePathname } from './lib/router';
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
  const signedIn = isSignedIn();
  return (
    <div className="min-h-screen bg-ink text-body">
      <a
        href="#what"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-[60] focus:rounded-lg focus:bg-mint focus:px-4 focus:py-2 focus:text-ink"
      >
        Skip to content
      </a>
      <Nav home signedIn={signedIn} />
      <main>
        <Hero />
        <Ticker />
        <Bento />
        <Swarm />
        <HowItWorks />
        <Pricing />
        <Faq />
        <Download />
      </main>
      <CrowdCanvas />
      <Footer home />
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
      {showIntro && <Preloader onDone={finishIntro} />}
      {path === '/signin' ? (
        <SignIn />
      ) : path === '/welcome' ? (
        <Welcome />
      ) : (
        <Home />
      )}
    </>
  );
}
