import { motion, useScroll, useSpring, useMotionValueEvent } from 'framer-motion';
import { SignedIn, SignedOut, UserButton } from '@clerk/clerk-react';
import { useState, type MouseEvent } from 'react';
import { clerkAppearance, CLERK_ENABLED } from '../lib/clerk';
import { springQuiet } from '../lib/motion';
import { navigate } from '../lib/router';
import { LiquidGlassButton } from './fx/LiquidGlassButton';

const LINKS = [
  { label: 'Toolkit', hash: '#what' },
  { label: 'The swarm', hash: '#swarm' },
  { label: 'How it works', hash: '#how' },
  { label: 'Pricing', hash: '#pricing' },
  { label: 'FAQ', hash: '#faq' },
];

function scrollToHash(hash: string) {
  document.querySelector(hash)?.scrollIntoView({ behavior: 'smooth' });
}

/**
 * Floating glass pill nav (Aceternity floating-navbar energy): it
 * materializes as a detached pill once you scroll, and a white hairline
 * tracks reading progress across the very top of the viewport.
 * Works on every route — section links hop home first when needed.
 */
export function Nav({ home = true }: { home?: boolean }) {
  const [scrolled, setScrolled] = useState(false);
  const { scrollY, scrollYProgress } = useScroll();
  const progress = useSpring(scrollYProgress, { stiffness: 120, damping: 26, mass: 0.4 });
  useMotionValueEvent(scrollY, 'change', (v) => setScrolled(v > 24));

  const goSection = (e: MouseEvent, hash: string) => {
    e.preventDefault();
    if (home) {
      scrollToHash(hash);
    } else {
      navigate('/');
      window.setTimeout(() => scrollToHash(hash), 90);
    }
  };

  const goHome = (e: MouseEvent) => {
    e.preventDefault();
    if (home) {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else {
      navigate('/');
    }
  };

  return (
    <>
      <motion.div
        aria-hidden
        className="fixed inset-x-0 top-0 z-[60] h-[2px] origin-left bg-white"
        style={{ scaleX: progress }}
      />
      <motion.header
        initial={{ y: -72, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={springQuiet}
        className="fixed inset-x-0 top-0 z-50 px-3 sm:px-6"
      >
        {/* Scroll-edge blur: content dissolves as it passes under the nav */}
        <div
          aria-hidden
          className={`nav-blur-strip pointer-events-none fixed inset-x-0 top-0 -z-10 h-32 transition-opacity duration-500 ${
            scrolled ? 'opacity-100' : 'opacity-0'
          }`}
        />
        <div
          className={`glass nav-material mx-auto flex items-center justify-between gap-3 px-4 py-3 transition-all duration-300 sm:px-5 ${
            scrolled ? 'mt-3 max-w-3xl rounded-full' : 'mt-3 max-w-6xl rounded-3xl'
          }`}
        >
          <a
            href={home ? '#top' : '/'}
            onClick={goHome}
            className="flex shrink-0 items-center gap-2.5"
            aria-label="BugSeek AI home"
          >
            <img src="/bug.svg" alt="" className="h-8 w-8" />
            <span className="font-display text-lg font-semibold tracking-tight text-bone">
              BugSeek <span className="text-white/50">AI</span>
            </span>
          </a>
          <nav className="hidden items-center gap-6 lg:flex" aria-label="Primary">
            {LINKS.map((l) => (
              <a
                key={l.hash}
                href={home ? l.hash : `/${l.hash}`}
                onClick={(e) => goSection(e, l.hash)}
                className="text-sm font-medium text-body/80 transition-colors hover:text-bone"
              >
                {l.label}
              </a>
            ))}
          </nav>
          <div className="flex shrink-0 items-center gap-2.5">
            {CLERK_ENABLED ? <ClerkAuthArea home={home} /> : <SignedOutLinks home={home} />}
          </div>
        </div>
      </motion.header>
    </>
  );
}

/** The signed-out nav actions — also the fallback when Clerk is off. */
function SignedOutLinks({ home }: { home: boolean }) {
  return (
    <>
      <a
        href="/signin"
        onClick={(e) => {
          e.preventDefault();
          navigate('/signin');
        }}
        className="px-1.5 py-2 text-sm font-medium text-body/85 transition-colors hover:text-bone sm:px-2"
      >
        Sign in
      </a>
      <LiquidGlassButton
        href={home ? '#download' : '/#download'}
        onClick={(e) => {
          if (home) {
            e.preventDefault();
            scrollToHash('#download');
          }
        }}
        size="sm"
      >
        Get the extension
      </LiquidGlassButton>
    </>
  );
}

/**
 * Clerk-backed nav auth area. Only ever mounted when CLERK_ENABLED —
 * SignedIn/SignedOut/UserButton throw without a ClerkProvider.
 */
function ClerkAuthArea({ home }: { home: boolean }) {
  return (
    <>
      <SignedIn>
        <UserButton appearance={clerkAppearance} />
      </SignedIn>
      <SignedOut>
        <SignedOutLinks home={home} />
      </SignedOut>
    </>
  );
}
