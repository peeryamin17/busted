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
 *
 * Two deliberately different faces:
 * - public: brand + account entry only. The product stays behind the door.
 * - member: the full site navigation, unlocked after Google sign-in.
 */
export function Nav({ variant = 'member' }: { variant?: 'public' | 'member' }) {
  const isPublic = variant === 'public';
  const [scrolled, setScrolled] = useState(false);
  const { scrollY, scrollYProgress } = useScroll();
  const progress = useSpring(scrollYProgress, { stiffness: 120, damping: 26, mass: 0.4 });
  useMotionValueEvent(scrollY, 'change', (v) => setScrolled(v > 24));

  const goSection = (e: MouseEvent, hash: string) => {
    e.preventDefault();
    scrollToHash(hash);
  };

  const goHome = (e: MouseEvent) => {
    e.preventDefault();
    window.scrollTo({ top: 0, behavior: 'smooth' });
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
            href="#top"
            onClick={goHome}
            className="flex shrink-0 items-center gap-2.5"
            aria-label="BugSeek AI home"
          >
            <img src="/bug.svg" alt="" className="h-8 w-8" />
            <span className="font-display text-lg font-semibold tracking-tight text-bone">
              BugSeek <span className="text-white/50">AI</span>
            </span>
          </a>
          {!isPublic && (
            <nav className="hidden items-center gap-6 lg:flex" aria-label="Primary">
              <a
                href="/app/connect"
                onClick={(e) => {
                  e.preventDefault();
                  navigate('/app/connect');
                }}
                className="text-sm font-semibold text-bone transition-colors hover:text-white"
              >
                Connect site
              </a>
              {LINKS.map((l) => (
                <a
                  key={l.hash}
                  href={l.hash}
                  onClick={(e) => goSection(e, l.hash)}
                  className="text-sm font-medium text-body/80 transition-colors hover:text-bone"
                >
                  {l.label}
                </a>
              ))}
            </nav>
          )}
          <div className="flex shrink-0 items-center gap-2.5">
            {isPublic ? <PublicAuthArea /> : <MemberAuthArea />}
          </div>
        </div>
      </motion.header>
    </>
  );
}

/** Account entry for the public face. */
function PublicLinks() {
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
        href="/signup"
        onClick={(e) => {
          e.preventDefault();
          navigate('/signup');
        }}
        size="sm"
      >
        Sign up
      </LiquidGlassButton>
    </>
  );
}

function PublicAuthArea() {
  if (!CLERK_ENABLED) return <PublicLinks />;
  return (
    <>
      <SignedIn>
        <div className="flex items-center gap-2.5">
          <LiquidGlassButton
            href="/app"
            onClick={(e) => {
              e.preventDefault();
              navigate('/app');
            }}
            size="sm"
          >
            Open BugSeek
          </LiquidGlassButton>
          <UserButton appearance={clerkAppearance} />
        </div>
      </SignedIn>
      <SignedOut>
        <PublicLinks />
      </SignedOut>
    </>
  );
}

function MemberAuthArea() {
  if (!CLERK_ENABLED) {
    return (
      <a
        href="/signin"
        onClick={(e) => {
          e.preventDefault();
          navigate('/signin');
        }}
        className="px-2 py-2 text-sm font-medium text-body/85 transition-colors hover:text-bone"
      >
        Sign in
      </a>
    );
  }
  return (
    <>
      <SignedIn>
        <UserButton appearance={clerkAppearance} />
      </SignedIn>
      <SignedOut>
        <a
          href="/signin"
          onClick={(e) => {
            e.preventDefault();
            navigate('/signin');
          }}
          className="px-2 py-2 text-sm font-medium text-body/85 transition-colors hover:text-bone"
        >
          Sign in
        </a>
      </SignedOut>
    </>
  );
}
