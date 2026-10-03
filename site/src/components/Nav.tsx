import { motion, useScroll, useSpring, useMotionValueEvent } from 'framer-motion';
import { useState, type MouseEvent } from 'react';
import { useAuth } from '../lib/auth';
import { springQuiet } from '../lib/motion';
import { navigate } from '../lib/router';

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
 * Brand plus section links on the left of the account slot; the account
 * slot itself is a "Sign in" link signed out, and an avatar chip with
 * sign-out signed in.
 *
 * The landing variant drops the section links (their targets only exist
 * inside the main site) and keeps just the brand and the account slot.
 */
export function Nav({ variant = 'site' }: { variant?: 'site' | 'landing' }) {
  const [scrolled, setScrolled] = useState(false);
  const { scrollY, scrollYProgress } = useScroll();
  const progress = useSpring(scrollYProgress, { stiffness: 120, damping: 26, mass: 0.4 });
  const { user, loading, signOut } = useAuth();
  useMotionValueEvent(scrollY, 'change', (v) => setScrolled(v > 24));

  const goSection = (e: MouseEvent, hash: string) => {
    e.preventDefault();
    scrollToHash(hash);
  };

  const goHome = (e: MouseEvent) => {
    e.preventDefault();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const goSignIn = (e: MouseEvent) => {
    e.preventDefault();
    navigate('/signin');
  };

  const handleSignOut = async (e: MouseEvent) => {
    e.preventDefault();
    await signOut();
    navigate('/');
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
          <div className="flex items-center gap-4 sm:gap-5">
            {variant === 'site' && (
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
            {/* account slot — nothing renders until the session probe
                answers, so the wrong state never flashes */}
            {!loading &&
              (user ? (
                <div className="flex items-center gap-2.5 sm:gap-3.5">
                  <span className="flex items-center gap-2 rounded-full border border-white/10 bg-white/5 py-1 pl-1 pr-3">
                    {user.avatar ? (
                      <img
                        src={user.avatar}
                        alt=""
                        referrerPolicy="no-referrer"
                        className="h-6 w-6 rounded-full"
                      />
                    ) : (
                      <span className="flex h-6 w-6 items-center justify-center rounded-full bg-white/10 font-display text-[11px] font-semibold text-bone">
                        {(user.name ?? user.email).charAt(0).toUpperCase()}
                      </span>
                    )}
                    <span className="max-w-[6.5rem] truncate text-sm font-medium text-bone">
                      {user.name ?? user.email}
                    </span>
                  </span>
                  <button
                    type="button"
                    onClick={handleSignOut}
                    className="shrink-0 text-sm font-medium text-body/80 transition-colors hover:text-bone"
                  >
                    Sign out
                  </button>
                </div>
              ) : (
                <a
                  href="/signin"
                  onClick={goSignIn}
                  className="shrink-0 text-sm font-semibold text-bone transition-colors hover:text-white"
                >
                  Sign in
                </a>
              ))}
          </div>
        </div>
      </motion.header>
    </>
  );
}
