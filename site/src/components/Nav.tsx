import { AnimatePresence, motion, useReducedMotion, useScroll, useSpring, useMotionValueEvent } from 'framer-motion';
import { ChevronDown } from 'lucide-react';
import { useEffect, useRef, useState, type MouseEvent } from 'react';
import { useAuth } from '../lib/auth';
import { springQuiet } from '../lib/motion';
import { navigate } from '../lib/router';
import { ConfirmSignOut } from './fx/ConfirmSignOut';

const LINKS = [
  { label: 'Toolkit', hash: '#what' },
  { label: 'The swarm', hash: '#swarm' },
  { label: 'How it works', hash: '#how' },
  { label: 'Pricing', hash: '#pricing' },
  { label: 'FAQ', hash: '#faq' },
];

interface NavTab {
  label: string;
  hash?: string;
  connect?: boolean;
}

/** Everything the mobile brand menu lists — the desktop tabs, in order. */
const TABS: NavTab[] = [
  { label: 'Connect site', connect: true },
  ...LINKS.map((l) => ({ label: l.label, hash: l.hash })),
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
 *
 * Below lg the section tabs vanish, so the brand itself becomes the
 * menu: tapping the mark opens a glass dropdown of the same tabs. On
 * the landing variant the tabs are locked doors — every one of them
 * routes to /signin. From lg up the brand is the plain scroll-to-top
 * mark it has always been.
 *
 * Sign out asks first: a small glass dialog (fx/ConfirmSignOut) stands
 * in front of the actual logout.
 */
export function Nav({ variant = 'site' }: { variant?: 'site' | 'landing' }) {
  const [scrolled, setScrolled] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [confirmOut, setConfirmOut] = useState(false);
  const signOutBtnRef = useRef<HTMLButtonElement | null>(null);
  const reduce = useReducedMotion();
  const headerRef = useRef<HTMLElement | null>(null);
  const brandBtnRef = useRef<HTMLButtonElement | null>(null);
  const { scrollY, scrollYProgress } = useScroll();
  const progress = useSpring(scrollYProgress, { stiffness: 120, damping: 26, mass: 0.4 });
  const { user, loading, signOut } = useAuth();
  useMotionValueEvent(scrollY, 'change', (v) => setScrolled(v > 24));

  // The mobile menu lives and dies with its trigger: an outside tap or
  // Escape closes it, and it folds away if the viewport grows to where
  // the desktop tabs take over.
  useEffect(() => {
    if (!menuOpen) return;
    const onPointerDown = (e: PointerEvent) => {
      if (headerRef.current && !headerRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setMenuOpen(false);
        brandBtnRef.current?.focus();
      }
    };
    const desktop = window.matchMedia('(min-width: 1024px)');
    const onDesktop = (e: MediaQueryListEvent) => {
      if (e.matches) setMenuOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKey);
    desktop.addEventListener('change', onDesktop);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKey);
      desktop.removeEventListener('change', onDesktop);
    };
  }, [menuOpen]);

  const goTab = (e: MouseEvent, tab: NavTab) => {
    e.preventDefault();
    setMenuOpen(false);
    if (variant === 'landing') {
      navigate('/signin');
    } else if (tab.connect) {
      navigate('/app/connect');
    } else if (tab.hash) {
      scrollToHash(tab.hash);
    }
  };

  const tabHref = (tab: NavTab) =>
    variant === 'landing' ? '/signin' : tab.connect ? '/app/connect' : (tab.hash ?? '#top');

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

  // Sign out is gated by the ConfirmSignOut dialog; the logout flow
  // itself (lib/auth signOut, then home) runs only on confirm.
  const openSignOut = (e: MouseEvent) => {
    e.preventDefault();
    setConfirmOut(true);
  };

  const cancelSignOut = () => {
    setConfirmOut(false);
    signOutBtnRef.current?.focus();
  };

  const confirmSignOut = async () => {
    setConfirmOut(false);
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
        ref={headerRef}
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
          {/* desktop brand — the plain scroll-to-top mark */}
          <a
            href="#top"
            onClick={goHome}
            className="hidden shrink-0 items-center gap-2.5 lg:flex"
            aria-label="BugSeek AI home"
          >
            <img src="/bug.svg" alt="" className="h-8 w-8" />
            <span className="font-display text-lg font-semibold tracking-tight text-bone">
              BugSeek <span className="text-white/50">AI</span>
            </span>
          </a>
          {/* mobile brand — under lg the mark is the menu trigger */}
          <button
            ref={brandBtnRef}
            type="button"
            onClick={() => setMenuOpen((o) => !o)}
            aria-haspopup="true"
            aria-expanded={menuOpen}
            aria-controls="nav-mobile-menu"
            aria-label="BugSeek AI"
            className="flex shrink-0 items-center gap-2 lg:hidden"
          >
            <img src="/bug.svg" alt="" className="h-8 w-8" />
            <span className="font-display text-lg font-semibold tracking-tight text-bone">
              BugSeek <span className="text-white/50">AI</span>
            </span>
            <ChevronDown
              aria-hidden
              className={`h-4 w-4 text-white/55 ${reduce ? '' : 'transition-transform duration-300'} ${
                menuOpen ? 'rotate-180' : ''
              }`}
            />
          </button>
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
                    ref={signOutBtnRef}
                    type="button"
                    onClick={openSignOut}
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
        {/* mobile tab dropdown — mirrors the pill above, mobile only */}
        <AnimatePresence>
          {menuOpen && (
            <motion.nav
              id="nav-mobile-menu"
              aria-label="Sections"
              initial={reduce ? false : { opacity: 0, y: -8, scale: 0.99 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={reduce ? { opacity: 0 } : { opacity: 0, y: -6, scale: 0.99 }}
              transition={springQuiet}
              className={`glass mx-auto mt-2 rounded-3xl p-2 transition-[max-width] duration-300 lg:hidden ${
                scrolled ? 'max-w-3xl' : 'max-w-6xl'
              }`}
            >
              {TABS.map((tab) => (
                <a
                  key={tab.label}
                  href={tabHref(tab)}
                  onClick={(e) => goTab(e, tab)}
                  className={`flex items-center rounded-2xl px-4 py-3 transition-colors hover:bg-white/5 hover:text-bone ${
                    tab.connect
                      ? 'text-[15px] font-semibold text-bone'
                      : 'text-[15px] font-medium text-body/85'
                  }`}
                >
                  {tab.label}
                </a>
              ))}
            </motion.nav>
          )}
        </AnimatePresence>
      </motion.header>
      <ConfirmSignOut open={confirmOut} onCancel={cancelSignOut} onConfirm={confirmSignOut} />
    </>
  );
}
