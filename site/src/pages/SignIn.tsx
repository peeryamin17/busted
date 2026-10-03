import { motion, useReducedMotion } from 'framer-motion';
import { ArrowLeft, Coins, History, Loader2, Radar } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { SonarGrid } from '../components/fx/SonarGrid';
import { TabCat } from '../components/fx/TabCat';
import { LiquidGlassButton } from '../components/fx/LiquidGlassButton';
import { useAuth } from '../lib/auth';
import { springQuiet } from '../lib/motion';
import { navigate } from '../lib/router';

/** The Google "G" — the one splash of brand colour allowed on the page. */
function GoogleMark({ className = '' }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} aria-hidden>
      <path
        fill="#4285F4"
        d="M23.49 12.27c0-.79-.07-1.54-.19-2.27H12v4.51h6.47c-.29 1.48-1.14 2.73-2.4 3.58v3h3.86c2.26-2.09 3.56-5.17 3.56-8.82z"
      />
      <path
        fill="#34A853"
        d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.86-3c-1.08.72-2.45 1.16-4.07 1.16-3.13 0-5.78-2.11-6.73-4.96H1.29v3.09C3.26 21.3 7.31 24 12 24z"
      />
      <path
        fill="#FBBC05"
        d="M5.27 14.29c-.25-.72-.38-1.49-.38-2.29s.14-1.57.38-2.29V6.62H1.29C.47 8.24 0 10.06 0 12s.47 3.76 1.29 5.38l3.98-3.09z"
      />
      <path
        fill="#EA4335"
        d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.31 0 3.26 2.7 1.29 6.62l3.98 3.09C6.22 6.86 8.87 4.75 12 4.75z"
      />
    </svg>
  );
}

const PERKS = [
  { icon: Coins, text: 'Credits and plans, synced to the extension' },
  { icon: History, text: 'Swarm history, scores and reports in one place' },
  { icon: Radar, text: 'One login for popup, backend and the deep stuff' },
];

/**
 * Sign-in: a split glass card in black & white — brand story on the
 * left, one Google button on the right. GOOGLE ONLY: no email field,
 * no password, nothing to phish or forget. The button hands the whole
 * browser to our backend's /api/auth/google, which starts the Google
 * OAuth round trip and lands members back on /app.
 */
export function SignIn() {
  const reduce = useReducedMotion();
  const { user, loading } = useAuth();
  const [busy, setBusy] = useState(false);
  const [agreed, setAgreed] = useState(false);
  const catRoofRef = useRef<HTMLDivElement>(null);

  // Already signed in? This door leads straight to the members' home.
  useEffect(() => {
    if (!loading && user) navigate('/app');
  }, [loading, user]);

  const beginSignIn = () => {
    if (busy || !agreed) return;
    setBusy(true);
    window.location.assign('/api/auth/google');
  };

  return (
    <div ref={catRoofRef} className="relative flex min-h-screen flex-col bg-ink">
      <SonarGrid />
      {/* the cat keeps watch over the door too — brand perch, no tabs here */}
      <TabCat variant="landing" containerRef={catRoofRef} />

      {/* top bar */}
      <header className="relative z-10 flex items-center justify-between px-5 pb-5 pt-12 sm:px-8">
        <a
          data-cat-brand
          href="/"
          onClick={(e) => {
            e.preventDefault();
            navigate('/');
          }}
          className="flex items-center gap-2.5"
          aria-label="BugSeek AI home"
        >
          <img src="/bug.svg" alt="" className="h-8 w-8" />
          <span className="font-display text-lg font-semibold tracking-tight text-bone">
            BugSeek <span className="text-white/50">AI</span>
          </span>
        </a>
        <a
          href="/"
          onClick={(e) => {
            e.preventDefault();
            navigate('/');
          }}
          className="inline-flex items-center gap-1.5 text-sm font-medium text-body/80 transition-colors hover:text-bone"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden /> Back to site
        </a>
      </header>

      <main className="relative z-10 flex flex-1 items-center justify-center px-4 pb-16 pt-4 sm:px-6">
        <motion.div
          initial={reduce ? false : { opacity: 0, y: 26, scale: 0.985 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={springQuiet}
          className="glass grid w-full max-w-4xl overflow-hidden rounded-[2rem] lg:grid-cols-[1.05fr_1fr]"
        >
          {/* brand pane */}
          <div className="relative hidden flex-col justify-between overflow-hidden border-r border-white/10 bg-white/[0.03] p-9 lg:flex">
            {/* sonar rings, echoing the hero */}
            <div aria-hidden className="pointer-events-none absolute -right-24 -top-24 h-96 w-96">
              {[0, 1, 2].map((i) => (
                <span
                  key={i}
                  className="ring-ping absolute inset-0 rounded-full border border-white/15"
                  style={{ animationDelay: `${i * 1.05}s` }}
                />
              ))}
              <span className="absolute inset-0 rounded-full border border-white/10" />
              <span className="absolute left-1/2 top-1/2 h-2 w-2 -translate-x-1/2 -translate-y-1/2 rounded-full bg-white" />
            </div>

            <div className="relative">
              <img src="/bug.svg" alt="" className="h-12 w-12" />
              <h2 className="mt-6 font-display text-3xl font-bold leading-tight tracking-tight text-bone">
                One account.
                <br />
                Every hunt.
              </h2>
              <p className="mt-3 max-w-xs text-sm leading-relaxed text-body/80">
                Sign in once and the extension, your credits and the swarm
                all know who you are.
              </p>
            </div>

            <ul className="relative mt-10 space-y-3.5">
              {PERKS.map((p) => (
                <li key={p.text} className="flex items-center gap-3 text-sm text-body/85">
                  <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-white/15 bg-white/5 text-white">
                    <p.icon className="h-4 w-4" aria-hidden />
                  </span>
                  {p.text}
                </li>
              ))}
            </ul>
          </div>

          {/* auth pane */}
          <div className="flex flex-col justify-center p-7 sm:p-10">
            <p className="font-mono text-[10px] tracking-[0.28em] text-slate2">
              WELCOME BACK
            </p>
            <h1 className="mt-3 font-display text-3xl font-bold tracking-tight text-bone">
              Sign in to BugSeek
            </h1>
            <p className="mt-2.5 text-sm leading-relaxed text-body/80">
              New here or coming back — it's the same door. Your Google
              account is your BugSeek account.
            </p>

            <label className="mt-8 flex cursor-pointer items-start gap-3 text-sm leading-relaxed text-body/85">
              <input
                type="checkbox"
                checked={agreed}
                onChange={(e) => setAgreed(e.target.checked)}
                aria-required="true"
                className="mt-0.5 h-4 w-4 shrink-0 accent-white"
              />
              <span>
                I've read and agree to the{' '}
                <a
                  href="/privacy"
                  onClick={(e) => {
                    e.preventDefault();
                    navigate('/privacy');
                  }}
                  className="font-medium text-bone underline decoration-white/40 underline-offset-2 transition-colors hover:decoration-white"
                >
                  Privacy Policy
                </a>
                .{' '}
                <span className="text-slate2">Required to create your account.</span>
              </span>
            </label>

            <div className="mt-5">
              <LiquidGlassButton
                variant="glass"
                size="lg"
                disabled={!agreed}
                className={`w-full ${busy ? 'pointer-events-none opacity-60' : ''}`}
                onClick={beginSignIn}
                ariaLabel="Sign in with Google"
              >
                {busy ? (
                  <>
                    <Loader2 className="h-5 w-5 animate-spin" aria-hidden />
                    Sending you to Google…
                  </>
                ) : (
                  <>
                    <GoogleMark className="h-5 w-5" />
                    Sign in with Google
                  </>
                )}
              </LiquidGlassButton>
            </div>

            <div className="mt-7 flex items-center gap-3" aria-hidden>
              <span className="h-px flex-1 bg-white/10" />
              <span className="font-mono text-[10px] tracking-[0.22em] text-slate2">
                GOOGLE ONLY · NO PASSWORDS
              </span>
              <span className="h-px flex-1 bg-white/10" />
            </div>

            <p className="mt-6 text-center text-xs leading-relaxed text-slate2">
              We never see or store a password — Google handles the keys.
              <br />
              And the house rule still applies: only test targets you're
              authorized to test.
            </p>
          </div>
        </motion.div>
      </main>

      <footer className="relative z-10 pb-6 text-center font-mono text-[11px] text-slate2/70">
        © 2026 BugSeek AI — no bugs were harmed
      </footer>
    </div>
  );
}
