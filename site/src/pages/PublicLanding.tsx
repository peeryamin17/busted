import { useAuth } from '@clerk/clerk-react';
import { ArrowRight, Globe2, LockKeyhole, UserRoundPlus } from 'lucide-react';
import { Nav } from '../components/Nav';
import { Reveal } from '../components/Reveal';
import { LiquidGlassButton } from '../components/fx/LiquidGlassButton';
import { SonarGrid } from '../components/fx/SonarGrid';
import { CLERK_ENABLED } from '../lib/clerk';
import { navigate } from '../lib/router';

const DOORS = [
  {
    n: '01',
    icon: UserRoundPlus,
    title: 'Sign up',
    body: 'One Google account gets you through the door. No BugSeek password to invent or forget.',
  },
  {
    n: '02',
    icon: LockKeyhole,
    title: 'Stay private',
    body: 'The product details, workspace and member site stay hidden until you are signed in.',
  },
  {
    n: '03',
    icon: Globe2,
    title: 'Connect what’s yours',
    body: 'Next, members will connect a website they own and unlock the authorised workspace.',
  },
];

function go(to: string) {
  return (e: { preventDefault: () => void }) => {
    e.preventDefault();
    navigate(to);
  };
}

function LandingActionsStatic() {
  return (
    <>
      <LiquidGlassButton href="/signup" size="lg" onClick={go('/signup')}>
        Sign up with Google
      </LiquidGlassButton>
      <LiquidGlassButton href="/signin" variant="glass" size="lg" onClick={go('/signin')}>
        Sign in
      </LiquidGlassButton>
    </>
  );
}

function LandingActionsClerk() {
  const { isLoaded, isSignedIn } = useAuth();
  if (isLoaded && isSignedIn) {
    return (
      <LiquidGlassButton href="/app" size="lg" onClick={go('/app')}>
        Open BugSeek <ArrowRight className="h-4 w-4" aria-hidden />
      </LiquidGlassButton>
    );
  }
  return <LandingActionsStatic />;
}

function LandingActions() {
  return CLERK_ENABLED ? <LandingActionsClerk /> : <LandingActionsStatic />;
}

/**
 * The public entrance: intentionally minimal and a little secretive.
 * One screen explains how to get in; everything worth seeing sits behind
 * Google authentication on /app.
 */
export function PublicLanding() {
  return (
    <div className="relative min-h-screen overflow-hidden bg-ink text-body">
      <SonarGrid />
      <Nav variant="public" />

      <main className="relative z-10">
        <section id="top" className="mx-auto flex min-h-[92vh] max-w-6xl flex-col items-center justify-center px-4 pb-20 pt-36 text-center sm:px-6">
          <Reveal>
            <img src="/bug.svg" alt="BugSeek AI logo" className="mx-auto h-16 w-16 sm:h-20 sm:w-20" />
            <p className="mt-8 inline-flex items-center gap-2 rounded-full border border-white/20 bg-white/5 px-3.5 py-1.5 font-mono text-[11px] font-semibold tracking-[0.18em] text-bone">
              <LockKeyhole className="h-3.5 w-3.5" aria-hidden />
              MEMBERS ONLY · PRIVATE BETA
            </p>
            <h1 className="mt-7 font-display text-6xl font-bold leading-none tracking-tight text-bone sm:text-7xl lg:text-8xl">
              BugSeek <span className="text-white/40">AI</span>
            </h1>
            <p className="mt-6 font-display text-3xl font-semibold tracking-tight text-bone sm:text-4xl">
              Find what scanners miss.
            </p>
            <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-body/85">
              The rest is behind the door. Sign up with Google and the full
              BugSeek site unlocks — no password, no public tour.
            </p>
            <div className="mt-9 flex flex-wrap items-center justify-center gap-3.5">
              <LandingActions />
            </div>
            <p className="mt-6 font-mono text-[11px] tracking-[0.18em] text-slate2">
              GOOGLE ACCOUNT REQUIRED · ONLY TEST WHAT YOU'RE AUTHORISED TO TEST
            </p>
          </Reveal>
        </section>

        <section className="relative mx-auto max-w-6xl px-4 pb-24 sm:px-6" aria-label="How entry works">
          <div className="grid gap-4 md:grid-cols-3">
            {DOORS.map((door, i) => (
              <Reveal key={door.n} delay={i * 0.07}>
                <article className="glass h-full rounded-[1.5rem] p-6 text-left">
                  <div className="flex items-center justify-between">
                    <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-white/15 bg-white/5 text-white">
                      <door.icon className="h-5 w-5" aria-hidden />
                    </span>
                    <span className="font-mono text-xs text-slate2">{door.n}</span>
                  </div>
                  <h2 className="mt-5 font-display text-xl font-semibold text-bone">{door.title}</h2>
                  <p className="mt-2 text-sm leading-relaxed text-body/80">{door.body}</p>
                </article>
              </Reveal>
            ))}
          </div>
        </section>
      </main>

      <footer className="relative z-10 border-t border-white/10 px-4 py-7 sm:px-6">
        <div className="mx-auto flex max-w-6xl flex-col gap-2 font-mono text-[11px] text-slate2 sm:flex-row sm:items-center sm:justify-between">
          <p>© 2026 BugSeek AI — no bugs were harmed.</p>
          <p>Members only beyond this point.</p>
        </div>
      </footer>
    </div>
  );
}
