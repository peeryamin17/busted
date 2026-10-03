import { ArrowRight } from 'lucide-react';
import { useEffect } from 'react';
import { Footer } from '../components/Footer';
import { Hero } from '../components/Hero';
import { Nav } from '../components/Nav';
import { Reveal } from '../components/Reveal';
import { Ticker } from '../components/Ticker';
import { LiquidGlassButton } from '../components/fx/LiquidGlassButton';
import { SonarGrid } from '../components/fx/SonarGrid';
import { useAuth } from '../lib/auth';
import { navigate } from '../lib/router';

/** Swap the current path without a page load (same pattern as /app). */
function replaceTo(to: string) {
  window.history.replaceState({}, '', to);
  window.dispatchEvent(new PopStateEvent('popstate'));
  window.scrollTo({ top: 0, behavior: 'auto' });
}

/**
 * The public front door: a trailer, not the film. New visitors get the
 * hero, its scan and the ticker — then a door. Everything past that
 * (the toolkit, the swarm, the whole working site) lives inside /app
 * behind Google sign-in. Members who land here are forwarded inside.
 */
export function Landing() {
  const { user } = useAuth();

  useEffect(() => {
    if (user) replaceTo('/app');
  }, [user]);

  return (
    <div className="min-h-screen bg-ink text-body">
      <SonarGrid />
      <Nav variant="landing" />
      <main className="relative z-10">
        <Hero teaser />
        <Ticker />
        <section className="relative mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20" aria-label="Sign in to enter">
          <Reveal>
            <div className="glass overflow-hidden rounded-[2rem] p-7 sm:p-10">
              <div className="grid items-center gap-8 lg:grid-cols-[1.15fr_0.85fr]">
                <div>
                  <p className="font-mono text-[11px] tracking-[0.24em] text-slate2">
                    THAT WAS THE TRAILER
                  </p>
                  <h2 className="mt-3 font-display text-3xl font-bold tracking-tight text-bone sm:text-4xl">
                    The rest of BugSeek is inside.
                  </h2>
                  <p className="mt-3 max-w-xl leading-relaxed text-body/85">
                    The toolkit, nine specialist agents, the swarm, pricing —
                    the whole working site lives past the door. One Google
                    click and you're in; BugSeek never sees a password,
                    because there isn't one.
                  </p>
                </div>
                <div className="lg:text-right">
                  <LiquidGlassButton
                    href="/signin"
                    size="lg"
                    onClick={(e) => {
                      e.preventDefault();
                      navigate('/signin');
                    }}
                  >
                    Sign in to enter <ArrowRight className="h-4 w-4" aria-hidden />
                  </LiquidGlassButton>
                  <p className="mt-3 font-mono text-[11px] leading-relaxed text-slate2">
                    Members only beyond this point. Obviously.
                  </p>
                </div>
              </div>
            </div>
          </Reveal>
        </section>
      </main>
      <div className="relative z-10">
        <Footer home />
      </div>
    </div>
  );
}
