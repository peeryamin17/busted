import { ArrowRight } from 'lucide-react';
import { Bento } from '../components/Bento';
import { Download } from '../components/Download';
import { Faq } from '../components/Faq';
import { Footer } from '../components/Footer';
import { Hero } from '../components/Hero';
import { HowItWorks } from '../components/HowItWorks';
import { Nav } from '../components/Nav';
import { Pricing } from '../components/Pricing';
import { Reveal } from '../components/Reveal';
import { Swarm } from '../components/Swarm';
import { Ticker } from '../components/Ticker';
import { CrowdCanvas } from '../components/fx/CrowdCanvas';
import { LiquidGlassButton } from '../components/fx/LiquidGlassButton';
import { SonarGrid } from '../components/fx/SonarGrid';
import { navigate } from '../lib/router';

function ConnectSiteCard() {
  return (
    <section className="relative mx-auto max-w-6xl px-4 py-12 sm:px-6" aria-label="Connect a website">
      <Reveal>
        <div className="glass overflow-hidden rounded-[2rem] p-7 sm:p-9">
          <div className="grid items-center gap-8 lg:grid-cols-[1.15fr_0.85fr]">
            <div>
              <p className="font-mono text-[11px] tracking-[0.24em] text-slate2">
                NEXT AUTHORISED WORKSPACE
              </p>
              <h2 className="mt-3 font-display text-3xl font-bold tracking-tight text-bone sm:text-4xl">
                Connect a website you own.
              </h2>
              <p className="mt-3 max-w-xl leading-relaxed text-body/85">
                BugSeek will verify a website belongs to you before any
                authorised checks unlock.
              </p>
            </div>
            <div className="lg:text-right">
              <LiquidGlassButton
                href="/app/connect"
                size="lg"
                onClick={(e) => {
                  e.preventDefault();
                  navigate('/app/connect');
                }}
              >
                Prepare website connection <ArrowRight className="h-4 w-4" aria-hidden />
              </LiquidGlassButton>
              <p className="mt-3 font-mono text-[11px] leading-relaxed text-slate2">
                Ownership verification comes before testing. Always.
              </p>
            </div>
          </div>
        </div>
      </Reveal>
    </section>
  );
}

/**
 * The main BugSeek site — the whole product story, open to everyone.
 * This used to sit behind Google sign-in; the door is gone and this is
 * simply the front page now.
 */
export function MemberSite() {
  return (
    <div className="min-h-screen bg-ink text-body">
      <a
        href="#what"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-[60] focus:rounded-lg focus:bg-mint focus:px-4 focus:py-2 focus:text-ink"
      >
        Skip to content
      </a>
      <SonarGrid />
      <Nav />
      <main className="relative z-10">
        <Hero />
        <Ticker />
        <ConnectSiteCard />
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
