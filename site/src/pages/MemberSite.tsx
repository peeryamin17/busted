import { ArrowRight, CheckCircle2 } from 'lucide-react';
import { Bento } from '../components/Bento';
import { Download } from '../components/Download';
import { Faq } from '../components/Faq';
import { Footer } from '../components/Footer';
import { Hero } from '../components/Hero';
import { HowItWorks } from '../components/HowItWorks';
import { MemberShell, type MemberIdentity } from '../components/MemberShell';
import { Nav } from '../components/Nav';
import { Pricing } from '../components/Pricing';
import { Reveal } from '../components/Reveal';
import { Swarm } from '../components/Swarm';
import { Ticker } from '../components/Ticker';
import { CrowdCanvas } from '../components/fx/CrowdCanvas';
import { LiquidGlassButton } from '../components/fx/LiquidGlassButton';
import { SonarGrid } from '../components/fx/SonarGrid';
import { navigate } from '../lib/router';

function ConnectSiteCard({ identity }: { identity: MemberIdentity }) {
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
                Your Google identity is connected. Next, BugSeek will verify a
                website belongs to you before any authorised checks unlock.
              </p>
              {identity.email && (
                <p className="mt-4 inline-flex items-center gap-2 rounded-full border border-signal/30 bg-signal/10 px-3 py-1.5 font-mono text-xs text-signal">
                  <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
                  Google connected · {identity.email}
                </p>
              )}
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
 * The main BugSeek site — available only after Google sign-in. The public
 * web gets the locked entrance; members get the whole product story here,
 * starting with a greeting from their Google profile.
 */
export function MemberSite() {
  return (
    <MemberShell>
      {(identity) => (
        <div className="min-h-screen bg-ink text-body">
          <a
            href="#what"
            className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-[60] focus:rounded-lg focus:bg-mint focus:px-4 focus:py-2 focus:text-ink"
          >
            Skip to content
          </a>
          <SonarGrid />
          <Nav variant="member" />
          <main className="relative z-10">
            <Hero memberName={identity.displayName} />
            <Ticker />
            <ConnectSiteCard identity={identity} />
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
      )}
    </MemberShell>
  );
}
