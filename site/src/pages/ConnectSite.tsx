import { CheckCircle2, Globe2, KeyRound, LockKeyhole } from 'lucide-react';
import { Footer } from '../components/Footer';
import { MemberShell } from '../components/MemberShell';
import { Nav } from '../components/Nav';
import { Reveal } from '../components/Reveal';
import { LiquidGlassButton } from '../components/fx/LiquidGlassButton';
import { SonarGrid } from '../components/fx/SonarGrid';
import { navigate } from '../lib/router';

const STEPS = [
  {
    icon: CheckCircle2,
    state: 'DONE',
    title: 'Google account connected',
    body: 'Your identity is in. BugSeek can greet you by name and keep your member workspace tied to one account.',
    tone: 'text-signal border-signal/30 bg-signal/10',
  },
  {
    icon: KeyRound,
    state: 'NEXT',
    title: 'Verify the website is yours',
    body: 'Before anything is tested, BugSeek will ask for ownership proof — the authorised-workspace step we are building next.',
    tone: 'text-sky2 border-sky2/30 bg-sky2/10',
  },
  {
    icon: LockKeyhole,
    state: 'LOCKED',
    title: 'Authorised checks unlock after that',
    body: 'No ownership, no active checks. That rule keeps BugSeek useful to hunters and unwelcome to everyone else.',
    tone: 'text-body/75 border-white/15 bg-white/5',
  },
];

/**
 * The next authorised page: website connection. Authentication is live;
 * ownership verification is deliberately shown as the next step rather
 * than pretending the full workspace already exists.
 */
export function ConnectSite() {
  return (
    <MemberShell>
      {(identity) => (
        <div className="min-h-screen bg-ink text-body">
          <SonarGrid />
          <Nav variant="member" />
          <main className="relative z-10 mx-auto max-w-6xl px-4 pb-24 pt-36 sm:px-6 sm:pt-44">
            <Reveal className="mx-auto max-w-3xl text-center">
              <p className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-white/5 px-3.5 py-1.5 font-mono text-[11px] font-semibold tracking-[0.18em] text-bone">
                <Globe2 className="h-3.5 w-3.5" aria-hidden />
                AUTHORISED WORKSPACE
              </p>
              <h1 className="mt-7 font-display text-5xl font-bold leading-none tracking-tight text-bone sm:text-6xl">
                Connect a website, {identity.displayName}.
              </h1>
              <p className="mx-auto mt-5 max-w-2xl text-lg leading-relaxed text-body/85">
                This is where a member will bring a site they own. First comes
                proof of ownership; only then do BugSeek's authorised tools open up.
              </p>
              {identity.email && (
                <p className="mt-5 font-mono text-xs text-slate2">
                  Signed in with Google as {identity.email}
                </p>
              )}
            </Reveal>

            <div className="mt-14 grid gap-5 md:grid-cols-3">
              {STEPS.map((step, i) => (
                <Reveal key={step.title} delay={i * 0.07}>
                  <article className="glass h-full rounded-[1.5rem] p-6">
                    <div className="flex items-center justify-between">
                      <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-mono text-[10px] font-bold tracking-[0.14em] ${step.tone}`}>
                        <step.icon className="h-3.5 w-3.5" aria-hidden />
                        {step.state}
                      </span>
                      <span className="font-mono text-xs text-slate2">0{i + 1}</span>
                    </div>
                    <h2 className="mt-6 font-display text-2xl font-semibold tracking-tight text-bone">
                      {step.title}
                    </h2>
                    <p className="mt-3 text-sm leading-relaxed text-body/85">{step.body}</p>
                  </article>
                </Reveal>
              ))}
            </div>

            <Reveal delay={0.12} className="mx-auto mt-8 max-w-3xl">
              <div className="glass rounded-[1.75rem] p-7 text-center sm:p-9">
                <h2 className="font-display text-2xl font-semibold tracking-tight text-bone">
                  Website connection opens next.
                </h2>
                <p className="mx-auto mt-3 max-w-xl text-sm leading-relaxed text-body/85">
                  Authentication had to land first. The next build is ownership
                  verification, then this page becomes the place where members
                  connect a domain and choose what BugSeek may check.
                </p>
                <div className="mt-7 flex flex-wrap justify-center gap-3">
                  <LiquidGlassButton
                    href="/app"
                    onClick={(e) => {
                      e.preventDefault();
                      navigate('/app');
                    }}
                  >
                    Back to the main site
                  </LiquidGlassButton>
                  <LiquidGlassButton
                    href="/app#download"
                    variant="glass"
                    onClick={(e) => {
                      e.preventDefault();
                      navigate('/app#download');
                    }}
                  >
                    Get the extension
                  </LiquidGlassButton>
                </div>
              </div>
            </Reveal>
          </main>
          <Footer member />
        </div>
      )}
    </MemberShell>
  );
}
