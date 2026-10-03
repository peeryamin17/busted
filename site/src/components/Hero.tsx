import { motion, useReducedMotion } from 'framer-motion';
import { ArrowRight, Gauge, Radar, ShieldCheck } from 'lucide-react';
import { ScanDemo } from './ScanDemo';
import { BorderBeam } from './fx/BorderBeam';
import { ContainerScroll } from './fx/ContainerScroll';
import { FlipWords } from './fx/FlipWords';
import { LiquidGlassButton } from './fx/LiquidGlassButton';
import { springQuiet } from '../lib/motion';
import { navigate } from '../lib/router';

const ROTATE = ['scanners', 'templates', 'checklists', 'crawlers'];

const STATS = [
  { icon: Radar, label: '9 specialist agents' },
  { icon: Gauge, label: '0–100 security score' },
  { icon: ShieldCheck, label: 'CVSS on every finding' },
];

/**
 * The showpiece: a live sonar grid behind a flip-words headline, and
 * the interactive scan demo framed by a travelling border beam.
 * Tap the black anywhere — the sonar answers.
 */
export function Hero({ memberName, teaser = false }: { memberName?: string; teaser?: boolean }) {
  const reduce = useReducedMotion();
  const rise = (delay: number) => ({
    initial: reduce ? (false as const) : { opacity: 0, y: 18 },
    animate: { opacity: 1, y: 0 },
    transition: { ...springQuiet, delay },
  });

  return (
    <section id="top" className="relative overflow-hidden pb-16 pt-36 sm:pt-44">
      {/* soft wash keeps hero copy legible while the sonar rings pass underneath */}
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_55%_50%_at_50%_42%,rgba(5,5,5,0.72)_0%,transparent_100%)]" />
      <div className="pointer-events-none absolute inset-x-0 bottom-0 h-40 bg-gradient-to-t from-ink to-transparent" />
      <div className="relative mx-auto max-w-6xl px-4 sm:px-6">
        <div className="mx-auto max-w-3xl text-center">
          <motion.div
            {...rise(0.05)}
            className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-white/5 px-3.5 py-1.5 font-mono text-xs"
          >
            <span className="h-1.5 w-1.5 rounded-full bg-white pulse-dot" />
            <span className="text-shiny font-semibold tracking-wide">AI SECURITY RECON · CHROME EXTENSION</span>
          </motion.div>

          {memberName && (
            <motion.p {...rise(0.2)} className="mt-6 font-display text-xl font-semibold tracking-tight text-bone sm:text-2xl">
              Welcome back, {memberName}. <span className="text-slate2">The full site is unlocked.</span>
            </motion.p>
          )}

          <motion.h1
            {...rise(memberName ? 0.24 : 0.14)}
            className="mt-7 font-display text-[2.85rem] font-bold leading-[1.03] tracking-tight text-bone sm:text-6xl lg:text-[4.6rem]"
          >
            Find what{' '}
            <FlipWords words={ROTATE} className="text-white underline decoration-white/30 decoration-[0.06em] underline-offset-[0.14em]" />{' '}
            miss.
          </motion.h1>

          <motion.p {...rise(0.26)} className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-body/90">
            BugSeek AI is the security researcher in your browser. One click maps a
            target's attack surface — passive recon for free, guided active testing
            when you're authorized, and an AI agent swarm for the deep stuff.
          </motion.p>

          <motion.div {...rise(0.36)} className="mt-9 flex flex-wrap items-center justify-center gap-4">
            {teaser ? (
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
            ) : (
              <>
                <LiquidGlassButton
                  href="/app/connect"
                  size="lg"
                  onClick={(e) => {
                    e.preventDefault();
                    navigate('/app/connect');
                  }}
                >
                  Connect a website
                </LiquidGlassButton>
                <LiquidGlassButton href="#download" variant="glass" size="lg">
                  Get it for Chrome
                </LiquidGlassButton>
              </>
            )}
          </motion.div>

          <motion.p {...rise(0.46)} className="mt-5 font-mono text-xs text-slate2">
            Only ever scan targets you're authorized to test. Seriously.
          </motion.p>

          <motion.ul {...rise(0.54)} className="mt-9 flex flex-wrap items-center justify-center gap-x-7 gap-y-2.5">
            {STATS.map((s) => (
              <li key={s.label} className="flex items-center gap-2 font-mono text-xs text-slate2">
                <s.icon className="h-3.5 w-3.5 text-white" aria-hidden />
                {s.label}
              </li>
            ))}
          </motion.ul>
        </div>

        <ContainerScroll className="mx-auto mt-14 max-w-3xl">
          <motion.div
            initial={reduce ? false : { opacity: 0, y: 40, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ ...springQuiet, delay: 0.42 }}
          >
            <BorderBeam>
              <ScanDemo bare />
            </BorderBeam>
            <p className="mt-3 text-center font-mono text-[11px] text-slate2">
              simulated scan — the real thing runs in your browser
            </p>
          </motion.div>
        </ContainerScroll>
      </div>
    </section>
  );
}
