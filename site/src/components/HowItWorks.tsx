import { motion, useReducedMotion, useScroll, useSpring } from 'framer-motion';
import { useRef } from 'react';
import { Reveal } from './Reveal';

const STEPS = [
  {
    n: '01',
    title: 'Install',
    body: "Add it to Chrome. Thirty seconds, no account needed to start poking around.",
    code: 'chrome web store → add → pin it',
  },
  {
    n: '02',
    title: 'Scan',
    body: "Open a target you're allowed to test and hit “Scan this page”. Passive recon runs right in the popup — DOM, scripts, cookies, storage, headers, the lot.",
    code: '1 click · 1 credit · 0 probes fired',
  },
  {
    n: '03',
    title: 'Authorize',
    body: 'Want active tests or the swarm? Confirm your authorization — bounty program, pentest contract, or ownership — and set the scope. Nothing fires without it.',
    code: 'scope-checked · rate-limited · non-destructive',
  },
  {
    n: '04',
    title: 'Report',
    body: 'Export a report with CVSS scores, repro steps and AI-suggested fixes. Paste it into HackerOne and look like you have a team. You do — it\'s nine robots.',
    code: 'markdown · json · pdf · docx',
  },
];

/**
 * The manual, as a timeline: a mint beam fills the rail as you scroll
 * (scroll-linked, spring-smoothed, transform-only), steps alternating
 * sides on desktop and stacking on mobile.
 */
export function HowItWorks() {
  const reduce = useReducedMotion();
  const railRef = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({
    target: railRef,
    offset: ['start 75%', 'end 55%'],
  });
  const fill = useSpring(scrollYProgress, { stiffness: 90, damping: 24, mass: 0.4 });

  return (
    <section id="how" className="mx-auto max-w-6xl scroll-mt-24 px-4 py-24 sm:px-6 sm:py-32">
      <Reveal>
        <p className="font-mono text-xs tracking-[0.2em] text-mint">THE MANUAL (SHORT)</p>
        <h2 className="mt-3 font-display text-4xl font-bold tracking-tight text-bone sm:text-5xl">
          Zero to report in four steps.
        </h2>
        <p className="mt-4 max-w-2xl text-lg text-body/85">
          That's the whole learning curve. If you can browse, you can hunt.
        </p>
      </Reveal>

      <div ref={railRef} className="relative mt-16">
        {/* rail */}
        <div aria-hidden className="absolute bottom-2 left-[19px] top-2 w-px bg-white/10 lg:left-1/2" />
        <motion.div
          aria-hidden
          className="absolute bottom-2 left-[19px] top-2 w-px origin-top bg-mint shadow-[0_0_12px_rgba(255,255,255,0.35)] lg:left-1/2"
          style={reduce ? { scaleY: 1 } : { scaleY: fill }}
        />

        <ol className="space-y-10 lg:space-y-0">
          {STEPS.map((s, i) => {
            const left = i % 2 === 0;
            return (
              <li key={s.n} className="relative lg:grid lg:grid-cols-2 lg:gap-16 lg:py-7">
                {/* node */}
                <span
                  aria-hidden
                  className="absolute left-[19px] top-7 z-10 flex h-10 w-10 -translate-x-1/2 items-center justify-center rounded-full border border-mint/40 bg-ink font-display text-xs font-bold text-mint lg:left-1/2 lg:top-1/2 lg:-translate-y-1/2"
                >
                  {s.n}
                </span>
                <Reveal
                  delay={0.05}
                  className={`pl-14 lg:pl-0 ${left ? 'lg:col-start-1 lg:pr-4' : 'lg:col-start-2 lg:pl-4'}`}
                >
                  <article className="rounded-3xl border border-white/10 bg-panel p-6 sm:p-7">
                    <h3 className="font-display text-2xl font-semibold text-bone">{s.title}</h3>
                    <p className="mt-2 text-[15px] leading-relaxed text-body/85">{s.body}</p>
                    <p className="mt-5 w-fit rounded-lg bg-white/5 px-3 py-2 font-mono text-[11px] text-mintlight/90">
                      {s.code}
                    </p>
                  </article>
                </Reveal>
              </li>
            );
          })}
        </ol>
      </div>

      <Reveal delay={0.1}>
        <div className="mt-14 flex items-start gap-4 rounded-2xl border border-amber2/25 bg-amber2/10 p-5">
          <span aria-hidden className="text-2xl leading-none">⚑</span>
          <p className="text-sm leading-relaxed text-body/90">
            <span className="font-semibold text-amber2">It'll also save you from yourself.</span>{' '}
            If something looks like a honeypot — say, /admin accepting admin:admin on the
            first try — BugSeek flags it as a possible trap instead of letting you
            report a canary and embarrass yourself. You're welcome.
          </p>
        </div>
      </Reveal>
    </section>
  );
}
