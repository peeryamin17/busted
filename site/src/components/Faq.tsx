import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import { Plus } from 'lucide-react';
import { useState } from 'react';
import { Reveal } from './Reveal';
import { springQuiet } from '../lib/motion';

const FAQS = [
  {
    q: 'Is this legal?',
    a: "On targets you're authorized to test — yes. That's why passive recon runs free with no gate, while active testing and the swarm demand an explicit authorization confirmation (bug bounty program, pentest contract, or your own site) and a scope you define, enforced on every request. BugSeek won't fire a single probe without it, and neither should you.",
  },
  {
    q: 'Do I need the backend?',
    a: 'No. The extension is fully self-contained for passive recon — DOM, scripts, cookies, storage, headers, reports, all in your browser. The backend only powers the AI swarm and AI deepening of findings. No account, no backend, still a very good scanner.',
  },
  {
    q: 'What are credits?',
    a: 'The unit of work. A passive scan costs 1 credit; a full AI swarm run costs 25. Plans refill monthly — Scout is free with 50, Hunter is $29 for 300, Pro is $99 for 1,500. Credits throttle the expensive AI work so the pricing can stay student-shaped.',
  },
  {
    q: 'Is my data sent anywhere?',
    a: "Passive scans never leave your browser. Swarm runs send the target URL and the agents' findings to the BugSeek backend — that's where the agents live — and get back the summary, scores and suggested fixes. Rule of thumb: don't point it at anything you wouldn't paste into a bug report.",
  },
  {
    q: 'Will it spam the target?',
    a: 'No. Active checks are rate-limited and non-destructive by design, probes use canary markers instead of real payloads where possible, and scope exclusions (paths, hosts) are hard stops. It behaves like a polite researcher, not a fuzzer having a bad day.',
  },
  {
    q: 'When can I download it?',
    a: "Very soon — it's headed to the Chrome Web Store. Leave an email in the big friendly section below and it lands on a real list this time: written to once at launch, never before, never after. Which is more honesty than most waitlists offer.",
  },
];

/**
 * Numbered FAQ accordion in the spirit of 21st.dev's own homepage FAQ:
 * big index numerals, one panel open at a time, spring-animated height.
 */
export function Faq() {
  const reduce = useReducedMotion();
  const [open, setOpen] = useState<number | null>(0);

  return (
    <section id="faq" className="mx-auto max-w-4xl scroll-mt-24 px-4 py-24 sm:px-6 sm:py-32">
      <Reveal className="text-center">
        <p className="font-mono text-xs tracking-[0.2em] text-mint">QUESTIONS, ANSWERED</p>
        <h2 className="mt-3 font-display text-4xl font-bold tracking-tight text-bone sm:text-5xl">
          Asked by every hunter.
        </h2>
      </Reveal>

      <div className="mt-12 divide-y divide-white/10 border-y border-white/10">
        {FAQS.map((f, i) => {
          const isOpen = open === i;
          return (
            <Reveal key={f.q} delay={i * 0.04}>
              <div>
                <button
                  type="button"
                  onClick={() => setOpen(isOpen ? null : i)}
                  aria-expanded={isOpen}
                  aria-controls={`faq-panel-${i}`}
                  className="flex w-full items-center gap-4 py-5 text-left sm:gap-6 sm:py-6"
                >
                  <span
                    className={`font-display text-sm font-bold tabular-nums transition-colors ${
                      isOpen ? 'text-mint' : 'text-slate2'
                    }`}
                  >
                    {String(i + 1).padStart(2, '0')}
                  </span>
                  <span
                    className={`flex-1 font-display text-lg font-semibold transition-colors sm:text-xl ${
                      isOpen ? 'text-bone' : 'text-body/85'
                    }`}
                  >
                    {f.q}
                  </span>
                  <motion.span
                    animate={{ rotate: isOpen ? 45 : 0 }}
                    transition={springQuiet}
                    className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full border ${
                      isOpen ? 'border-mint/40 bg-mint/10 text-mint' : 'border-white/15 text-body/70'
                    }`}
                  >
                    <Plus className="h-4 w-4" aria-hidden />
                  </motion.span>
                </button>
                <AnimatePresence initial={false}>
                  {isOpen && (
                    <motion.div
                      id={`faq-panel-${i}`}
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={reduce ? { duration: 0 } : springQuiet}
                      className="overflow-hidden"
                    >
                      <p className="max-w-3xl pb-6 pl-9 pr-2 text-[15px] leading-relaxed text-body/85 sm:pl-12">
                        {f.a}
                      </p>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </Reveal>
          );
        })}
      </div>
    </section>
  );
}
