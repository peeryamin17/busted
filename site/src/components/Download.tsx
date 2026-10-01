import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import { useState } from 'react';
import { Reveal } from './Reveal';
import { springPop, springQuiet } from '../lib/motion';

export function Download() {
  const reduce = useReducedMotion();
  const [email, setEmail] = useState('');
  const [noted, setNoted] = useState(false);

  return (
    <section id="download" className="relative scroll-mt-24 overflow-hidden py-24 sm:py-32">
      <div
        aria-hidden
        className="pointer-events-none absolute left-1/2 top-1/2 h-[420px] w-[720px] -translate-x-1/2 -translate-y-1/2 rounded-full opacity-[0.1] blur-[120px]"
        style={{ background: 'radial-gradient(closest-side, #34D399, transparent)' }}
      />
      <div className="relative mx-auto max-w-3xl px-4 text-center sm:px-6">
        <Reveal>
          <img src="/bug.svg" alt="BugSeek AI logo" className="mx-auto h-20 w-20" />
          <p className="mt-6 font-mono text-xs tracking-[0.2em] text-mint">THE DROP</p>
          <h2 className="mt-3 font-display text-4xl font-bold tracking-tight text-bone sm:text-6xl">
            Ready when
            <br />
            you are.
          </h2>
          <p className="mx-auto mt-5 max-w-xl text-lg text-body/85">
            BugSeek AI is landing on the Chrome Web Store soon. We're polishing the
            last findings — the bugs aren't going anywhere.
          </p>
        </Reveal>

        <Reveal delay={0.1}>
          <div className="glass mx-auto mt-10 max-w-md rounded-3xl p-6">
            <p className="font-mono text-xs text-slate2">COMING SOON TO THE CHROME WEB STORE</p>
            <div className="mt-4 min-h-[52px]">
              <AnimatePresence mode="wait" initial={false}>
                {noted ? (
                  <motion.p
                    key="noted"
                    initial={reduce ? false : { opacity: 0, scale: 0.94 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={springPop}
                    className="rounded-2xl border border-mint/30 bg-mint/10 px-4 py-3 text-sm text-mint"
                  >
                    You're on the list.*
                    <span className="mt-1 block font-mono text-[11px] text-slate2">
                      *there is no list yet — we're a student project, remember?
                    </span>
                  </motion.p>
                ) : (
                  <motion.form
                    key="form"
                    exit={reduce ? undefined : { opacity: 0, scale: 0.96 }}
                    transition={springQuiet}
                    className="flex gap-2"
                    onSubmit={(e) => {
                      e.preventDefault();
                      if (email.trim()) setNoted(true);
                    }}
                  >
                    <label htmlFor="notify-email" className="sr-only">
                      Email for launch notification
                    </label>
                    <input
                      id="notify-email"
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="you@hunter.dev"
                      className="min-w-0 flex-1 rounded-2xl border border-white/10 bg-ink px-4 py-3 text-sm text-bone placeholder:text-slate2 focus:border-mint/50 focus:outline-none"
                    />
                    <motion.button
                      type="submit"
                      whileTap={{ scale: 0.97, transition: { duration: 0.1 } }}
                      whileHover={{ scale: 1.03 }}
                      transition={springQuiet}
                      className="shrink-0 rounded-2xl bg-mint px-5 py-3 font-display text-sm font-semibold text-ink"
                    >
                      Remind me
                    </motion.button>
                  </motion.form>
                )}
              </AnimatePresence>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
