import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import { BellRing } from 'lucide-react';
import { useState } from 'react';
import { Reveal } from './Reveal';
import { LiquidGlassButton } from './fx/LiquidGlassButton';
import { springPop, springQuiet } from '../lib/motion';

/**
 * The drop: aurora-lit CTA block with the world's most honest waitlist.
 * The store listing doesn't exist yet — the copy says so, loudly.
 */
export function Download() {
  const reduce = useReducedMotion();
  const [email, setEmail] = useState('');
  const [noted, setNoted] = useState(false);

  return (
    <section id="download" className="relative scroll-mt-24 overflow-hidden py-28 sm:py-36">
      {/* aurora backdrop — white glow, drifting on transform */}
      <div aria-hidden className="pointer-events-none absolute inset-0 overflow-hidden">
        <div
          className="aurora absolute left-1/2 top-1/2 h-[460px] w-[820px] -translate-x-1/2 -translate-y-1/2 rounded-full opacity-[0.12] blur-[110px]"
          style={{ background: 'radial-gradient(closest-side, #FFFFFF, transparent)' }}
        />
        <div className="grid-bg grid-mask-center absolute inset-0 opacity-60" />
      </div>

      <div className="relative mx-auto max-w-3xl px-4 text-center sm:px-6">
        <Reveal>
          <motion.img
            src="/bug.svg"
            alt="BugSeek AI logo"
            className="mx-auto h-20 w-20"
            whileHover={reduce ? undefined : { rotate: -8, scale: 1.06 }}
            transition={springPop}
          />
          <p className="mt-6 font-mono text-xs tracking-[0.2em] text-mint">THE DROP</p>
          <h2 className="mt-3 font-display text-5xl font-bold tracking-tight text-bone sm:text-6xl">
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
                    <LiquidGlassButton type="submit" size="md" className="shrink-0">
                      <BellRing className="h-4 w-4" aria-hidden />
                      Remind me
                    </LiquidGlassButton>
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
