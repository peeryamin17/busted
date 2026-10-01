import { motion, useReducedMotion } from 'framer-motion';
import { MaskedLine } from './Reveal';
import { ScanDemo } from './ScanDemo';
import { pressable, springQuiet } from '../lib/motion';

const STATS = ['9 specialist agents', 'CVSS on every finding', '1-click Markdown reports'];

export function Hero() {
  const reduce = useReducedMotion();
  return (
    <section id="top" className="relative overflow-hidden pt-32 sm:pt-40">
      {/* faint mint glow — atmosphere, not decoration */}
      <div
        aria-hidden
        className="pointer-events-none absolute -top-40 left-1/2 h-[480px] w-[820px] -translate-x-1/2 rounded-full opacity-[0.13] blur-[120px]"
        style={{ background: 'radial-gradient(closest-side, #34D399, transparent)' }}
      />
      <div className="relative mx-auto grid max-w-6xl items-center gap-12 px-4 sm:px-6 lg:grid-cols-[1.02fr_0.98fr] lg:gap-10">
        <div>
          <motion.div
            initial={reduce ? false : { opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={springQuiet}
            className="inline-flex items-center gap-2 rounded-full border border-mint/25 bg-mint/10 px-3.5 py-1.5 font-mono text-xs text-mint"
          >
            <span className="h-1.5 w-1.5 rounded-full bg-mint pulse-dot" />
            CHROME EXTENSION · MANIFEST V3
          </motion.div>

          <h1 className="mt-6 font-display text-[2.9rem] font-bold leading-[1.02] tracking-tight text-bone sm:text-6xl lg:text-[4.4rem]">
            <MaskedLine delay={0.08}>Find what</MaskedLine>
            <MaskedLine delay={0.16}>
              <span className="text-mint">scanners</span> miss.
            </MaskedLine>
          </h1>

          <motion.p
            initial={reduce ? false : { opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ ...springQuiet, delay: 0.28 }}
            className="mt-6 max-w-xl text-lg leading-relaxed text-body/90"
          >
            BugSeek AI is the security researcher in your browser. One click maps a
            target's attack surface — passive recon for free, guided active testing
            when you're authorized, and an AI agent swarm for the deep stuff.
          </motion.p>

          <motion.div
            initial={reduce ? false : { opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ ...springQuiet, delay: 0.38 }}
            className="mt-8 flex flex-wrap items-center gap-4"
          >
            <motion.a
              href="#download"
              {...pressable}
              className="rounded-2xl bg-mint px-7 py-3.5 font-display text-base font-semibold text-ink shadow-[0_16px_40px_-12px_rgba(52,211,153,0.55)]"
            >
              Get it for Chrome
            </motion.a>
            <motion.a
              href="#how"
              {...pressable}
              className="glass-soft rounded-2xl px-7 py-3.5 font-display text-base font-semibold text-bone"
            >
              See how it works
            </motion.a>
          </motion.div>

          <motion.p
            initial={reduce ? false : { opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ ...springQuiet, delay: 0.5 }}
            className="mt-5 font-mono text-xs text-slate2"
          >
            Only ever scan targets you're authorized to test. Seriously.
          </motion.p>

          <motion.ul
            initial={reduce ? false : { opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ ...springQuiet, delay: 0.58 }}
            className="mt-8 flex flex-wrap gap-x-6 gap-y-2"
          >
            {STATS.map((s) => (
              <li key={s} className="flex items-center gap-2 font-mono text-xs text-slate2">
                <span className="text-mint">▸</span> {s}
              </li>
            ))}
          </motion.ul>
        </div>

        <motion.div
          initial={reduce ? false : { opacity: 0, y: 32, scale: 0.98 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ ...springQuiet, delay: 0.3 }}
        >
          <ScanDemo />
          <p className="mt-3 text-center font-mono text-[11px] text-slate2">
            simulated scan — the real thing runs in your browser
          </p>
        </motion.div>
      </div>
    </section>
  );
}
