import { animate, motion, useMotionValue, useReducedMotion, useTransform } from 'framer-motion';
import { Check, Loader2 } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

const STEPS = ['Creating your workspace…', 'Syncing credits…', 'Arming the swarm…'];

/**
 * The intentional pause after "Continue with Google" (in the spirit of
 * 21st.dev's @kokonutd/loader): a deliberate, premium loading screen —
 * big percentage, a filling bar, and status lines that tick themselves
 * off one by one. The lines are ambience for the handoff moment; no
 * account claims are made here.
 */
export function LoaderScreen({ onComplete }: { onComplete: () => void }) {
  const reduce = useReducedMotion();
  const [pct, setPct] = useState(0);
  const bar = useMotionValue(0);
  const barScale = useTransform(bar, (v) => v / 100);
  const calledRef = useRef(false);

  useEffect(() => {
    const duration = reduce ? 0.5 : 2.8;
    const controls = animate(0, 100, {
      duration,
      ease: [0.65, 0, 0.35, 1],
      onUpdate: (v) => {
        setPct(Math.floor(v));
        bar.set(v);
      },
      onComplete: () => {
        if (calledRef.current) return;
        calledRef.current = true;
        setTimeout(onComplete, 200);
      },
    });
    return () => controls.stop();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reduce]);

  const doneCount = pct >= 100 ? 3 : Math.floor(pct / 34);

  return (
    <motion.div
      role="status"
      aria-label="Setting up your BugSeek workspace"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.35 }}
      className="fixed inset-0 z-[90] flex flex-col items-center justify-center bg-[#050505] px-6"
    >
      {/* mark inside a slow-spinning dashed ring */}
      <div className="relative flex h-28 w-28 items-center justify-center">
        <span
          aria-hidden
          className={`absolute inset-0 rounded-full border border-dashed border-white/25 ${reduce ? '' : 'animate-[spin_14s_linear_infinite]'}`}
        />
        <span aria-hidden className="absolute inset-3 rounded-full border border-white/10" />
        <img src="/bug.svg" alt="" className="h-12 w-12" />
      </div>

      <p className="mt-8 font-display text-5xl font-bold tabular-nums tracking-tight text-white">
        {pct}
        <span className="text-xl text-slate2">%</span>
      </p>

      {/* progress bar */}
      <div className="mt-5 h-[3px] w-60 overflow-hidden rounded-full bg-white/10">
        <motion.div className="h-full w-full origin-left bg-white" style={{ scaleX: barScale }} />
      </div>

      {/* status lines — spinner becomes a check as each step lands */}
      <ul className="mt-9 space-y-3.5" aria-live="polite">
        {STEPS.map((step, i) => {
          const done = i < doneCount;
          const current = i === doneCount && pct < 100;
          return (
            <li
              key={step}
              className={`flex items-center gap-3 font-mono text-sm transition-colors duration-300 ${
                done || current ? 'text-bone' : 'text-slate2/60'
              }`}
            >
              <span
                className={`flex h-5 w-5 items-center justify-center rounded-full border ${
                  done ? 'border-white bg-white text-ink' : 'border-white/25 text-body'
                }`}
              >
                {done ? (
                  <Check className="h-3 w-3" aria-hidden />
                ) : current && !reduce ? (
                  <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
                ) : (
                  <span className="h-1 w-1 rounded-full bg-current" aria-hidden />
                )}
              </span>
              {step}
            </li>
          );
        })}
      </ul>

      <p className="mt-10 font-mono text-[10px] tracking-[0.24em] text-slate2/70">
        GOOD THINGS TAKE A SECOND
      </p>
    </motion.div>
  );
}
