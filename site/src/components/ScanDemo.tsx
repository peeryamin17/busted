import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import { useCallback, useEffect, useRef, useState } from 'react';
import { springPop, springQuiet } from '../lib/motion';

type Sev = 'critical' | 'high' | 'medium' | 'low' | 'trap';

interface DemoFinding {
  sev: Sev;
  title: string;
  detail: string;
  cvss?: string;
}

const FINDINGS: DemoFinding[] = [
  {
    sev: 'critical',
    title: 'AWS secret key in bundle.js',
    detail: 'AKIA…(redacted) · hardcoded credential',
    cvss: '9.1',
  },
  {
    sev: 'high',
    title: 'Reflected XSS in ?search=',
    detail: 'input reflected unencoded in the response',
    cvss: '7.4',
  },
  {
    sev: 'medium',
    title: 'Content-Security-Policy missing',
    detail: 'no CSP header on any response',
    cvss: '5.3',
  },
  {
    sev: 'low',
    title: 'Exposed source map',
    detail: 'app.js.map ships the original sources',
  },
  {
    sev: 'trap',
    title: 'Possible trap — verify manually',
    detail: '/admin accepted admin:admin · smells like a canary',
  },
];

const PHASES = [
  'Reading the DOM…',
  'Mining JavaScript for secrets…',
  'Checking headers & cookies…',
  'Scoring findings…',
];

const SEV_STYLE: Record<Sev, { label: string; chip: string; bar: string }> = {
  critical: { label: 'CRITICAL', chip: 'bg-crit/15 text-crit border-crit/30', bar: 'bg-crit' },
  high: {
    label: 'HIGH',
    chip: 'bg-hot/15 text-hot border-hot/30',
    bar: 'bg-hot',
  },
  medium: { label: 'MEDIUM', chip: 'bg-amber2/15 text-amber2 border-amber2/30', bar: 'bg-amber2' },
  low: {
    label: 'LOW',
    chip: 'bg-mintlight/15 text-mintlight border-mintlight/30',
    bar: 'bg-mintlight',
  },
  trap: {
    label: 'POSSIBLE TRAP',
    chip: 'border-dashed bg-amber2/10 text-amber2 border-amber2/40',
    bar: 'bg-amber2',
  },
};

/**
 * Interactive mock scan — a glass card styled like the extension popup.
 * Findings pop in on springs as the "scan" progresses. Re-runnable.
 * Fully static when the user prefers reduced motion.
 */
export function ScanDemo() {
  const reduce = useReducedMotion();
  const [phase, setPhase] = useState(0);
  const [visible, setVisible] = useState(0);
  const [done, setDone] = useState(false);
  const timers = useRef<number[]>([]);
  const runId = useRef(0);

  const clear = () => {
    timers.current.forEach((t) => window.clearTimeout(t));
    timers.current = [];
  };

  const run = useCallback(() => {
    clear();
    const id = ++runId.current;
    setPhase(0);
    setVisible(0);
    setDone(false);
    if (reduce) {
      setVisible(FINDINGS.length);
      setPhase(PHASES.length - 1);
      setDone(true);
      return;
    }
    PHASES.forEach((_, i) => {
      timers.current.push(
        window.setTimeout(() => {
          if (runId.current !== id) return;
          setPhase(i);
        }, 500 + i * 750),
      );
    });
    FINDINGS.forEach((_, i) => {
      timers.current.push(
        window.setTimeout(() => {
          if (runId.current !== id) return;
          setVisible(i + 1);
          if (i === FINDINGS.length - 1) setDone(true);
        }, 900 + i * 800),
      );
    });
  }, [reduce]);

  useEffect(() => {
    run();
    return clear;
  }, [run]);

  return (
    <div className="glass overflow-hidden rounded-3xl" aria-label="Simulated BugSeek scan">
      {/* window chrome */}
      <div className="flex items-center gap-2 border-b border-white/10 px-5 py-3.5">
        <span className="h-3 w-3 rounded-full bg-crit/80" />
        <span className="h-3 w-3 rounded-full bg-amber2/80" />
        <span className="h-3 w-3 rounded-full bg-mint/80" />
        <span className="ml-3 font-mono text-xs text-slate2">bugseek — scan</span>
        <span className="ml-auto flex items-center gap-1.5 font-mono text-[11px] text-mint">
          <span className={`h-1.5 w-1.5 rounded-full bg-mint ${done ? '' : 'pulse-dot'}`} />
          {done ? 'DONE' : 'LIVE DEMO'}
        </span>
      </div>

      <div className="px-5 py-4 sm:px-6">
        {/* target bar */}
        <div className="flex items-center gap-3 rounded-xl bg-ink px-4 py-2.5 font-mono text-sm">
          <span className="text-slate2">target</span>
          <span className="truncate text-bone">https://juice-shop.local</span>
          <span className="ml-auto hidden shrink-0 rounded-md bg-mint/15 px-2 py-0.5 text-xs text-mint sm:inline">
            authorized ✓
          </span>
        </div>

        {/* progress */}
        <div className="mt-4">
          <div className="flex items-center justify-between font-mono text-xs">
            <span className="text-body/70">{done ? 'Scan complete' : PHASES[phase]}</span>
            <span className="text-slate2">
              {visible}/{FINDINGS.length} findings
            </span>
          </div>
          <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/10">
            <motion.div
              className="h-full rounded-full bg-mint"
              initial={false}
              animate={{ width: `${(visible / FINDINGS.length) * 100}%` }}
              transition={springQuiet}
            />
          </div>
        </div>

        {/* findings */}
        <div className="thin-scroll mt-4 max-h-72 space-y-2.5 overflow-y-auto pr-1">
          <AnimatePresence initial={false}>
            {FINDINGS.slice(0, visible).map((f) => {
              const s = SEV_STYLE[f.sev];
              return (
                <motion.div
                  key={f.title}
                  layout
                  initial={{ opacity: 0, scale: 0.92, y: 10 }}
                  animate={{ opacity: 1, scale: 1, y: 0 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  transition={springPop}
                  className="rounded-xl border border-white/10 bg-panel p-3.5"
                >
                  <div className="flex items-center gap-2">
                    <span className={`h-6 w-1 rounded-full ${s.bar}`} aria-hidden />
                    <span
                      className={`rounded-md border px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-wide ${s.chip}`}
                    >
                      {s.label}
                    </span>
                    {f.cvss && (
                      <span className="ml-auto font-mono text-xs text-slate2">
                        CVSS <span className="text-bone">{f.cvss}</span>
                      </span>
                    )}
                  </div>
                  <p className="mt-1.5 text-sm font-semibold text-bone">{f.title}</p>
                  <p className="mt-0.5 font-mono text-xs text-slate2">{f.detail}</p>
                </motion.div>
              );
            })}
          </AnimatePresence>
          {visible === 0 && (
            <p className="py-8 text-center font-mono text-xs text-slate2">
              warming up the scanner…
            </p>
          )}
        </div>

        {/* footer */}
        <div className="mt-4 flex items-center justify-between border-t border-white/10 pt-4">
          <p className="font-mono text-[11px] text-slate2">
            4 findings · 1 trap flagged, not reported
          </p>
          <motion.button
            onClick={run}
            whileTap={{ scale: 0.97, transition: { duration: 0.1 } }}
            whileHover={{ scale: 1.03 }}
            transition={springQuiet}
            className="rounded-lg border border-mint/30 bg-mint/10 px-3.5 py-1.5 text-sm font-semibold text-mint transition-colors hover:bg-mint/20"
          >
            ↻ Re-run scan
          </motion.button>
        </div>
      </div>
    </div>
  );
}
