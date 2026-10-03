import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import { RotateCcw } from 'lucide-react';
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
    chip: 'bg-sky2/15 text-sky2 border-sky2/35',
    bar: 'bg-sky2',
  },
  trap: {
    label: 'POSSIBLE TRAP',
    chip: 'border-dashed bg-violet2/10 text-violet2 border-violet2/40',
    bar: 'bg-violet2',
  },
};

/**
 * Interactive mock scan — a glass card styled like the extension popup.
 * Findings pop in on springs as the "scan" progresses. Re-runnable.
 * Fully static when the user prefers reduced motion.
 */
export function ScanDemo({ bare = false }: { bare?: boolean }) {
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
    <div
      className={bare ? 'overflow-hidden rounded-3xl' : 'glass overflow-hidden rounded-3xl'}
      aria-label="Simulated BugSeek scan"
    >
      {/* window chrome */}
      <div className="flex items-center gap-2 border-b border-white/10 px-5 py-3.5">
        <span className="h-3 w-3 rounded-full bg-crit" />
        <span className="h-3 w-3 rounded-full bg-amber2" />
        <span className="h-3 w-3 rounded-full bg-signal" />
        <span className="ml-3 font-mono text-xs text-body/75">bugseek — scan</span>
        <span className="ml-auto flex items-center gap-1.5 font-mono text-[11px] font-semibold text-signal">
          <span className={`h-1.5 w-1.5 rounded-full bg-signal ${done ? '' : 'pulse-dot'}`} />
          {done ? 'DONE' : 'LIVE DEMO'}
        </span>
      </div>

      <div className="px-5 py-4 sm:px-6">
        {/* target bar */}
        <div className="flex items-center gap-3 rounded-xl bg-ink px-4 py-2.5 font-mono text-sm">
          <span className="text-slate2">target</span>
          <span className="truncate text-bone">https://juice-shop.github.io</span>
          <span className="ml-auto hidden shrink-0 rounded-md bg-signal/15 px-2 py-0.5 text-xs font-semibold text-signal sm:inline">
            authorized ✓
          </span>
        </div>

        {/* progress */}
        <div className="mt-4">
          <div className="flex items-center justify-between font-mono text-xs">
            <span className="font-medium text-bone/90">{done ? 'Scan complete' : PHASES[phase]}</span>
            <span className="text-body/75">
              {visible}/{FINDINGS.length} findings
            </span>
          </div>
          <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/10">
            <motion.div
              className="h-full rounded-full bg-signal shadow-[0_0_18px_rgba(46,234,140,0.5)]"
              initial={false}
              animate={{ width: `${(visible / FINDINGS.length) * 100}%` }}
              transition={springQuiet}
            />
          </div>
        </div>

        {/* findings */}
        <div className="mt-4 space-y-2.5">
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
                      <span className="ml-auto font-mono text-xs text-body/75">
                        CVSS <span className="text-bone">{f.cvss}</span>
                      </span>
                    )}
                  </div>
                  <p className="mt-1.5 text-[15px] font-semibold leading-snug text-bone">{f.title}</p>
                  <p className="mt-1 font-mono text-[13px] leading-relaxed text-body/90">{f.detail}</p>
                </motion.div>
              );
            })}
          </AnimatePresence>
          {visible === 0 && (
            <p className="py-8 text-center font-mono text-xs text-body/75">
              warming up the scanner…
            </p>
          )}
        </div>

        {/* footer */}
        <div className="mt-4 flex items-center justify-between border-t border-white/10 pt-4">
          <p className="font-mono text-[11px] text-body/75">
            4 findings · 1 trap flagged, not reported
          </p>
          <motion.button
            onClick={run}
            whileTap={{ scale: 0.97, transition: { duration: 0.1 } }}
            whileHover={{ scale: 1.03 }}
            transition={springQuiet}
            className="flex items-center gap-1.5 rounded-lg border border-signal/35 bg-signal/10 px-3.5 py-1.5 text-sm font-semibold text-signal transition-colors hover:bg-signal/20"
          >
            <RotateCcw className="h-3.5 w-3.5" aria-hidden /> Re-run scan
          </motion.button>
        </div>
      </div>
    </div>
  );
}
