import { animate, AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import { useEffect, useMemo, useRef, useState } from 'react';
import { springPop } from '../../lib/motion';
import { BackgroundPaths } from './BackgroundPaths';

/**
 * Glyph paths lifted from the onyx-glyph-preloader vocabulary (MIT) —
 * geometric marks drawn in a 100×100 box, plus two of our own:
 * a viewfinder (scanning) and a sonar wave.
 */
const GLYPHS: Array<{ d: string; stroke?: number }> = [
  { d: 'M50 18 L82 50 L50 82 L18 50 Z M50 36 L64 50 L50 64 L36 50 Z' },
  { d: 'M28 30 H72 M28 50 H72 M28 70 H56', stroke: 10 },
  { d: 'M50 16 A34 34 0 1 0 50.1 16 Z M50 34 A16 16 0 1 1 49.9 34 Z' },
  { d: 'M30 70 L50 30 L70 70', stroke: 11 },
  { d: 'M22 38 V22 H38 M62 22 H78 V38 M78 62 V78 H62 M38 78 H22 V62', stroke: 9 },
  { d: 'M14 50 Q32 24 50 50 T86 50', stroke: 9 },
];

interface Fleck {
  left: string;
  top: string;
  size: number;
  delay: string;
  duration: string;
}

function useFlecks(count: number, seed: number): Fleck[] {
  return useMemo(() => {
    // stateless hash-based pseudo-random — deterministic per (seed, index)
    const rand = (n: number) => {
      const x = Math.sin(n * 127.1 + 311.7) * 43758.5453;
      return x - Math.floor(x);
    };
    return Array.from({ length: count }, (_, i) => ({
      left: `${8 + rand(seed + i * 4) * 84}%`,
      top: `${8 + rand(seed + i * 4 + 1) * 84}%`,
      size: 1.5 + rand(seed + i * 4 + 2) * 1.8,
      delay: `${(rand(seed + i * 4 + 3) * 1.4).toFixed(2)}s`,
      duration: `${(1.2 + rand(seed + i * 4 + 1.5) * 1.2).toFixed(2)}s`,
    }));
  }, [count, seed]);
}

function GlyphTile({ index, lit }: { index: number; lit: boolean }) {
  const glyph = GLYPHS[index % GLYPHS.length];
  const flecks = useFlecks(4, 1234 + index * 777);
  // position on the orbit ring
  const angle = (index / GLYPHS.length) * Math.PI * 2 - Math.PI / 2;
  const RADIUS = 118; // px from centre (sm screens scale via container)
  const x = Math.cos(angle) * RADIUS;
  const y = Math.sin(angle) * RADIUS;

  return (
    <div
      className="absolute left-1/2 top-1/2"
      style={{ transform: `translate(calc(-50% + ${x}px), calc(-50% + ${y}px))` }}
    >
      <div
        className={`relative flex h-14 w-14 items-center justify-center rounded-2xl transition-all duration-500 sm:h-16 sm:w-16 ${
          lit
            ? 'border border-white/35 bg-gradient-to-br from-[#262626] to-[#0b0b0b] shadow-[inset_0_1px_0_rgba(255,255,255,0.35),0_0_24px_rgba(255,255,255,0.12)]'
            : 'border border-white/10 bg-gradient-to-br from-[#161616] to-[#080808] shadow-[inset_0_1px_0_rgba(255,255,255,0.08)]'
        }`}
      >
        <svg viewBox="0 0 100 100" className="h-8 w-8 sm:h-9 sm:w-9" aria-hidden>
          <path
            d={glyph.d}
            fill="none"
            stroke={lit ? '#FFFFFF' : '#4d4d4d'}
            strokeWidth={glyph.stroke ?? 6}
            strokeLinecap="round"
            strokeLinejoin="round"
            style={{
              transition: 'stroke 0.5s ease',
              filter: lit ? 'drop-shadow(0 0 5px rgba(255,255,255,0.65))' : 'none',
            }}
          />
        </svg>
        {lit &&
          flecks.map((f, i) => (
            <span
              key={i}
              aria-hidden
              className="glitter-fleck pointer-events-none absolute rounded-full bg-white"
              style={{
                left: f.left,
                top: f.top,
                width: f.size,
                height: f.size,
                animationDelay: f.delay,
                animationDuration: f.duration,
              }}
            />
          ))}
      </div>
    </div>
  );
}

/**
 * Onyx Glyph Preloader (after 21st.dev's @kedhareswer/onyx-glyph-preloader):
 * sandblasted black-metal glyph tiles orbit a climbing percentage,
 * lighting up one by one — then forge into the BugSeek mark above the
 * wordmark. ~2s, click to skip, once per session, instant (absent)
 * under reduced motion.
 */
export function Preloader({ onDone }: { onDone: () => void }) {
  const reduce = useReducedMotion();
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState<'load' | 'forge' | 'gone'>('load');
  const doneRef = useRef(false);

  const finish = () => {
    if (doneRef.current) return;
    doneRef.current = true;
    onDone();
  };

  const skipToForge = () => {
    if (phase === 'load') setPhase('forge');
    else if (phase === 'forge') setPhase('gone');
  };

  useEffect(() => {
    if (reduce) {
      finish();
      return;
    }
    document.documentElement.style.overflow = 'hidden';
    const controls = animate(0, 100, {
      duration: 1.75,
      ease: [0.65, 0, 0.35, 1],
      onUpdate: (v) => setProgress(v),
      onComplete: () => setPhase('forge'),
    });
    return () => {
      controls.stop();
      document.documentElement.style.overflow = '';
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reduce]);

  useEffect(() => {
    if (phase !== 'forge') return;
    const t = setTimeout(() => setPhase('gone'), 800);
    return () => clearTimeout(t);
  }, [phase]);

  useEffect(() => {
    if (phase !== 'gone') return;
    document.documentElement.style.overflow = '';
    const t = setTimeout(finish, 480);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase]);

  if (reduce) return null;

  const litCount = Math.min(GLYPHS.length, Math.floor((progress / 100) * GLYPHS.length) + (progress > 2 ? 1 : 0));
  const pct = Math.floor(progress);

  return (
    <motion.div
      role="status"
      aria-label="Loading BugSeek AI"
      onClick={skipToForge}
      initial={{ opacity: 1 }}
      animate={{ opacity: phase === 'gone' ? 0 : 1 }}
      transition={{ duration: 0.45, ease: 'easeOut' }}
      className="fixed inset-0 z-[100] flex cursor-pointer flex-col items-center justify-center bg-[#050505]"
      style={{ pointerEvents: phase === 'gone' ? 'none' : 'auto' }}
    >
      {/* flowing strokes behind everything */}
      <BackgroundPaths />

      {/* ambient glitter dust */}
      <AmbientDust />

      <div className="relative flex h-[320px] w-[320px] items-center justify-center sm:h-[360px] sm:w-[360px]">
        {/* orbiting tiles */}
        <motion.div
          className="orbit-spin absolute inset-0"
          animate={
            phase === 'load'
              ? { scale: 1, opacity: 1 }
              : { scale: 0.55, opacity: 0, rotate: 24 }
          }
          transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
        >
          {GLYPHS.map((_, i) => (
            <GlyphTile key={i} index={i} lit={phase !== 'load' || i < litCount} />
          ))}
        </motion.div>

        {/* centre: percentage, then the forged mark */}
        <AnimatePresence mode="wait" initial={false}>
          {phase === 'load' ? (
            <motion.div
              key="pct"
              exit={{ opacity: 0, scale: 0.85 }}
              transition={{ duration: 0.25 }}
              className="relative z-10 text-center"
            >
              <p className="font-display text-6xl font-bold tabular-nums tracking-tight text-white">
                {pct}
                <span className="text-2xl text-slate2">%</span>
              </p>
              <p className="mt-2 font-mono text-[10px] tracking-[0.3em] text-slate2">
                CASTING GLYPHS
              </p>
            </motion.div>
          ) : (
            <motion.div
              key="mark"
              initial={{ opacity: 0, scale: 0.7, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              transition={springPop}
              className="relative z-10 flex flex-col items-center text-center"
            >
              <img
                src="/bug.svg"
                alt=""
                className="h-20 w-20 drop-shadow-[0_0_28px_rgba(255,255,255,0.35)]"
              />
              <p className="mt-4 font-display text-3xl font-bold tracking-[0.28em] text-white">
                BUGSEEK
              </p>
              <p className="mt-1.5 font-mono text-[10px] tracking-[0.24em] text-slate2">
                THE SECURITY RESEARCHER IN YOUR BROWSER
              </p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* progress hairline */}
      <div className="mt-2 h-px w-52 overflow-hidden bg-white/10">
        <div
          className="h-full bg-white transition-[width] duration-100 ease-linear"
          style={{ width: `${phase === 'load' ? pct : 100}%` }}
        />
      </div>
      <p className="mt-4 font-mono text-[10px] text-slate2/70">tap anywhere to skip</p>
    </motion.div>
  );
}

function AmbientDust() {
  const flecks = useFlecks(26, 9871);
  return (
    <div aria-hidden className="pointer-events-none absolute inset-0 overflow-hidden">
      {flecks.map((f, i) => (
        <span
          key={i}
          className="glitter-fleck absolute rounded-full bg-white"
          style={{
            left: f.left,
            top: f.top,
            width: f.size,
            height: f.size,
            animationDelay: f.delay,
            animationDuration: f.duration,
            opacity: 0.25,
          }}
        />
      ))}
    </div>
  );
}
