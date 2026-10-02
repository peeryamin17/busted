import { animate, motion, useInView, useMotionValue, useReducedMotion, useTransform } from 'framer-motion';
import { useEffect, useRef } from 'react';

/**
 * Security-score ring with a number-ticker count-up (Magic UI number-ticker
 * meets an SVG progress ring). One spring-driven motion value drives both
 * the digits and the ring so they land together. Reduced motion: instant.
 */
export function ScoreRing({
  value,
  grade,
  size = 190,
  caption,
}: {
  value: number;
  grade: string;
  size?: number;
  caption?: string;
}) {
  const reduce = useReducedMotion();
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: '-80px' });
  const mv = useMotionValue(0);
  const display = useTransform(mv, (v) => Math.round(v).toString());
  const stroke = useTransform(mv, (v) => {
    const c = 2 * Math.PI * 80;
    return c - (Math.min(100, Math.max(0, v)) / 100) * c;
  });

  useEffect(() => {
    if (!inView) return;
    if (reduce) {
      mv.set(value);
      return;
    }
    const controls = animate(mv, value, { type: 'spring', bounce: 0, duration: 1.4 });
    return controls.stop;
  }, [inView, value, reduce, mv]);

  const color = value >= 75 ? '#34D399' : value >= 55 ? '#FBBF24' : value >= 35 ? '#FB923C' : '#F87171';

  return (
    <div ref={ref} className="relative shrink-0" style={{ width: size, height: size }}>
      <svg viewBox="0 0 190 190" className="h-full w-full -rotate-90" aria-hidden>
        <circle cx="95" cy="95" r="80" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="11" />
        <motion.circle
          cx="95"
          cy="95"
          r="80"
          fill="none"
          stroke={color}
          strokeWidth="11"
          strokeLinecap="round"
          strokeDasharray={2 * Math.PI * 80}
          style={{ strokeDashoffset: stroke }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className="flex items-baseline font-display font-bold leading-none text-bone">
          <motion.span className="tabular-nums" style={{ fontSize: size * 0.3 }}>
            {display}
          </motion.span>
          <span className="ml-1 text-lg text-slate2">/100</span>
        </div>
        <span
          className="mt-1.5 rounded-md px-2 py-0.5 font-mono text-[11px] font-semibold tracking-widest"
          style={{ color, background: `${color}1f`, border: `1px solid ${color}55` }}
        >
          GRADE {grade}
        </span>
        {caption && <span className="mt-2 font-mono text-[10px] text-slate2">{caption}</span>}
      </div>
    </div>
  );
}
