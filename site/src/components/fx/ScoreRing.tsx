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

  // Data is allowed to be loud: saturated score colours pop against the
  // black-and-white interface, with green at the top and red at the floor.
  const color =
    value >= 90 ? '#2EEA8C' : value >= 75 ? '#A3E635' : value >= 55 ? '#FFD60A' : value >= 35 ? '#FF9F0A' : '#FF453A';

  return (
    <div
      ref={ref}
      className="flex shrink-0 flex-col items-center"
      style={{ width: size }}
      role="img"
      aria-label={`Security score ${value} out of 100, grade ${grade}`}
    >
      <div className="relative shrink-0" style={{ width: size, height: size }}>
        <svg
          viewBox="0 0 190 190"
          className="h-full w-full -rotate-90"
          style={{ filter: `drop-shadow(0 0 14px ${color}40)` }}
          aria-hidden
        >
          <circle cx="95" cy="95" r="80" fill="none" stroke="rgba(255,255,255,0.13)" strokeWidth="11" />
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
        <div className="absolute inset-0 flex flex-col items-center justify-center px-5 text-center">
          <div className="flex items-baseline font-display font-bold leading-none tracking-[-0.03em] text-bone">
            <motion.span className="tabular-nums" style={{ fontSize: size * 0.31 }}>
              {display}
            </motion.span>
            <span className="ml-1 font-sans font-medium text-[#B9B9B1]" style={{ fontSize: size * 0.105 }}>
              /100
            </span>
          </div>
          <span
            className="mt-2 rounded-md px-2.5 py-1 font-sans text-xs font-bold tracking-[0.14em]"
            style={{ color, background: `${color}24`, border: `1px solid ${color}66` }}
          >
            GRADE {grade}
          </span>
        </div>
      </div>
      {caption && (
        <p className="mt-4 max-w-[27ch] text-center font-sans text-sm font-medium leading-snug text-bone">
          {caption}
        </p>
      )}
    </div>
  );
}
