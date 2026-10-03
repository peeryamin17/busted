import { motion, useReducedMotion } from 'framer-motion';
import { useMemo } from 'react';

interface FlowPath {
  d: string;
  opacity: number;
  duration: number;
  delay: number;
}

/**
 * Flowing background paths (21st.dev @kokonutd background-paths,
 * rebuilt): two families of long bezier strokes drift diagonally
 * across the frame, each slowly drawing itself along with a travelling
 * offset and a breathing opacity. Pure white at a whisper of opacity —
 * paint-only animation, a modest path count, and completely static
 * under reduced motion.
 */
function buildPaths(): FlowPath[] {
  const families = [1, -1]; // sweep right, then mirror left
  return families.flatMap((dir, family) =>
    Array.from({ length: 8 }, (_, i) => {
      const startX = dir === 1 ? -360 + i * 92 : 1800 - i * 92;
      const sway = 240 + (i % 4) * 70;
      const d = [
        `M ${startX} -140`,
        `C ${startX + sway * dir} ${180 + i * 18}, ${startX - sway * 0.4 * dir} ${480 - i * 12}, ${startX + 460 * dir} 1020`,
      ].join(' ');
      return {
        d,
        opacity: 0.05 + (i % 4) * 0.018,
        duration: 12 + ((i * 3 + family * 5) % 6) * 2.5,
        delay: ((i + family * 3) % 5) * 0.8,
      };
    }),
  );
}

export function BackgroundPaths() {
  const reduce = useReducedMotion();
  const paths = useMemo(() => buildPaths(), []);

  return (
    <svg
      aria-hidden
      viewBox="0 0 1440 900"
      preserveAspectRatio="none"
      className="pointer-events-none absolute inset-0 h-full w-full"
    >
      {paths.map((p, i) =>
        reduce ? (
          <path
            key={i}
            d={p.d}
            fill="none"
            stroke="#ffffff"
            strokeOpacity={p.opacity}
            strokeWidth={1}
          />
        ) : (
          <motion.path
            key={i}
            d={p.d}
            fill="none"
            stroke="#ffffff"
            strokeWidth={1}
            initial={{ pathLength: 0.3, pathOffset: 0, opacity: 0 }}
            animate={{
              pathLength: [0.3, 0.85],
              pathOffset: [0, 0.5],
              opacity: [0, p.opacity, p.opacity, 0],
            }}
            transition={{
              duration: p.duration,
              delay: p.delay,
              repeat: Infinity,
              ease: 'linear',
            }}
          />
        ),
      )}
    </svg>
  );
}
