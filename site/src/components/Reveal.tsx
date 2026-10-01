import { motion, useReducedMotion } from 'framer-motion';
import type { ReactNode } from 'react';
import { springQuiet } from '../lib/motion';

/** Scroll-triggered reveal: fade + rise on a quiet spring. Once, then stays. */
export function Reveal({
  children,
  delay = 0,
  className,
  y = 28,
}: {
  children: ReactNode;
  delay?: number;
  className?: string;
  y?: number;
}) {
  const reduce = useReducedMotion();
  if (reduce) {
    return <div className={className}>{children}</div>;
  }
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-64px' }}
      transition={{ ...springQuiet, delay }}
    >
      {children}
    </motion.div>
  );
}

/** Masked line reveal for display type — lines slide up from behind a mask. */
export function MaskedLine({ children, delay = 0 }: { children: ReactNode; delay?: number }) {
  const reduce = useReducedMotion();
  if (reduce) {
    return <span className="block">{children}</span>;
  }
  return (
    <span className="block overflow-hidden pb-1">
      <motion.span
        className="block"
        initial={{ y: '112%' }}
        animate={{ y: '0%' }}
        transition={{ ...springQuiet, delay }}
      >
        {children}
      </motion.span>
    </span>
  );
}
