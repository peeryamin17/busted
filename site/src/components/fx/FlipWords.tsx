import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import { useEffect, useState } from 'react';
import { springPop } from '../../lib/motion';

/**
 * Rotating word (Magic UI word-rotate / Aceternity flip-words energy).
 * Words spring up through a mask; static first word under reduced motion.
 */
export function FlipWords({
  words,
  interval = 2300,
  className,
}: {
  words: string[];
  interval?: number;
  className?: string;
}) {
  const reduce = useReducedMotion();
  const [i, setI] = useState(0);

  useEffect(() => {
    if (reduce || words.length < 2) return;
    const t = setInterval(() => setI((v) => (v + 1) % words.length), interval);
    return () => clearInterval(t);
  }, [reduce, words.length, interval]);

  if (reduce) {
    return <span className={className}>{words[0]}</span>;
  }

  return (
    <span className={`relative inline-block overflow-hidden align-bottom ${className ?? ''}`}>
      <AnimatePresence mode="wait" initial={false}>
        <motion.span
          key={words[i]}
          className="inline-block will-change-transform"
          initial={{ y: '85%', opacity: 0 }}
          animate={{ y: '0%', opacity: 1 }}
          exit={{ y: '-85%', opacity: 0 }}
          transition={springPop}
        >
          {words[i]}
        </motion.span>
      </AnimatePresence>
    </span>
  );
}
