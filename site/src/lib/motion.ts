import type { Transition } from 'framer-motion';

/**
 * Shared spring presets, per the Apple fluid-interfaces guidance:
 * critically damped (bounce 0) by default; a whisper of bounce only for
 * small playful entrances. Interruptible springs everywhere — never lock
 * out input mid-flight.
 */
export const springQuiet: Transition = { type: 'spring', bounce: 0, duration: 0.45 };
export const springMove: Transition = { type: 'spring', bounce: 0, duration: 0.4 };
export const springPop: Transition = { type: 'spring', bounce: 0.28, duration: 0.55 };
export const springSheet: Transition = { type: 'spring', bounce: 0.12, duration: 0.35 };

/** Button press: instant feedback, scale 0.97. */
export const pressable = {
  whileTap: { scale: 0.97, transition: { duration: 0.1 } },
  whileHover: { scale: 1.02, transition: springQuiet },
};
