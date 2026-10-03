import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import { useEffect, useRef } from 'react';
import { springQuiet } from '../../lib/motion';

interface Props {
  open: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

/**
 * The "are you sure" standing in front of sign-out. Purely a gate —
 * the logout flow in lib/auth runs untouched, exactly as before, once
 * Sign out is confirmed here.
 *
 * "Stay" is the safe default and takes initial focus; Escape and a
 * tap on the backdrop mean the same as Stay.
 */
export function ConfirmSignOut({ open, onCancel, onConfirm }: Props) {
  const reduce = useReducedMotion();
  const stayRef = useRef<HTMLButtonElement | null>(null);

  // Focus lands on Stay when the dialog opens; Escape is Stay.
  useEffect(() => {
    if (!open) return;
    stayRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCancel();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onCancel]);

  return (
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-[70] flex items-center justify-center px-4">
          <motion.div
            aria-hidden
            onClick={onCancel}
            initial={reduce ? false : { opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={springQuiet}
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
          />
          <motion.div
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="signout-title"
            aria-describedby="signout-body"
            initial={reduce ? false : { opacity: 0, y: 10, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={reduce ? { opacity: 0 } : { opacity: 0, y: 6, scale: 0.98 }}
            transition={springQuiet}
            className="glass relative w-full max-w-sm rounded-3xl p-6 text-center"
          >
            <h2 id="signout-title" className="font-display text-xl font-semibold text-bone">
              Heading out?
            </h2>
            <p id="signout-body" className="mt-2 text-sm leading-relaxed text-body/85">
              The swarm keeps hunting either way — you can wander back in any time.
            </p>
            <div className="mt-6 flex gap-2">
              <button
                ref={stayRef}
                type="button"
                onClick={onCancel}
                className="flex-1 rounded-full border border-white/15 bg-white/5 px-5 py-2.5 text-sm font-semibold text-bone transition-colors hover:bg-white/10 focus:outline-none focus-visible:ring-2 focus-visible:ring-white/60"
              >
                Stay
              </button>
              <button
                type="button"
                onClick={onConfirm}
                className="flex-1 rounded-full bg-white px-5 py-2.5 text-sm font-semibold text-ink transition-colors hover:bg-white/85 focus:outline-none focus-visible:ring-2 focus-visible:ring-white/60"
              >
                Sign out
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}
