import { motion, useScroll, useSpring, useMotionValueEvent } from 'framer-motion';
import { useState } from 'react';
import { springQuiet } from '../lib/motion';

const LINKS = [
  { label: 'Toolkit', href: '#what' },
  { label: 'The swarm', href: '#swarm' },
  { label: 'How it works', href: '#how' },
  { label: 'Pricing', href: '#pricing' },
  { label: 'FAQ', href: '#faq' },
];

/**
 * Floating glass pill nav (Aceternity floating-navbar energy): it
 * materializes as a detached pill once you scroll, and a mint hairline
 * tracks reading progress across the very top of the viewport.
 */
export function Nav() {
  const [scrolled, setScrolled] = useState(false);
  const { scrollY, scrollYProgress } = useScroll();
  const progress = useSpring(scrollYProgress, { stiffness: 120, damping: 26, mass: 0.4 });
  useMotionValueEvent(scrollY, 'change', (v) => setScrolled(v > 24));

  return (
    <>
      <motion.div
        aria-hidden
        className="fixed inset-x-0 top-0 z-[60] h-[2px] origin-left bg-mint"
        style={{ scaleX: progress }}
      />
      <motion.header
        initial={{ y: -72, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={springQuiet}
        className="fixed inset-x-0 top-0 z-50 px-3 sm:px-6"
      >
        <div
          className={`glass mx-auto flex items-center justify-between gap-3 px-4 py-3 transition-all duration-300 sm:px-5 ${
            scrolled ? 'mt-3 max-w-3xl rounded-full' : 'mt-3 max-w-6xl rounded-3xl'
          }`}
        >
          <a href="#top" className="flex shrink-0 items-center gap-2.5" aria-label="BugSeek AI home">
            <img src="/bug.svg" alt="" className="h-8 w-8" />
            <span className="font-display text-lg font-semibold tracking-tight text-bone">
              BugSeek <span className="text-mint">AI</span>
            </span>
          </a>
          <nav className="hidden items-center gap-6 lg:flex" aria-label="Primary">
            {LINKS.map((l) => (
              <a
                key={l.href}
                href={l.href}
                className="text-sm font-medium text-body/80 transition-colors hover:text-bone"
              >
                {l.label}
              </a>
            ))}
          </nav>
          <motion.a
            href="#download"
            whileTap={{ scale: 0.97, transition: { duration: 0.1 } }}
            whileHover={{ scale: 1.03 }}
            transition={springQuiet}
            className="btn-shimmer shrink-0 rounded-full px-4 py-2 text-sm font-semibold text-ink shadow-[0_8px_24px_-8px_rgba(52,211,153,0.6)]"
          >
            Get the extension
          </motion.a>
        </div>
      </motion.header>
    </>
  );
}
