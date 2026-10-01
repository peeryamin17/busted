import { motion, useScroll, useMotionValueEvent } from 'framer-motion';
import { useState } from 'react';
import { springQuiet } from '../lib/motion';

const LINKS = [
  { label: 'What it does', href: '#what' },
  { label: 'How it works', href: '#how' },
  { label: 'Pricing', href: '#pricing' },
];

export function Nav() {
  const [scrolled, setScrolled] = useState(false);
  const { scrollY } = useScroll();
  useMotionValueEvent(scrollY, 'change', (v) => setScrolled(v > 24));

  return (
    <motion.header
      initial={{ y: -72, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={springQuiet}
      className="fixed inset-x-0 top-0 z-50"
    >
      <div
        className={`glass mx-auto flex max-w-6xl items-center justify-between px-4 py-3 transition-all sm:px-6 ${
          scrolled ? 'mt-3 rounded-2xl' : 'mt-0 rounded-none border-x-0 border-t-0'
        }`}
      >
        <a href="#top" className="flex items-center gap-2.5" aria-label="BugSeek AI home">
          <img src="/bug.svg" alt="" className="h-8 w-8" />
          <span className="font-display text-lg font-semibold tracking-tight text-bone">
            BugSeek <span className="text-mint">AI</span>
          </span>
        </a>
        <nav className="hidden items-center gap-7 md:flex" aria-label="Primary">
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
          className="rounded-xl bg-mint px-4 py-2 text-sm font-semibold text-ink shadow-[0_8px_24px_-8px_rgba(52,211,153,0.6)]"
        >
          Get the extension
        </motion.a>
      </div>
    </motion.header>
  );
}
