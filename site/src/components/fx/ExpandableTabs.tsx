import { AnimatePresence, motion } from 'framer-motion';
import { useEffect, useRef, useState, type ComponentType } from 'react';
import { springSheet } from '../../lib/motion';

export interface ExpandableTab {
  title: string;
  icon: ComponentType<{ className?: string; 'aria-hidden'?: boolean | 'true' | 'false' }>;
}

interface Props {
  tabs: ExpandableTab[];
  active: number;
  onChange: (index: number) => void;
  ariaLabel?: string;
}

/**
 * Expandable Tabs (after 21st.dev's @victorwelander/expandable-tabs):
 * an icon-only pill bar where the selected tab springs open to reveal
 * its label. Clicking anywhere outside collapses the bar back to icons
 * — the selection (and the content it drives) stays put.
 */
export function ExpandableTabs({ tabs, active, onChange, ariaLabel }: Props) {
  const [expanded, setExpanded] = useState(true);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onDown = (e: PointerEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setExpanded(false);
    };
    document.addEventListener('pointerdown', onDown);
    return () => document.removeEventListener('pointerdown', onDown);
  }, []);

  return (
    <div
      ref={ref}
      role="tablist"
      aria-label={ariaLabel}
      className="glass inline-flex items-center gap-1 rounded-full p-1.5"
    >
      {tabs.map((tab, i) => {
        const selected = active === i;
        const showLabel = selected && expanded;
        const Icon = tab.icon;
        return (
          <motion.button
            key={tab.title}
            role="tab"
            aria-selected={selected}
            type="button"
            layout
            transition={springSheet}
            onClick={() => {
              onChange(i);
              setExpanded(true);
            }}
            className={`flex items-center gap-2 whitespace-nowrap rounded-full px-3.5 py-2.5 text-sm font-semibold outline-none transition-colors duration-200 focus-visible:ring-2 focus-visible:ring-white/70 focus-visible:ring-offset-2 focus-visible:ring-offset-ink ${
              selected
                ? 'bg-white text-ink shadow-[0_8px_24px_-8px_rgba(255,255,255,0.4)]'
                : 'text-body/70 hover:bg-white/5 hover:text-bone'
            }`}
          >
            <Icon className="h-[18px] w-[18px] shrink-0" aria-hidden />
            <AnimatePresence initial={false}>
              {showLabel && (
                <motion.span
                  key="label"
                  initial={{ width: 0, opacity: 0 }}
                  animate={{ width: 'auto', opacity: 1 }}
                  exit={{ width: 0, opacity: 0 }}
                  transition={springSheet}
                  className="overflow-hidden"
                >
                  {tab.title}
                </motion.span>
              )}
            </AnimatePresence>
          </motion.button>
        );
      })}
    </div>
  );
}
