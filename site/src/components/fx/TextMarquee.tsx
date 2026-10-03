import { useReducedMotion } from 'framer-motion';
import { Children, type CSSProperties, type ReactNode } from 'react';

/**
 * Text marquee (the vertical word-cycler): a fixed prefix with a slot of
 * words rolling upward forever, edges faded by a mask. Integrated from
 * the component Peer supplied, adapted to this codebase — no "use
 * client", keyframes live in index.css (`tm-slide-vertical`), mask is an
 * inline style (Tailwind v3 has no mask-image utilities), heights are
 * font-relative so the slot sits inside a headline at any size, and
 * reduced motion gets the first word standing still.
 */
export function TextMarquee({
  children,
  speed = 1,
  className,
  prefix,
  windowHeight = '1.03em',
  itemHeight = '1.03em',
}: {
  children: ReactNode[];
  /** seconds each word dwells in the slot */
  speed?: number;
  className?: string;
  prefix?: ReactNode;
  windowHeight?: string;
  itemHeight?: string;
}) {
  const reduce = useReducedMotion();
  const items = Children.toArray(children);
  const count = items.length;

  if (reduce || count < 2) {
    return (
      <span className={className}>
        {prefix}
        {items[0]}
      </span>
    );
  }

  const fade =
    'linear-gradient(rgba(0,0,0,0) 0%, rgb(0,0,0) 30%, rgb(0,0,0) 70%, rgba(0,0,0,0) 100%)';

  return (
    <span className={`relative inline-flex items-baseline ${className ?? ''}`} aria-hidden="true">
      {prefix && <span className="relative whitespace-pre">{prefix}</span>}
      <span
        className="relative inline-block overflow-hidden align-[-0.16em]"
        style={{ height: windowHeight, WebkitMaskImage: fade, maskImage: fade }}
      >
        <span
          className="relative block h-full"
          style={{ '--count': count, '--speed': speed } as CSSProperties}
        >
          {items.map((child, index) => (
            <span
              key={index}
              className="flex items-center"
              style={
                {
                  height: itemHeight,
                  '--index': index,
                  '--origin': `calc((var(--count) - var(--index)) * 100%)`,
                  '--destination': `calc((var(--index) + 1) * -100%)`,
                  '--duration': `calc(var(--speed) * ${count}s)`,
                  '--delay': `calc((var(--duration) / var(--count)) * var(--index) - var(--duration))`,
                  translate: '0 var(--origin)',
                  animation: 'tm-slide-vertical var(--duration) var(--delay) infinite linear',
                } as CSSProperties
              }
            >
              {child}
            </span>
          ))}
        </span>
      </span>
    </span>
  );
}
