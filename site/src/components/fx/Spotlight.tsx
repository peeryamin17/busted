import { useRef, type ReactNode, type MouseEvent } from 'react';

/**
 * Spotlight card (Magic UI magic-card): a soft mint light follows the
 * cursor across the surface. Pointer-only paint effect — the card itself
 * stays a solid panel, so no translucent-on-translucent stacking.
 */
export function Spotlight({
  children,
  className = '',
}: {
  children: ReactNode;
  className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);

  const onMove = (e: MouseEvent<HTMLDivElement>) => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    el.style.setProperty('--mx', `${e.clientX - r.left}px`);
    el.style.setProperty('--my', `${e.clientY - r.top}px`);
  };

  return (
    <div ref={ref} onMouseMove={onMove} className={`group relative ${className}`}>
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 z-10 opacity-0 transition-opacity duration-300 group-hover:opacity-100"
        style={{
          background:
            'radial-gradient(420px circle at var(--mx, 50%) var(--my, 50%), rgba(52,211,153,0.10), transparent 65%)',
        }}
      />
      {children}
    </div>
  );
}
