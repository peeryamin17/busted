import type { ReactNode } from 'react';

/**
 * A single beam of mint light endlessly circuits the border
 * (Magic UI border-beam). The beam layer sits in a 1.5px frame;
 * the child renders on solid panel so glass never stacks on glass.
 */
export function BorderBeam({
  children,
  className = '',
  radius = 'rounded-3xl',
}: {
  children: ReactNode;
  className?: string;
  radius?: string;
}) {
  return (
    <div className={`relative ${radius} p-[1.5px] ${className}`}>
      <div aria-hidden className={`border-beam-layer absolute inset-0 ${radius}`} />
      <div className={`relative ${radius} bg-panel`}>{children}</div>
    </div>
  );
}
