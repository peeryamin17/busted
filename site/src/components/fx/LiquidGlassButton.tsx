import { motion } from 'framer-motion';
import type { MouseEvent, ReactNode } from 'react';
import { springQuiet } from '../../lib/motion';

interface Props {
  children: ReactNode;
  href?: string;
  onClick?: (e: MouseEvent<HTMLElement>) => void;
  type?: 'button' | 'submit';
  /** solid = white glossy glass · glass = translucent dark glass */
  variant?: 'solid' | 'glass';
  size?: 'sm' | 'md' | 'lg';
  className?: string;
  ariaLabel?: string;
}

const SIZES = {
  sm: 'px-4 py-2 text-sm rounded-full',
  md: 'px-6 py-3 text-sm rounded-full',
  lg: 'px-7 py-3.5 text-base rounded-2xl',
} as const;

/**
 * Liquid Glass Button (after 21st.dev's @designali-in liquid-glass-button):
 * glossy monochrome glass — specular top edge, deep inner glow, and a
 * sheen that sweeps the surface on hover. Press feedback is instant
 * (scale 0.97 on pointer-down, Apple-style), springs everywhere.
 */
export function LiquidGlassButton({
  children,
  href,
  onClick,
  type = 'button',
  variant = 'solid',
  size = 'md',
  className = '',
  ariaLabel,
}: Props) {
  const cls = `liquid-glass liquid-glass-${variant} inline-flex shrink-0 cursor-pointer items-center justify-center gap-2 font-display font-semibold ${SIZES[size]} ${className}`;
  const motionProps = {
    whileTap: { scale: 0.97, transition: { duration: 0.1 } },
    whileHover: { scale: 1.02 },
    transition: springQuiet,
  };

  if (href) {
    return (
      <motion.a
        href={href}
        onClick={onClick}
        aria-label={ariaLabel}
        className={cls}
        {...motionProps}
      >
        <span className="inline-flex items-center gap-2">{children}</span>
      </motion.a>
    );
  }
  return (
    <motion.button
      type={type}
      onClick={onClick}
      aria-label={ariaLabel}
      className={cls}
      {...motionProps}
    >
      <span className="inline-flex items-center gap-2">{children}</span>
    </motion.button>
  );
}
