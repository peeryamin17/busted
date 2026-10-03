import { motion, useReducedMotion, useScroll, useTransform } from 'framer-motion';
import { useEffect, useRef, useState, type ReactNode } from 'react';

/**
 * Container scroll (21st.dev container-scroll-animation, rebuilt): the
 * wrapped visual starts tipped back in 3D and straightens as it scrolls
 * into place — rotateX eases to zero while a slight overscale settles.
 * Transform-only, so layout never moves; touch scroll drives it like
 * any other scroll. Small screens tilt less, and under reduced motion
 * the visual simply sits flat from the start.
 */
export function ContainerScroll({
  children,
  className = '',
  innerClassName = '',
  maxTilt = 18,
  tiltY = 0,
  perspective = 1100,
  startScale = 1.05,
}: {
  children: ReactNode;
  className?: string;
  innerClassName?: string;
  /** peak backward tip (deg) before it flattens; small screens use ~55% */
  maxTilt?: number;
  /** sideways tip (deg) that settles to 0 — negative leans left */
  tiltY?: number;
  /** camera distance (px); lower reads more dramatically 3D */
  perspective?: number;
  startScale?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const reduce = useReducedMotion();
  const [smallScreen, setSmallScreen] = useState(
    () =>
      typeof window !== 'undefined' &&
      window.matchMedia('(max-width: 640px)').matches,
  );

  useEffect(() => {
    const mq = window.matchMedia('(max-width: 640px)');
    const onChange = () => setSmallScreen(mq.matches);
    onChange();
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ['start end', 'end end'],
  });
  const tilt = smallScreen ? Math.round(maxTilt * 0.55) : maxTilt;
  const rotateX = useTransform(scrollYProgress, [0, 1], [tilt, 0]);
  const rotateY = useTransform(scrollYProgress, [0, 1], [tiltY, 0]);
  const scale = useTransform(scrollYProgress, [0, 1], [startScale, 1]);

  if (reduce) {
    return <div className={className}>{children}</div>;
  }

  return (
    <div ref={ref} className={className} style={{ perspective }}>
      <motion.div
        style={{ rotateX, rotateY, scale, transformOrigin: '50% 42%' }}
        className={`shadow-[0_36px_70px_-28px_rgba(0,0,0,0.75)] will-change-transform ${innerClassName}`}
      >
        {children}
      </motion.div>
    </div>
  );
}
