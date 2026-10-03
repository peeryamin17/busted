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
}: {
  children: ReactNode;
  className?: string;
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
  const rotateX = useTransform(scrollYProgress, [0, 1], [smallScreen ? 10 : 18, 0]);
  const scale = useTransform(scrollYProgress, [0, 1], [1.05, 1]);

  if (reduce) {
    return <div className={className}>{children}</div>;
  }

  return (
    <div ref={ref} className={className} style={{ perspective: 1100 }}>
      <motion.div
        style={{ rotateX, scale, transformOrigin: '50% 42%' }}
        className="shadow-[0_36px_70px_-28px_rgba(0,0,0,0.75)] will-change-transform"
      >
        {children}
      </motion.div>
    </div>
  );
}
