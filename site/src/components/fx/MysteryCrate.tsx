import { motion, useAnimationControls, useInView, useReducedMotion } from 'framer-motion';
import { ArrowRight } from 'lucide-react';
import { useCallback, useEffect, useRef } from 'react';
import { springPop } from '../../lib/motion';
import { navigate } from '../../lib/router';
import { LiquidGlassButton } from './LiquidGlassButton';

/**
 * The end of the road: past the footer, where the site is supposed to
 * be over, a sealed crate sits in the dark. It rattles now and then —
 * something inside wants out. Only ever rendered for signed-out
 * visitors (Landing gates it on the auth probe); signing in is the
 * unwrap. Mystery, yes; fake promises, no — the copy says exactly
 * what's inside.
 *
 * Reduced motion gets the still life: no rattle, no wiggle, no pop.
 */
export function MysteryCrate() {
  const reduce = useReducedMotion();
  const wrapRef = useRef<HTMLDivElement>(null);
  const inView = useInView(wrapRef, { margin: '-12% 0px' });
  const rattleControls = useAnimationControls();

  const rattle = useCallback(() => {
    if (reduce) return;
    rattleControls.start({
      x: [0, -3, 3, -2, 1.2, 0],
      transition: { duration: 0.42, ease: 'easeInOut' },
    });
  }, [rattleControls, reduce]);

  // Every few seconds, something inside knocks. Only while it's on
  // screen — a crate rattling in an empty room is just wasteful.
  useEffect(() => {
    if (!inView || reduce) return;
    let alive = true;
    let t = 0;
    const loop = () => {
      t = window.setTimeout(
        () => {
          if (!alive) return;
          rattle();
          loop();
        },
        3800 + Math.random() * 2400,
      );
    };
    loop();
    return () => {
      alive = false;
      window.clearTimeout(t);
    };
  }, [inView, rattle, reduce]);

  return (
    <section
      aria-label="A surprise for making it this far"
      className="relative overflow-hidden border-t border-white/5 bg-black py-24 sm:py-32"
    >
      {/* a low white glow pooled behind the crate */}
      <div
        aria-hidden
        className="pointer-events-none absolute left-1/2 top-1/2 h-[340px] w-[640px] -translate-x-1/2 -translate-y-1/2 rounded-full opacity-[0.07] blur-[100px]"
        style={{ background: 'radial-gradient(closest-side, #FFFFFF, transparent)' }}
      />
      <div className="relative mx-auto max-w-2xl px-4 text-center sm:px-6">
        <div ref={wrapRef} className="flex justify-center">
          <motion.div
            initial={reduce ? false : { opacity: 0, scale: 0.8, y: 18 }}
            whileInView={{ opacity: 1, scale: 1, y: 0 }}
            viewport={{ once: true, margin: '-10% 0px' }}
            transition={springPop}
            onViewportEnter={rattle}
          >
            <motion.div
              whileHover={reduce ? undefined : { rotate: [0, -2.5, 2, -1, 0] }}
              transition={{ duration: 0.45, ease: 'easeInOut' }}
              style={{ transformOrigin: '50% 90%' }}
            >
              <motion.div animate={rattleControls}>
                <svg
                  aria-hidden
                  viewBox="0 0 120 120"
                  className="h-28 w-28 sm:h-32 sm:w-32"
                >
                  {/* lid */}
                  <rect
                    x="17"
                    y="30"
                    width="86"
                    height="13"
                    rx="6"
                    fill="rgba(255,255,255,0.05)"
                    stroke="rgba(255,255,255,0.45)"
                    strokeWidth="1.5"
                  />
                  {/* body */}
                  <rect
                    x="22"
                    y="43"
                    width="76"
                    height="58"
                    rx="8"
                    fill="rgba(255,255,255,0.04)"
                    stroke="rgba(255,255,255,0.35)"
                    strokeWidth="1.5"
                  />
                  {/* straps */}
                  <path
                    d="M42,43 L42,101 M78,43 L78,101"
                    stroke="rgba(255,255,255,0.14)"
                    strokeWidth="1.5"
                  />
                  {/* rivets */}
                  <g fill="rgba(255,255,255,0.4)">
                    <circle cx="29" cy="50" r="1.6" />
                    <circle cx="91" cy="50" r="1.6" />
                    <circle cx="29" cy="94" r="1.6" />
                    <circle cx="91" cy="94" r="1.6" />
                  </g>
                  {/* clasp */}
                  <rect
                    x="52"
                    y="47"
                    width="16"
                    height="13"
                    rx="3"
                    fill="rgba(0,0,0,0.65)"
                    stroke="rgba(255,255,255,0.5)"
                    strokeWidth="1.5"
                  />
                  <circle cx="60" cy="53.5" r="2" fill="rgba(255,255,255,0.6)" />
                  {/* the mystery */}
                  <text
                    x="60"
                    y="88"
                    textAnchor="middle"
                    fontSize="30"
                    fontWeight="600"
                    fill="rgba(255,255,255,0.85)"
                    fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                  >
                    ?
                  </text>
                </svg>
              </motion.div>
            </motion.div>
          </motion.div>
        </div>

        <p className="mt-8 font-mono text-[11px] tracking-[0.24em] text-slate2">
          YOU SCROLLED THE WHOLE WAY.
        </p>
        <h2 className="mt-3 font-display text-3xl font-bold tracking-tight text-bone sm:text-4xl">
          There's something in here with your name on it.
        </h2>
        <p className="mx-auto mt-3 max-w-xl leading-relaxed text-body/85">
          Sign in and it's yours — the full site, your first swarm run, and
          one thing we're keeping quiet about.
        </p>
        <div className="mt-7">
          <LiquidGlassButton
            href="/signin"
            size="lg"
            onClick={(e) => {
              e.preventDefault();
              navigate('/signin');
            }}
          >
            Sign in to unwrap <ArrowRight className="h-4 w-4" aria-hidden />
          </LiquidGlassButton>
        </div>
      </div>
    </section>
  );
}
