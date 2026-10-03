import { animate, motion, useMotionValue, useReducedMotion } from 'framer-motion';
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type RefObject,
} from 'react';
import { usePathname } from '../../lib/router';

/**
 * The BugSeek cat: a little line-figure hunter drawn in the crowd's own
 * language (fx/CrowdCanvas) — filled round head, triangle ears, thin
 * white stroke body, legs and tail. Faceless, like the people.
 *
 * It lives in the header and stands ON the nav: on desktop it perches
 * on the active tab (scroll-spy over the MemberSite sections; the
 * Connect tab when the route is /app/check) and hops tab to tab with
 * a crouch–arc–squash as the active section changes. Where there are
 * no tabs (the landing teaser, or below lg) it perches on the brand
 * mark instead. Tapping it startles a hop in place.
 *
 * Positioning is measurement, never constants: Nav tags its tabs with
 * data-cat-tab, the brand with data-cat-brand and the pill with
 * data-cat-pill, and the cat re-reads those boxes on active change,
 * resize, route change and pill morphs. Reduced motion: no hops, no
 * idle sway — the cat just sits where it belongs.
 */

type TabKey = 'connect' | 'what' | 'swarm' | 'how' | 'pricing' | 'faq';

const SECTION_KEYS: TabKey[] = ['what', 'swarm', 'how', 'pricing', 'faq'];
const CAT = 38; // px — the tap target and the drawing share one box

interface Perch {
  /** centre x of the perch, relative to the header container */
  cx: number;
  /** y of the cat's feet, relative to the header container */
  feet: number;
}

export function TabCat({
  variant,
  containerRef,
}: {
  variant: 'site' | 'landing';
  containerRef: RefObject<HTMLElement | null>;
}) {
  const reduce = useReducedMotion();
  const pathname = usePathname();
  const [wide, setWide] = useState(
    () => typeof window !== 'undefined' && window.matchMedia('(min-width: 1024px)').matches,
  );
  const [spyKey, setSpyKey] = useState<TabKey>('what');
  const [ready, setReady] = useState(false);

  const xv = useMotionValue(0);
  const yv = useMotionValue(0);
  const syv = useMotionValue(1);
  const fxv = useMotionValue(1);

  const perchesRef = useRef<Partial<Record<TabKey | 'brand', Perch>>>({});
  const perchedKeyRef = useRef<string | null>(null);
  const restYRef = useRef(0);
  const hoppingRef = useRef(false);
  const hopTokenRef = useRef(0);

  const tabsMode = variant === 'site' && wide;
  // The Connect tab is a route, not a section: on /app/check it owns
  // the cat outright; everywhere else the scroll-spy decides.
  const activeKey: TabKey = pathname === '/app/check' ? 'connect' : spyKey;
  const perchKey = tabsMode ? activeKey : 'brand';

  /* ——— measurement ——— */

  const measure = useCallback(() => {
    const container = containerRef.current;
    if (!container) return;
    const cRect = container.getBoundingClientRect();
    const next: Partial<Record<TabKey | 'brand', Perch>> = {};

    const pointFor = (el: Element, centreOffset?: number): Perch => {
      const r = el.getBoundingClientRect();
      return {
        cx: r.left + (centreOffset ?? r.width / 2) - cRect.left,
        feet: r.top + r.height / 2 + 6 - cRect.top,
      };
    };

    container.querySelectorAll('[data-cat-tab]').forEach((el) => {
      if (el.getBoundingClientRect().width === 0) return;
      const key = el.getAttribute('data-cat-tab') as TabKey | null;
      if (key) next[key] = pointFor(el);
    });
    container.querySelectorAll('[data-cat-brand]').forEach((el) => {
      if (el.getBoundingClientRect().width === 0) return;
      if (!next.brand) next.brand = pointFor(el, 16); // stands on the bug mark
    });

    perchesRef.current = next;
  }, [containerRef]);

  /** Re-measure, then snap the cat to its current perch if it drifted. */
  const refresh = useCallback(() => {
    measure();
    const key = perchedKeyRef.current;
    if (!key || hoppingRef.current) return;
    const p = perchesRef.current[key as TabKey | 'brand'];
    if (!p) return;
    xv.set(p.cx - CAT / 2);
    restYRef.current = p.feet - CAT;
    yv.set(restYRef.current);
  }, [measure, xv, yv]);

  /* ——— movement ——— */

  const hopTo = useCallback(
    (p: Perch, key: string) => {
      const toX = p.cx - CAT / 2;
      const restY = p.feet - CAT;
      const first = perchedKeyRef.current === null;
      perchedKeyRef.current = key;

      if (!first && toX !== xv.get()) fxv.set(toX > xv.get() ? 1 : -1);

      if (reduce || first) {
        xv.set(toX);
        yv.set(restY);
        restYRef.current = restY;
        setReady(true);
        return;
      }

      setReady(true);
      hoppingRef.current = true;
      const token = ++hopTokenRef.current;
      const dist = Math.abs(toX - xv.get());
      const height = Math.min(34, Math.max(12, 10 + dist * 0.09));
      animate(xv, toX, { type: 'spring', bounce: 0.16, duration: 0.62 });
      animate(yv, [restYRef.current, restY - height, restY], {
        duration: 0.6,
        times: [0, 0.42, 1],
        ease: ['easeOut', 'easeIn'],
      }).then(() => {
        if (hopTokenRef.current === token) hoppingRef.current = false;
      });
      animate(syv, [1, 0.84, 1.09, 0.8, 1], {
        duration: 0.62,
        times: [0, 0.16, 0.45, 0.78, 1],
        ease: 'easeInOut',
      });
      restYRef.current = restY;
    },
    [reduce, xv, yv, syv, fxv],
  );

  const startle = useCallback(() => {
    if (reduce || hoppingRef.current) return;
    const restY = restYRef.current;
    animate(yv, [restY, restY - 16, restY], {
      duration: 0.48,
      times: [0, 0.4, 1],
      ease: ['easeOut', 'easeIn'],
    });
    animate(syv, [1, 0.9, 1.06, 0.82, 1], {
      duration: 0.5,
      times: [0, 0.2, 0.45, 0.75, 1],
      ease: 'easeInOut',
    });
  }, [reduce, yv, syv]);

  /* ——— which tab is active ——— */

  // Scroll-spy over the MemberSite sections. A thin band across the
  // middle of the viewport decides which section the reader is "in";
  // whichever section crosses it owns the cat. Last one wins on exit.
  useEffect(() => {
    if (variant !== 'site') return;
    const found: { key: TabKey; el: HTMLElement }[] = [];
    for (const key of SECTION_KEYS) {
      const el = document.getElementById(key);
      if (el) found.push({ key, el });
    }
    if (found.length === 0) return;

    const spy = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          const hit = found.find((f) => f.el === entry.target);
          if (hit) setSpyKey(hit.key);
        }
      },
      { rootMargin: '-38% 0px -55% 0px', threshold: 0 },
    );
    found.forEach((f) => spy.observe(f.el));
    return () => spy.disconnect();
  }, [variant, pathname]);

  /* ——— perch tracking ——— */

  useEffect(() => {
    const mq = window.matchMedia('(min-width: 1024px)');
    const onChange = (e: MediaQueryListEvent) => setWide(e.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  // Settle onto (or hop to) the current perch whenever the target changes.
  useEffect(() => {
    measure();
    const p =
      perchesRef.current[perchKey] ??
      perchesRef.current.what ??
      perchesRef.current.brand;
    if (!p) {
      setReady(false);
      return;
    }
    const key = perchesRef.current[perchKey]
      ? perchKey
      : perchesRef.current.what
        ? 'what'
        : 'brand';
    if (key === perchedKeyRef.current) {
      // same perch — just stay glued to it
      xv.set(p.cx - CAT / 2);
      restYRef.current = p.feet - CAT;
      if (!hoppingRef.current) yv.set(restYRef.current);
      setReady(true);
      return;
    }
    hopTo(p, key);
  }, [perchKey, pathname, wide, variant, measure, hopTo, xv, yv]);

  // Keep the perch honest as the world moves: window resizes, the nav
  // pill morphing between widths, late font/layout settling, scrolling.
  useEffect(() => {
    refresh();
    const raf = requestAnimationFrame(refresh);
    const settle = window.setTimeout(refresh, 550);
    const onLoad = () => refresh();
    window.addEventListener('load', onLoad);

    let scrollRaf = 0;
    const onScroll = () => {
      cancelAnimationFrame(scrollRaf);
      scrollRaf = requestAnimationFrame(refresh);
    };
    window.addEventListener('resize', refresh);
    window.addEventListener('scroll', onScroll, { passive: true });

    const pill = containerRef.current?.querySelector('[data-cat-pill]');
    const ro = pill ? new ResizeObserver(refresh) : null;
    if (pill && ro) ro.observe(pill);

    return () => {
      cancelAnimationFrame(raf);
      cancelAnimationFrame(scrollRaf);
      window.clearTimeout(settle);
      window.removeEventListener('load', onLoad);
      window.removeEventListener('resize', refresh);
      window.removeEventListener('scroll', onScroll);
      ro?.disconnect();
    };
  }, [refresh, containerRef]);

  /* ——— the cat itself ——— */

  return (
    <div aria-hidden={false} className="pointer-events-none absolute inset-0 z-30">
      <motion.div
        className="absolute left-0 top-0"
        style={{ x: xv, y: yv, opacity: ready ? 1 : 0, width: CAT, height: CAT }}
      >
        <motion.div
          className="h-full w-full"
          style={{ scaleY: syv, scaleX: fxv, transformOrigin: '50% 100%' }}
        >
          <button
            type="button"
            aria-label="Say hi to the BugSeek cat"
            onClick={startle}
            className="pointer-events-auto block h-full w-full cursor-pointer rounded-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/50"
          >
            <svg aria-hidden viewBox="0 0 40 40" className="block h-full w-full">
              <motion.g
                animate={reduce ? undefined : { y: [0, -1.1, 0] }}
                transition={{ duration: 3.4, repeat: Infinity, ease: 'easeInOut' }}
              >
                {/* tail — sways around its base at the body's rear */}
                <motion.g
                  style={{ transformBox: 'fill-box', transformOrigin: '92% 96%' }}
                  animate={reduce ? undefined : { rotate: [-7, 9, -7] }}
                  transition={{ duration: 2.6, repeat: Infinity, ease: 'easeInOut' }}
                >
                  <path
                    d="M9.5,26.5 C4.5,25 3,20.5 4.4,15"
                    fill="none"
                    stroke="rgba(255,255,255,0.9)"
                    strokeWidth="2.2"
                    strokeLinecap="round"
                  />
                </motion.g>
                {/* legs */}
                <g
                  stroke="rgba(255,255,255,0.9)"
                  strokeWidth="2.2"
                  strokeLinecap="round"
                >
                  <path d="M10.5,29 L9.5,36.5" fill="none" />
                  <path d="M14.5,29 L14.5,36.5" fill="none" />
                  <path d="M24.5,29 L24.5,36.5" fill="none" />
                  <path d="M28.5,29 L29.5,36.5" fill="none" />
                </g>
                {/* body + neck */}
                <path
                  d="M9.5,27 Q19,22.5 28,26"
                  fill="none"
                  stroke="rgba(255,255,255,0.9)"
                  strokeWidth="2.2"
                  strokeLinecap="round"
                />
                <path
                  d="M27.5,25.5 L30,21.5"
                  fill="none"
                  stroke="rgba(255,255,255,0.9)"
                  strokeWidth="2.2"
                  strokeLinecap="round"
                />
                {/* ears, then the filled round head over their bases */}
                <g fill="rgba(255,255,255,0.95)">
                  <polygon points="26.9,15.4 27.7,10.2 30.5,13.8" />
                  <polygon points="31.6,13.6 35,10.6 35.3,15.6" />
                  <circle cx="31" cy="19" r="5.6" />
                </g>
              </motion.g>
            </svg>
          </button>
        </motion.div>
      </motion.div>
    </div>
  );
}
