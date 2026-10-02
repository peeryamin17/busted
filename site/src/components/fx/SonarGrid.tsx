import { useEffect, useRef } from 'react';
import { useReducedMotion } from 'framer-motion';

interface Ring {
  x: number;
  y: number;
  r: number;
  born: number;
}

/**
 * Sonar Grid (after 21st.dev's @n1m4mz/sonar-grid): a canvas dot-grid
 * that behaves like a sonar scope — rings expand from ambient pings,
 * dots flare and swell as each wavefront passes, and tapping anywhere
 * fires your own ping. Monochrome white on black. Canvas, zero deps.
 * Rendered ONCE per page as a fixed full-viewport background layer, so
 * the dots run continuously through every section. Reduced motion:
 * one still frame, no loop, no pings.
 */
export function SonarGrid({ className = '' }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const reduce = useReducedMotion();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const SPACING = 26;
    const SPEED = 260; // px per second the wavefront travels
    const BAND = 46; // gaussian sigma of the wavefront band
    const PING_EVERY = 3200; // ms between ambient pings

    let w = 0;
    let h = 0;
    let raf = 0;
    let running = true;
    let visible = true;
    let last = performance.now();
    let lastPing = 0;
    const rings: Ring[] = [];

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      w = rect.width;
      h = rect.height;
      canvas.width = Math.max(1, Math.round(w * dpr));
      canvas.height = Math.max(1, Math.round(h * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      if (reduce) drawStill();
    };

    const spawnPing = (x: number, y: number, r = 2) => {
      rings.push({ x, y, r, born: performance.now() });
      if (rings.length > 5) rings.shift();
    };

    const drawDots = (now: number) => {
      ctx.clearRect(0, 0, w, h);
      const cols = Math.ceil(w / SPACING) + 1;
      const rows = Math.ceil(h / SPACING) + 1;
      const maxR = Math.hypot(w, h);
      for (let i = 0; i < cols; i++) {
        for (let j = 0; j < rows; j++) {
          const x = i * SPACING + SPACING / 2;
          const y = j * SPACING + SPACING / 2;
          let energy = 0;
          for (const ring of rings) {
            const d = Math.abs(Math.hypot(x - ring.x, y - ring.y) - ring.r);
            energy += Math.exp(-(d * d) / (2 * BAND * BAND));
          }
          energy = Math.min(1, energy);
          const alpha = 0.1 + energy * 0.75;
          const radius = 1 + energy * 1.7;
          ctx.beginPath();
          ctx.fillStyle = `rgba(255,255,255,${alpha.toFixed(3)})`;
          ctx.arc(x, y, radius, 0, Math.PI * 2);
          ctx.fill();
          void now;
        }
      }
      // prune dead rings
      for (let i = rings.length - 1; i >= 0; i--) {
        if (rings[i].r > maxR + BAND * 3) rings.splice(i, 1);
      }
    };

    const drawStill = () => {
      rings.length = 0;
      rings.push({ x: w * 0.62, y: h * 0.38, r: Math.min(w, h) * 0.3, born: 0 });
      drawDots(0);
    };

    const loop = (now: number) => {
      if (!running) return;
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      if (visible) {
        if (now - lastPing > PING_EVERY) {
          lastPing = now;
          spawnPing(w * (0.18 + Math.random() * 0.64), h * (0.15 + Math.random() * 0.7));
        }
        for (const ring of rings) ring.r += SPEED * dt;
        drawDots(now);
      }
      raf = requestAnimationFrame(loop);
    };

    const onPointerDown = (e: PointerEvent) => {
      if (reduce) return;
      // The canvas is fixed full-viewport, so viewport coords are canvas coords.
      spawnPing(e.clientX, e.clientY);
      lastPing = performance.now();
    };

    resize();
    window.addEventListener('resize', resize);
    window.addEventListener('pointerdown', onPointerDown);

    if (reduce) {
      drawStill();
    } else {
      // one ring already mid-flight at first paint
      spawnPing(w * 0.62, h * 0.36, Math.min(w, h) * 0.22);
      lastPing = performance.now();
      raf = requestAnimationFrame(loop);
      return () => {
        running = false;
        cancelAnimationFrame(raf);
        window.removeEventListener('resize', resize);
        window.removeEventListener('pointerdown', onPointerDown);
      };
    }

    return () => {
      window.removeEventListener('resize', resize);
      window.removeEventListener('pointerdown', onPointerDown);
    };
  }, [reduce]);

  return (
    <div aria-hidden className={`pointer-events-none fixed inset-0 overflow-hidden ${className}`}>
      <canvas ref={canvasRef} className="block h-full w-full" />
    </div>
  );
}
