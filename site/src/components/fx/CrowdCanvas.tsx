import { useEffect, useRef } from 'react';
import { useReducedMotion } from 'framer-motion';

interface Figure {
  x: number;
  speed: number; // px/s, signed
  scale: number; // depth
  phase: number; // walk-cycle phase
  shade: number; // 0..1 whiteness
  baseY: number; // jitter within the band
}

/**
 * Canvas Crowd (after 21st.dev's @reuno-ui/skiper39 "Canvas Crowd"):
 * a strip of tiny monochrome hunters endlessly walking the beat in
 * both directions, drawn on canvas. Figures near the cursor light up
 * and hop. Pure decoration — reduced motion gets a single still frame.
 */
export function CrowdCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const reduce = useReducedMotion();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let w = 0;
    let h = 0;
    let raf = 0;
    let running = true;
    let last = performance.now();
    let mouseX = -9999;
    const figures: Figure[] = [];

    const seed = () => {
      figures.length = 0;
      const count = Math.max(18, Math.floor(w / 46));
      for (let i = 0; i < count; i++) {
        const depth = 0.8 + Math.random() * 0.8;
        figures.push({
          x: Math.random() * w,
          speed: (14 + Math.random() * 26) * (Math.random() < 0.5 ? -1 : 1),
          scale: depth,
          phase: Math.random() * Math.PI * 2,
          shade: 0.25 + depth * 0.55,
          baseY: (Math.random() - 0.5) * 26,
        });
      }
    };

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      w = rect.width;
      h = rect.height;
      canvas.width = Math.max(1, Math.round(w * dpr));
      canvas.height = Math.max(1, Math.round(h * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      if (figures.length === 0) seed();
      if (reduce) draw(0);
    };

    const drawFigure = (f: Figure, t: number) => {
      const s = f.scale;
      const groundY = h * 0.78 + f.baseY;
      const stride = Math.sin(f.phase) * 4.4 * s;
      const bob = Math.abs(Math.sin(f.phase)) * 1.8 * s;
      const nearMouse = Math.max(0, 1 - Math.abs(f.x - mouseX) / 90);
      const hop = nearMouse * Math.abs(Math.sin(t / 160)) * 5;
      const alpha = Math.min(1, f.shade + nearMouse * 0.6);
      const y = groundY - bob - hop;
      const hipY = y - 7 * s;
      const neckY = y - 15 * s;

      ctx.strokeStyle = `rgba(255,255,255,${alpha.toFixed(3)})`;
      ctx.fillStyle = `rgba(255,255,255,${alpha.toFixed(3)})`;
      ctx.lineWidth = 2 * s;
      ctx.lineCap = 'round';

      // legs
      ctx.beginPath();
      ctx.moveTo(f.x, hipY);
      ctx.lineTo(f.x + stride, groundY - hop);
      ctx.moveTo(f.x, hipY);
      ctx.lineTo(f.x - stride, groundY - hop);
      ctx.stroke();
      // torso
      ctx.beginPath();
      ctx.moveTo(f.x, hipY);
      ctx.lineTo(f.x, neckY);
      ctx.stroke();
      // arms (counter-swing)
      ctx.beginPath();
      ctx.moveTo(f.x, neckY + 2 * s);
      ctx.lineTo(f.x - stride * 0.8, neckY + 9 * s);
      ctx.moveTo(f.x, neckY + 2 * s);
      ctx.lineTo(f.x + stride * 0.8, neckY + 9 * s);
      ctx.stroke();
      // head
      ctx.beginPath();
      ctx.arc(f.x, neckY - 4.4 * s, 3.4 * s, 0, Math.PI * 2);
      ctx.fill();
    };

    const draw = (t: number) => {
      ctx.clearRect(0, 0, w, h);
      // ground line
      ctx.strokeStyle = 'rgba(255,255,255,0.08)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, h * 0.78 + 14);
      ctx.lineTo(w, h * 0.78 + 14);
      ctx.stroke();
      const sorted = [...figures].sort((a, b) => a.scale - b.scale);
      for (const f of sorted) drawFigure(f, t);
    };

    const loop = (now: number) => {
      if (!running) return;
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      for (const f of figures) {
        f.x += f.speed * dt;
        f.phase += dt * (Math.abs(f.speed) / 3.4);
        if (f.x < -32) f.x = w + 32;
        if (f.x > w + 32) f.x = -32;
      }
      draw(now);
      raf = requestAnimationFrame(loop);
    };

    const onMove = (e: PointerEvent) => {
      const rect = canvas.getBoundingClientRect();
      mouseX = e.clientX - rect.left;
    };
    const onLeave = () => {
      mouseX = -9999;
    };

    resize();
    window.addEventListener('resize', resize);
    canvas.addEventListener('pointermove', onMove);
    canvas.addEventListener('pointerleave', onLeave);

    if (!reduce) {
      raf = requestAnimationFrame(loop);
    }

    return () => {
      running = false;
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
      canvas.removeEventListener('pointermove', onMove);
      canvas.removeEventListener('pointerleave', onLeave);
    };
  }, [reduce]);

  return (
    <section aria-hidden className="relative overflow-hidden border-t border-white/10">
      <div className="relative h-44 sm:h-52">
        <canvas ref={canvasRef} className="absolute inset-0 block h-full w-full" />
        <div className="pointer-events-none absolute inset-x-0 top-0 h-16 bg-gradient-to-b from-ink to-transparent" />
        <p className="pointer-events-none absolute left-1/2 top-5 -translate-x-1/2 whitespace-nowrap font-mono text-[10px] tracking-[0.3em] text-white/30">
          THE CROWD IS ALREADY HUNTING
        </p>
      </div>
    </section>
  );
}
