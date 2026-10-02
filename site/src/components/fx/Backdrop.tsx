/**
 * Hero backdrop: blueprint grid with a radial mask, falling mint beams
 * (Aceternity background-beams energy) and one soft glow. Pure CSS —
 * beams are transform-only and vanish under prefers-reduced-motion.
 */
const BEAMS = [
  { left: '6%', height: 210, duration: 7.5, delay: 0.4 },
  { left: '17%', height: 150, duration: 9.5, delay: 2.6 },
  { left: '31%', height: 260, duration: 8.2, delay: 1.2 },
  { left: '47%', height: 170, duration: 10.5, delay: 4.1 },
  { left: '58%', height: 230, duration: 7.9, delay: 0.9 },
  { left: '72%', height: 160, duration: 9.1, delay: 3.3 },
  { left: '84%', height: 240, duration: 8.7, delay: 1.8 },
  { left: '94%', height: 180, duration: 10.2, delay: 5 },
];

export function Backdrop() {
  return (
    <div aria-hidden className="pointer-events-none absolute inset-0 overflow-hidden">
      <div className="grid-bg grid-mask absolute inset-0" />
      <div
        className="absolute -top-48 left-1/2 h-[520px] w-[900px] -translate-x-1/2 rounded-full opacity-[0.13] blur-[120px]"
        style={{ background: 'radial-gradient(closest-side, #34D399, transparent)' }}
      />
      {BEAMS.map((b, i) => (
        <span
          key={i}
          className="beam"
          style={{
            left: b.left,
            height: b.height,
            animationDuration: `${b.duration}s`,
            animationDelay: `${b.delay}s`,
          }}
        />
      ))}
      {/* fade into the page at the bottom */}
      <div className="absolute inset-x-0 bottom-0 h-40 bg-gradient-to-t from-ink to-transparent" />
    </div>
  );
}
