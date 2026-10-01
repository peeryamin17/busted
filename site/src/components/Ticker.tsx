const ITEMS = [
  'exposed .map files',
  'missing CSP headers',
  'reflected XSS',
  'GraphQL introspection left on',
  'cookies without Secure',
  'CORS wildcard + credentials',
  'secrets in bundle.js',
  'admin:admin still a thing',
  'JWTs in localStorage',
  'verbose error pages',
];

/** Playful ticker of things BugSeek loves to find. Pauses on hover. */
export function Ticker() {
  const row = [...ITEMS, ...ITEMS];
  return (
    <div className="relative mt-20 overflow-hidden border-y border-white/10 bg-panel/40 py-4 sm:mt-24" aria-hidden>
      <div className="ticker-track flex w-max items-center gap-8 whitespace-nowrap pr-8">
        {row.map((item, i) => (
          <span key={i} className="flex items-center gap-8 font-mono text-sm text-slate2">
            {item}
            <img src="/bug.svg" alt="" className="h-4 w-4 opacity-60" />
          </span>
        ))}
      </div>
      {/* edge fades */}
      <div className="pointer-events-none absolute inset-y-0 left-0 w-24 bg-gradient-to-r from-ink to-transparent" />
      <div className="pointer-events-none absolute inset-y-0 right-0 w-24 bg-gradient-to-l from-ink to-transparent" />
    </div>
  );
}
