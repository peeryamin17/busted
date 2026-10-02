const FINDINGS_ROW = [
  'exposed .map files',
  'missing CSP headers',
  'reflected XSS',
  'GraphQL introspection left on',
  'cookies without Secure',
  'CORS wildcard + credentials',
  'secrets in bundle.js',
  'admin:admin still a thing',
  'JWTs in localStorage',
  '.git folders in production',
  'price fields the client controls',
  'verbose error pages',
];

const CREW_ROW = [
  'Recon maps it',
  'Secret Hunter sniffs it',
  'Headers & Cookies judges it',
  'CORS Analyst pokes it',
  'XSS Hunter reflects it',
  'IDOR Hunter swaps the ID',
  'Auth Analyst knocks twice',
  'GraphQL Prober introspects it',
  'Source-Map Miner rebuilds it',
  'the head agent writes it up',
];

function Row({ items, reverse = false }: { items: string[]; reverse?: boolean }) {
  const doubled = [...items, ...items];
  return (
    <div className="flex overflow-hidden">
      <div
        className={`${reverse ? 'ticker-track-rev' : 'ticker-track'} flex w-max items-center gap-8 whitespace-nowrap pr-8`}
      >
        {doubled.map((item, i) => (
          <span key={i} className="flex items-center gap-8 font-mono text-sm text-slate2">
            {item}
            <img src="/bug.svg" alt="" className="h-4 w-4 opacity-60" />
          </span>
        ))}
      </div>
    </div>
  );
}

/**
 * Twin marquees running in opposite directions (Magic UI marquee, doubled):
 * the top row is what BugSeek finds; the bottom row is who finds it.
 * Both pause on hover; both stop under reduced motion.
 */
export function Ticker() {
  return (
    <div className="relative overflow-hidden border-y border-white/10 bg-panel/40 py-4" aria-hidden>
      <div className="space-y-3.5">
        <Row items={FINDINGS_ROW} />
        <Row items={CREW_ROW} reverse />
      </div>
      <div className="pointer-events-none absolute inset-y-0 left-0 w-24 bg-gradient-to-r from-ink to-transparent" />
      <div className="pointer-events-none absolute inset-y-0 right-0 w-24 bg-gradient-to-l from-ink to-transparent" />
    </div>
  );
}
