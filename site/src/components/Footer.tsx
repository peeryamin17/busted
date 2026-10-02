const COLUMNS: Array<{ title: string; links: Array<{ label: string; href: string }> }> = [
  {
    title: 'PRODUCT',
    links: [
      { label: 'The toolkit', href: '#what' },
      { label: 'The swarm', href: '#swarm' },
      { label: 'How it works', href: '#how' },
    ],
  },
  {
    title: 'DECIDE',
    links: [
      { label: 'Pricing', href: '#pricing' },
      { label: 'FAQ', href: '#faq' },
      { label: 'Get the extension', href: '#download' },
    ],
  },
];

/**
 * Footer with an oversized wordmark bleeding off the bottom edge —
 * the agency-poster treatment. Links and credits ride above it.
 */
export function Footer({ home = true, member = false }: { home?: boolean; member?: boolean }) {
  const prefix = member ? '/app' : home ? '' : '/';
  return (
    <footer className="relative overflow-hidden border-t border-white/10">
      <div className="mx-auto max-w-6xl px-4 pb-10 pt-14 sm:px-6">
        <div className="flex flex-col gap-10 md:flex-row md:justify-between">
          <div className="max-w-xs">
            <div className="flex items-center gap-2.5">
              <img src="/bug.svg" alt="" className="h-8 w-8" />
              <span className="font-display text-lg font-semibold text-bone">
                BugSeek <span className="text-mint">AI</span>
              </span>
            </div>
            <p className="mt-3 text-sm leading-relaxed text-slate2">
              The security researcher in your browser. Built by{' '}
              <span className="text-mint">Peer</span>, a student who reads other
              people's JavaScript so you don't have to.
            </p>
          </div>
          <nav className="flex gap-16 sm:gap-24" aria-label="Footer">
            {COLUMNS.map((col) => (
              <div key={col.title}>
                <p className="font-mono text-[11px] tracking-[0.2em] text-slate2">{col.title}</p>
                <ul className="mt-4 space-y-2.5">
                  {col.links.map((l) => (
                    <li key={l.label}>
                      <a href={`${prefix}${l.href}`} className="text-sm text-body/80 transition-colors hover:text-bone">
                        {l.label}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </nav>
        </div>
        <div className="mt-12 flex flex-col gap-2 border-t border-white/10 pt-6 font-mono text-xs text-slate2 sm:flex-row sm:items-center sm:justify-between">
          <p>© 2026 BugSeek AI — no bugs were harmed. Several were reported.</p>
          <p>test only what you're allowed to</p>
        </div>
      </div>

      {/* oversized wordmark, clipped by the footer edge */}
      <div aria-hidden className="pointer-events-none relative select-none overflow-hidden">
        <p className="-mb-[0.16em] text-center font-display text-[19.5vw] font-bold leading-[0.78] tracking-tight text-white/[0.045]">
          BUGSEEK
        </p>
        <div className="absolute inset-x-0 bottom-0 h-1/2 bg-gradient-to-t from-ink/60 to-transparent" />
      </div>
    </footer>
  );
}
