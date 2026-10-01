export function Footer() {
  return (
    <footer className="border-t border-white/10 py-10">
      <div className="mx-auto flex max-w-6xl flex-col items-center gap-6 px-4 sm:flex-row sm:justify-between sm:px-6">
        <div className="flex items-center gap-2.5">
          <img src="/bug.svg" alt="" className="h-7 w-7" />
          <span className="font-display text-base font-semibold text-bone">
            BugSeek <span className="text-mint">AI</span>
          </span>
        </div>
        <nav className="flex items-center gap-6 text-sm text-slate2" aria-label="Footer">
          <a href="#what" className="transition-colors hover:text-bone">
            What it does
          </a>
          <a href="#how" className="transition-colors hover:text-bone">
            How it works
          </a>
          <a href="#pricing" className="transition-colors hover:text-bone">
            Pricing
          </a>
        </nav>
        <p className="font-mono text-xs text-slate2">
          Built by <span className="text-mint">Peer</span> · test only what you're allowed to
        </p>
      </div>
    </footer>
  );
}
