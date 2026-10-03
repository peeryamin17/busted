import { Component, type ReactNode } from 'react';

/**
 * Last-resort error boundary: if anything in the tree ever throws at
 * render time, the visitor gets a branded fallback with a reload —
 * never a blank black void. (Added after a missing env var on the
 * host took the whole page down via an unguarded auth component.)
 */
export class ErrorBoundary extends Component<
  { children: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch(err: unknown) {
    console.error('BugSeek UI error:', err);
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-[#050505] px-4 text-center">
        <img src="/bug.svg" alt="" className="h-12 w-12" />
        <p className="mt-6 font-display text-xl font-semibold tracking-tight text-[#F5F5F2]">
          Something tripped in the tall grass.
        </p>
        <p className="mt-2 max-w-sm text-sm leading-relaxed text-[#A8A8A3]">
          The page hit an unexpected error. A reload usually clears it.
        </p>
        <button
          type="button"
          onClick={() => window.location.reload()}
          className="mt-7 rounded-full border border-white/25 bg-white/5 px-6 py-2.5 text-sm font-medium text-[#F5F5F2] transition-colors hover:bg-white/10"
        >
          Reload the page
        </button>
      </div>
    );
  }
}
