export const HASH_SCROLL_INTERVAL_MS = 100;
export const HASH_SCROLL_TIMEOUT_MS = 2000;

export interface HashScrollTarget {
  scrollIntoView: () => void;
}

export type HashScrollFinder = (hash: string) => HashScrollTarget | null;

function defaultFinder(hash: string): HashScrollTarget | null {
  return document.querySelector(hash);
}

// Scroll to a hash target, retrying while the target is not mounted
// yet. Returns a cancel function; polling stops on its own once the
// target is found or the timeout runs out.
export function scrollToHashWhenReady(
  hash: string,
  find: HashScrollFinder = defaultFinder,
  options: { intervalMs?: number; timeoutMs?: number } = {},
): () => void {
  const intervalMs = options.intervalMs ?? HASH_SCROLL_INTERVAL_MS;
  const timeoutMs = options.timeoutMs ?? HASH_SCROLL_TIMEOUT_MS;
  const started = Date.now();
  let timer: ReturnType<typeof setInterval> | null = null;

  const stop = () => {
    if (timer !== null) {
      clearInterval(timer);
      timer = null;
    }
  };

  const attempt = (): boolean => {
    let target: HashScrollTarget | null = null;
    try {
      target = find(hash);
    } catch {
      return true;
    }
    if (target) {
      target.scrollIntoView();
      return true;
    }
    return Date.now() - started >= timeoutMs;
  };

  if (!hash || attempt()) return stop;
  timer = setInterval(() => {
    if (attempt()) stop();
  }, intervalMs);
  return stop;
}
