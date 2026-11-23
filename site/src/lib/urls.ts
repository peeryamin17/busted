/**
 * Untrusted URLs (search results, user input) are only ever rendered
 * as links when they parse to http or https. Anything else renders
 * as plain text, never as a clickable href.
 */
export function safeExternalUrl(raw: string): string | null {
  try {
    const u = new URL(raw);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.toString() : null;
  } catch {
    return null;
  }
}
