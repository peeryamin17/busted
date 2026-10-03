import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Website session + OAuth-state cookie primitives.
 *
 * Sessions: the browser holds an opaque 32-byte random token in the
 * `bs_session` cookie; the database stores only its SHA-256 hash, so a
 * database leak does not expose usable session tokens.
 *
 * OAuth state: a random nonce kept in a short-lived signed cookie
 * (`nonce.hmac`), so the callback can prove the flow started here
 * (CSRF protection) without server-side state storage.
 */

export const SESSION_COOKIE = 'bs_session';
export const STATE_COOKIE = 'bs_oauth_state';

export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
export const STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes

export function generateSessionToken(): string {
  return randomBytes(32).toString('base64url');
}

export function hashSessionToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/** Create a state value + its signed cookie value (`nonce.sig`). */
export function createState(secret: string): { state: string; cookieValue: string } {
  const nonce = randomBytes(16).toString('base64url');
  const sig = createHmac('sha256', secret).update(nonce).digest('base64url');
  const value = `${nonce}.${sig}`;
  return { state: value, cookieValue: value };
}

/**
 * Verify the callback's `state` against the signed cookie: both must be
 * identical and carry a valid signature.
 */
export function verifyState(secret: string, stateParam: string, cookieValue: string): boolean {
  if (!stateParam || !cookieValue || stateParam !== cookieValue) return false;
  const dot = cookieValue.indexOf('.');
  if (dot <= 0) return false;
  const nonce = cookieValue.slice(0, dot);
  const sig = cookieValue.slice(dot + 1);
  const expected = createHmac('sha256', secret).update(nonce).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Minimal Cookie-header parser (name=value; …). */
export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name) {
      try {
        out[name] = decodeURIComponent(value);
      } catch {
        out[name] = value;
      }
    }
  }
  return out;
}

export function serializeCookie(
  name: string,
  value: string,
  opts: { maxAgeSeconds: number; secure: boolean },
): string {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${opts.maxAgeSeconds}`,
  ];
  if (opts.secure) parts.push('Secure');
  return parts.join('; ');
}

export function clearCookie(name: string, opts: { secure: boolean }): string {
  return serializeCookie(name, '', { maxAgeSeconds: 0, secure: opts.secure });
}
