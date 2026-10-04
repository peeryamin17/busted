import { createHash, randomBytes } from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { config } from '../config.js';
import type { PlanTier } from '../types.js';

export interface SessionClaims {
  sub: string; // user id
  email: string;
  plan: PlanTier;
}

const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function signSession(user: { id: string; email: string; plan: PlanTier }): string {
  return jwt.sign(
    { email: user.email, plan: user.plan } as Omit<SessionClaims, 'sub'>,
    config.jwtSecret,
    { subject: user.id, expiresIn: TOKEN_TTL_SECONDS }
  );
}

export function verifySession(token: string): SessionClaims | null {
  try {
    const decoded = jwt.verify(token, config.jwtSecret) as jwt.JwtPayload & {
      email?: string;
      plan?: PlanTier;
    };
    if (!decoded.sub || !decoded.email || !decoded.plan) return null;
    return { sub: decoded.sub, email: decoded.email, plan: decoded.plan };
  } catch {
    return null;
  }
}

/**
 * API keys: the raw key is shown ONCE at creation. Only a SHA-256 hash is
 * stored server-side, so a database leak does not expose usable keys.
 */
export function generateApiKey(): { key: string; keyHash: string; keyPrefix: string } {
  const secret = randomBytes(32).toString('hex');
  const key = `bs_${secret}`;
  const keyHash = createHash('sha256').update(key).digest('hex');
  return { key, keyHash, keyPrefix: `bs_${secret.slice(0, 4)}` };
}

export function hashApiKey(key: string): string {
  return createHash('sha256').update(key).digest('hex');
}

/**
 * Extension link codes: a 32-character code the website shows once and
 * the user types into the extension, which exchanges it (exactly once)
 * for a real API key. Only a SHA-256 hash is stored server-side. The
 * alphabet skips look-alike characters (0/O, 1/I) because humans type it.
 */
export const PAIRING_CODE_TTL_MS = 10 * 60 * 1000;
const PAIRING_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export function generatePairingCode(): { code: string; codeHash: string } {
  const bytes = randomBytes(32);
  let code = '';
  for (let i = 0; i < 32; i++) {
    code += PAIRING_ALPHABET[bytes[i] % PAIRING_ALPHABET.length];
  }
  return { code, codeHash: createHash('sha256').update(code).digest('hex') };
}

/** Codes are typed by humans: dashes/spaces and case do not matter. */
export function normalizePairingCode(raw: string): string {
  return raw.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
}

export function hashPairingCode(normalizedCode: string): string {
  return createHash('sha256').update(normalizedCode).digest('hex');
}
