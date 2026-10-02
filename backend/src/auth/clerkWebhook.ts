import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Clerk webhook signature verification (Svix).
 *
 * Clerk signs every webhook delivery: the signing secret (`whsec_...`)
 * from the dashboard webhook endpoint is base64 after the prefix, and the
 * signature is HMAC-SHA256 over `${svix-id}.${svix-timestamp}.${body}`,
 * delivered in the `svix-signature` header as space-separated
 * `v1,<base64>` entries (several during key rotation). Verified by hand —
 * same dependency-free approach as the Clerk JWT verifier.
 */

export interface SvixHeaders {
  id?: string;
  timestamp?: string;
  signature?: string;
}

const TOLERANCE_MS = 5 * 60_000;

export function verifySvixSignature(
  secret: string,
  headers: SvixHeaders,
  rawBody: string,
  nowMs: number = Date.now(),
): boolean {
  if (!secret.startsWith('whsec_') || !headers.id || !headers.timestamp || !headers.signature) {
    return false;
  }
  const ts = Number(headers.timestamp) * 1000;
  if (!Number.isFinite(ts) || Math.abs(nowMs - ts) > TOLERANCE_MS) return false;
  let key: Buffer;
  try {
    key = Buffer.from(secret.slice('whsec_'.length), 'base64');
  } catch {
    return false;
  }
  if (key.length === 0) return false;
  const expected = createHmac('sha256', key)
    .update(`${headers.id}.${headers.timestamp}.${rawBody}`)
    .digest();
  for (const entry of headers.signature.split(' ')) {
    const [version, sig] = entry.split(',');
    if (version !== 'v1' || !sig) continue;
    let candidate: Buffer;
    try {
      candidate = Buffer.from(sig, 'base64');
    } catch {
      continue;
    }
    if (candidate.length === expected.length && timingSafeEqual(candidate, expected)) return true;
  }
  return false;
}
