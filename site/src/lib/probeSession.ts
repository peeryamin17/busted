import type { SessionCredits, SessionUser } from './auth';

/**
 * Session probe, tri-state: a sleeping backend is not a signed-out
 * user. 401/403 mean signed out; any other non-ok status or a network
 * error means the backend may just be waking up.
 *
 * Probes /api/me, the site session endpoint: /api/v1/account only
 * returns email/plan/operator, it has no user record or credits.
 */
export type AuthProbeResult =
  | { status: 'authenticated'; user: SessionUser; credits: SessionCredits | null }
  | { status: 'unauthenticated' }
  | { status: 'backend_waking'; detail: string };

export async function probeSession(): Promise<AuthProbeResult> {
  try {
    const res = await fetch('/api/me', {
      credentials: 'include',
      signal: AbortSignal.timeout(15_000),
    });
    if (res.status === 401 || res.status === 403) {
      return { status: 'unauthenticated' };
    }
    if (!res.ok) {
      return { status: 'backend_waking', detail: `Backend returned HTTP ${res.status}` };
    }
    const data = (await res.json()) as { user: SessionUser; credits?: SessionCredits };
    return { status: 'authenticated', user: data.user, credits: data.credits ?? null };
  } catch (err) {
    return {
      status: 'backend_waking',
      detail: err instanceof Error ? err.message : 'Backend waking up',
    };
  }
}
