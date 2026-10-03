import { config } from '../config.js';

/**
 * Google OAuth2 client for the website's "Sign in with Google" flow
 * (authorization-code flow, server-side exchange).
 *
 * The client secret is used ONLY here, server-side, when swapping the
 * authorization code for tokens — it never reaches frontend code. The
 * exchange happens once per sign-in; no Google tokens are stored (we
 * fetch the profile, then discard them) because our own session cookie
 * is the credential from that point on.
 *
 * The client is a factory with an injectable fetch so tests can drive
 * the real code paths (URL building, form encoding, parsing) with a
 * fake transport — tests never talk to Google.
 */

export interface GoogleProfile {
  /** Stable Google subject id — the identity key for our users. */
  sub: string;
  email: string;
  name?: string;
  picture?: string;
  emailVerified?: boolean;
}

export interface GoogleClient {
  /** Google consent-screen URL the browser is redirected to. */
  buildAuthUrl(state: string): string;
  /** Swap an authorization code for an access token. */
  exchangeCode(code: string): Promise<{ accessToken: string }>;
  /** Fetch the signed-in user's profile with the access token. */
  fetchProfile(accessToken: string): Promise<GoogleProfile>;
}

const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const USERINFO_URL = 'https://openidconnect.googleapis.com/v1/userinfo';

export function createGoogleClient(opts: {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  fetchImpl?: typeof fetch;
}): GoogleClient {
  const fetchImpl = opts.fetchImpl ?? fetch;

  return {
    buildAuthUrl(state: string): string {
      const params = new URLSearchParams({
        client_id: opts.clientId,
        redirect_uri: opts.redirectUri,
        response_type: 'code',
        scope: 'openid email profile',
        state,
      });
      return `${AUTH_URL}?${params.toString()}`;
    },

    async exchangeCode(code: string): Promise<{ accessToken: string }> {
      const res = await fetchImpl(TOKEN_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: opts.clientId,
          client_secret: opts.clientSecret,
          redirect_uri: opts.redirectUri,
          grant_type: 'authorization_code',
        }).toString(),
      });
      if (!res.ok) throw new Error(`Google token exchange failed (${res.status})`);
      const body = (await res.json()) as { access_token?: string };
      if (!body.access_token) throw new Error('Google token exchange returned no access token');
      return { accessToken: body.access_token };
    },

    async fetchProfile(accessToken: string): Promise<GoogleProfile> {
      const res = await fetchImpl(USERINFO_URL, {
        headers: { authorization: `Bearer ${accessToken}` },
      });
      if (!res.ok) throw new Error(`Google userinfo failed (${res.status})`);
      const body = (await res.json()) as {
        sub?: string;
        email?: string;
        name?: string;
        picture?: string;
        email_verified?: boolean;
      };
      if (!body.sub || !body.email) throw new Error('Google profile is missing sub/email');
      return {
        sub: body.sub,
        email: body.email,
        name: body.name,
        picture: body.picture,
        emailVerified: body.email_verified,
      };
    },
  };
}

let defaultClient: GoogleClient | null | undefined;

/**
 * Singleton client from config (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET /
 * GOOGLE_REDIRECT_URI). Null when Google sign-in is not configured — the
 * auth routes answer 503 in that case while the rest of the app runs.
 */
export function googleClientFromEnv(): GoogleClient | null {
  if (defaultClient !== undefined) return defaultClient;
  const { googleClientId, googleClientSecret, googleRedirectUri } = config;
  defaultClient =
    googleClientId && googleClientSecret && googleRedirectUri
      ? createGoogleClient({
          clientId: googleClientId,
          clientSecret: googleClientSecret,
          redirectUri: googleRedirectUri,
        })
      : null;
  return defaultClient;
}
