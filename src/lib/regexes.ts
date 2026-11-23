/**
 * Secret-detection regex patterns for scanning JavaScript source.
 *
 * These only flag *well-known* credential formats. Generic high-entropy
 * string detection is intentionally left out of Phase 1 to keep false
 * positives low. All reported evidence is redacted by the caller.
 */
import type { Severity } from './types';

export interface SecretPattern {
  id: string;
  name: string;
  /** Must include the `g` flag handling; scanSecrets() re-instantiates it. */
  regex: RegExp;
  severity: Severity;
  description: string;
  remediation: string;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'aws-access-key',
    name: 'AWS access key ID',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: 'critical',
    description:
      'A hardcoded AWS access key ID was found in client-side JavaScript. ' +
      'If the matching secret key is also exposed (or the key has broad IAM permissions), ' +
      'attackers can operate your AWS resources directly.',
    remediation:
      'Rotate the key immediately in IAM. Remove it from client-side code and issue ' +
      'credentials from a secure backend or a secrets manager instead.',
  },
  {
    id: 'aws-session-token',
    name: 'AWS session token',
    regex: /\bFQoGZXIvYXdz[A-Za-z0-9+/=]{40,}\b/g,
    severity: 'critical',
    description:
      'An AWS temporary session token was found in client-side JavaScript. ' +
      'Session tokens grant the same access as the underlying temporary credentials until they expire.',
    remediation:
      'Revoke the session that issued the token and never ship temporary AWS credentials to the browser.',
  },
  {
    id: 'gcp-service-account',
    name: 'GCP service-account key file',
    regex: /"type"\s*:\s*"service_account"/g,
    severity: 'critical',
    description:
      'A Google Cloud service-account key file (or its marker) was found in client-side JavaScript. ' +
      'Service-account keys grant direct API access as the service account, often with broad permissions.',
    remediation:
      'Delete the key in Google Cloud Console, rotate anything it could reach, and never ship ' +
      'service-account JSON to the browser. Use Workload Identity or a backend proxy instead.',
  },
  {
    id: 'gcp-oauth-client-secret',
    name: 'GCP OAuth client secret',
    regex: /\bGOCSPX-[0-9A-Za-z_-]{28}\b/g,
    severity: 'high',
    description:
      'A Google Cloud OAuth client secret was found in client-side JavaScript. ' +
      'It can be used to complete OAuth flows as the registered client.',
    remediation:
      'Rotate the client secret in Google Cloud Console and keep OAuth secrets server-side.',
  },
  {
    id: 'azure-storage-connection',
    name: 'Azure Storage connection string',
    regex: /\bDefaultEndpointsProtocol=https?;AccountName=[^;\s"'`\\]+;AccountKey=[^;\s"'`\\]+/g,
    severity: 'critical',
    description:
      'An Azure Storage connection string was found in client-side JavaScript. ' +
      'It embeds the storage account key, which grants full read/write access to blobs, queues, and tables.',
    remediation:
      'Regenerate the storage account keys in the Azure portal immediately and never ship connection strings to the browser.',
  },
  {
    id: 'azure-servicebus-connection',
    name: 'Azure Service Bus connection string',
    regex: /\bEndpoint=sb:\/\/[^;\s"'`\\]+;SharedAccessKeyName=[^;\s"'`\\]+;SharedAccessKey=[^;\s"'`\\]+/g,
    severity: 'critical',
    description:
      'An Azure Service Bus connection string was found in client-side JavaScript. ' +
      'The shared access key grants send/listen/manage access to queues and topics.',
    remediation:
      'Regenerate the shared access keys in the Azure portal and keep connection strings server-side.',
  },
  {
    id: 'openai-api-key',
    name: 'OpenAI API key',
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
    severity: 'high',
    description:
      'An OpenAI API key was found in client-side JavaScript. Anyone who copies it can make billed API calls on the account.',
    remediation:
      'Revoke the key at platform.openai.com, restrict remaining keys, and proxy AI calls through your backend.',
  },
  {
    id: 'anthropic-api-key',
    name: 'Anthropic API key',
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    severity: 'high',
    description:
      'An Anthropic API key was found in client-side JavaScript. Anyone who copies it can make billed API calls on the account.',
    remediation:
      'Revoke the key in the Anthropic console and proxy AI calls through your backend.',
  },
  {
    id: 'stripe-live-key',
    name: 'Stripe live secret key',
    regex: /\b[rs]k_live_[0-9A-Za-z]{16,}\b/g,
    severity: 'critical',
    description:
      'A Stripe LIVE secret key was found in client-side JavaScript. Anyone who copies ' +
      'this key can create charges, refunds, and payouts against the account.',
    remediation:
      'Roll the key immediately in the Stripe dashboard. Secret keys must only ever live ' +
      'server-side; the browser should only ever see publishable (pk_*) keys.',
  },
  {
    id: 'square-access-token',
    name: 'Square access token',
    regex: /\bsq0(?:atp|csp)-[A-Za-z0-9_-]{22,}\b/g,
    severity: 'high',
    description:
      'A Square access token or application secret was found in client-side JavaScript. ' +
      'It can be used to call Square APIs as the merchant application.',
    remediation:
      'Rotate the token in the Square developer dashboard and keep it server-side.',
  },
  {
    id: 'sendgrid-api-key',
    name: 'SendGrid API key',
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    severity: 'high',
    description:
      'A SendGrid API key was found in client-side JavaScript. It can be used to send email as the account.',
    remediation:
      'Delete the key in the SendGrid dashboard and send mail from your backend only.',
  },
  {
    id: 'mailchimp-api-key',
    name: 'Mailchimp API key',
    regex: /\b[0-9a-f]{32}-us\d{1,2}\b/g,
    severity: 'high',
    description:
      'A Mailchimp API key was found in client-side JavaScript. It can be used to read and modify audiences and campaigns.',
    remediation:
      'Revoke the key in the Mailchimp account settings and keep it server-side.',
  },
  {
    id: 'twilio-api-key',
    name: 'Twilio API key',
    regex: /\bSK[0-9a-f]{32}\b/g,
    severity: 'high',
    description:
      'A Twilio API key SID was found in client-side JavaScript. Together with its secret it can send messages and calls on the account.',
    remediation:
      'Delete the API key in the Twilio console and keep Twilio credentials server-side.',
  },
  {
    id: 'twilio-account-sid',
    name: 'Twilio account SID',
    regex: /\bAC[0-9a-f]{32}\b/g,
    severity: 'low',
    description:
      'A Twilio account SID was found in client-side JavaScript. The SID alone is an identifier, not a secret, ' +
      'but it tells an attacker exactly which account to target and is worth correlating with other findings.',
    remediation:
      'No rotation is needed for the SID alone. Confirm no Twilio auth token or API key secret ships alongside it.',
  },
  {
    id: 'npm-token',
    name: 'npm access token',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    severity: 'high',
    description:
      'An npm access token was found in client-side JavaScript. Depending on its type it may publish packages or read private ones.',
    remediation:
      'Revoke the token at npmjs.com/settings/tokens and keep registry tokens out of shipped code.',
  },
  {
    id: 'google-api-key',
    name: 'Google API key',
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    severity: 'high',
    description:
      'A Google Cloud API key was found in client-side JavaScript. Depending on which APIs ' +
      'are enabled and whether HTTP-referrer restrictions are set, it may be abusable for ' +
      'quota theft or billed API calls.',
    remediation:
      'Restrict the key (HTTP referrers / API restrictions) in Google Cloud Console, ' +
      'rotate it, and proxy sensitive API calls through your backend.',
  },
  {
    id: 'slack-token',
    name: 'Slack token',
    regex: /\bx(?:ox[bpras]|app)-[0-9A-Za-z-]{10,}\b/g,
    severity: 'high',
    description:
      'A Slack token was found in client-side JavaScript. Tokens of this form can grant ' +
      'access to Slack workspaces, channels, and messages depending on scopes.',
    remediation:
      'Revoke the token in the Slack app admin panel immediately and rotate any ' +
      'credentials it may have had access to.',
  },
  {
    id: 'discord-bot-token',
    name: 'Discord bot token',
    regex: /\b[\w-]{24}\.[\w-]{6}\.[\w-]{27}\b/g,
    severity: 'high',
    description:
      'A Discord bot token was found in client-side JavaScript. It grants full control of the bot account, ' +
      'including reading messages and acting in every server the bot joined.',
    remediation:
      'Regenerate the token in the Discord developer portal immediately and keep bot tokens server-side.',
  },
  {
    id: 'discord-webhook',
    name: 'Discord webhook URL',
    regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{60,}/g,
    severity: 'high',
    description:
      'A Discord webhook URL was found in client-side JavaScript. Anyone with it can post messages to the channel it points at.',
    remediation:
      'Delete the webhook in the Discord channel settings and create a fresh one kept server-side.',
  },
  {
    id: 'telegram-bot-token',
    name: 'Telegram bot token',
    regex: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g,
    severity: 'high',
    description:
      'A Telegram bot token was found in client-side JavaScript. It grants full control of the bot via the Bot API.',
    remediation:
      'Revoke the token with @BotFather (/revoke) and keep bot tokens server-side.',
  },
  {
    id: 'github-token',
    name: 'GitHub token',
    regex: /\b(ghp_[0-9A-Za-z]{36}|gho_[0-9A-Za-z]{36}|ghu_[0-9A-Za-z]{36}|ghs_[0-9A-Za-z]{36}|ghr_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,})\b/g,
    severity: 'high',
    description:
      'A GitHub token was found in client-side JavaScript. Depending on scopes it may ' +
      'grant read/write access to private repositories and organisations.',
    remediation:
      'Revoke the token at github.com/settings/tokens immediately. Never ship tokens ' +
      'in frontend code; use a backend proxy for GitHub API calls.',
  },
  {
    id: 'private-key',
    name: 'Private key material',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
    severity: 'critical',
    description:
      'Private key material (PEM block header) was found in client-side JavaScript. ' +
      'This is almost certainly an accidental leak of server-side credentials.',
    remediation:
      'Treat the key as compromised: generate a new keypair, revoke/replace the old ' +
      'one everywhere it was trusted, and remove it from all client-facing code.',
  },
  {
    id: 'mongodb-uri',
    name: 'MongoDB connection string',
    regex: /\bmongodb(?:\+srv)?:\/\/[^\s"'`\\]+/g,
    severity: 'high',
    description:
      'A MongoDB connection string was found in client-side JavaScript. It typically ' +
      'embeds a username and password and the database host.',
    remediation:
      'Rotate the database credentials immediately, restrict network access to the ' +
      'database, and never expose connection strings to the browser.',
  },
  {
    id: 'postgres-uri',
    name: 'PostgreSQL connection string',
    regex: /\bpostgres(?:ql)?:\/\/[^\s"'`\\]+/g,
    severity: 'high',
    description:
      'A PostgreSQL connection string was found in client-side JavaScript. It typically ' +
      'embeds a username and password and the database host.',
    remediation:
      'Rotate the database credentials immediately, restrict network access to the ' +
      'database, and never expose connection strings to the browser.',
  },
  {
    id: 'mysql-uri',
    name: 'MySQL connection string',
    regex: /\bmysql:\/\/[^\s"'`\\]+/g,
    severity: 'high',
    description:
      'A MySQL connection string was found in client-side JavaScript. It typically ' +
      'embeds a username and password and the database host.',
    remediation:
      'Rotate the database credentials immediately, restrict network access to the ' +
      'database, and never expose connection strings to the browser.',
  },
  {
    id: 'redis-uri',
    name: 'Redis connection string',
    regex: /\brediss?:\/\/[^\s"'`\\]+/g,
    severity: 'high',
    description:
      'A Redis connection string was found in client-side JavaScript. It typically ' +
      'embeds a password and the cache host; Redis often has no further auth.',
    remediation:
      'Rotate the Redis password (AUTH) immediately, restrict network access to the ' +
      'instance, and never expose connection strings to the browser.',
  },
  {
    id: 'jwt',
    name: 'JSON Web Token',
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    severity: 'medium',
    description:
      'A JSON Web Token was found hardcoded in JavaScript. It may be a test/dummy ' +
      'token, but a live token could grant authenticated access as the embedded user.',
    remediation:
      'Verify whether the token is live (check expiry/claims). Never hardcode live ' +
      'tokens in frontend code; obtain them at runtime via an auth flow.',
  },
  {
    id: 'generic-secret-assignment',
    name: 'Hardcoded secret assignment',
    regex: /\b(api[_-]?key|api[_-]?secret|secret[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|private[_-]?key|db[_-]?password|db[_-]?pass)\s*[:=]\s*["'`]([^"'`\s]{8,})["'`]/gi,
    severity: 'medium',
    description:
      'A variable that looks like a secret or API credential is assigned a literal ' +
      'string value in client-side JavaScript. Pattern-matched generically, so manual ' +
      'review is advised.',
    remediation:
      'Confirm whether the value is a real credential. If so, rotate it and move it ' +
      'server-side; the frontend should only hold public identifiers.',
  },
  {
    id: 'password-assignment',
    name: 'Hardcoded password',
    regex: /\bpassword\s*[:=]\s*["'`][^"'`\s]{4,}["'`]/gi,
    severity: 'medium',
    description:
      'A literal password value was found in client-side JavaScript.',
    remediation:
      'Rotate the credential and remove it from client-side code. Use proper auth ' +
      'flows instead of embedding passwords.',
  },
  {
    id: 'debug-flag',
    name: 'Debug flag enabled',
    regex: /["']?(?:DEBUG|debug)["']?\s*[:=]\s*(?:true|1)\b/g,
    severity: 'low',
    description:
      'A debug flag appears to be enabled in client-side JavaScript. Debug modes can ' +
      'leak stack traces, verbose errors, or internal state.',
    remediation:
      'Ensure debug flags are disabled in production builds.',
  },
];

/** Heuristic filter to skip obvious placeholders and test values. */
const PLACEHOLDER_RE =
  /(your[_-]?key|example|test|dummy|placeholder|changeme|xxx+|1234|abcd|sample|demo|none|null|undefined)/i;

export function isPlaceholder(match: string): boolean {
  return PLACEHOLDER_RE.test(match);
}

/** Keep only a short prefix of a secret for display; never show the full value. */
export function redactSecret(match: string): string {
  // Short secrets keep almost nothing: showing 8 of a 10-char value
  // would be showing the secret. Reveal shrinks with length.
  const keep = match.length <= 4 ? 1 : match.length <= 10 ? 2 : 8;
  const prefix = match.slice(0, keep);
  return `${prefix}… (redacted)`;
}

/* ------------------------------------------------------------------ */
/* Entropy + fingerprint helpers (API-key bloodhound)                  */
/* ------------------------------------------------------------------ */

/** Generic high-entropy detection tuning: ~4.5 bits/char, min 20 chars. */
export const ENTROPY_THRESHOLD = 4.5;
export const ENTROPY_MIN_LENGTH = 20;
export const ENTROPY_MAX_FINDINGS_PER_SOURCE = 5;

/** Shannon entropy in bits per character. Random base64 sits near 5–6; English near 4. */
export function shannonEntropy(value: string): number {
  if (!value) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Redacted fingerprint: provider + first 4 + last 4 characters only.
 * The middle is never stored, logged, or rendered anywhere. Short values
 * reveal even less (first 2 + last 2). Use this, never the raw value,
 * when correlating a key across locations.
 */
export function fingerprintSecret(value: string, provider = 'unknown'): string {
  const clean = value.replace(/\s+/g, '');
  if (clean.length <= 8) {
    const keep = Math.max(1, Math.floor(clean.length / 4));
    return `${provider}:${clean.slice(0, keep)}…${clean.slice(-keep)}`;
  }
  return `${provider}:${clean.slice(0, 4)}…${clean.slice(-4)}`;
}

/**
 * Hashes of well-known public values. A high-entropy-looking string that is
 * just the hash of "" / "test" / "password" is not a secret. Only exact
 * matches are ignored, an unknown hash is still reported by the generic
 * assignment patterns, not silently dropped.
 */
const KNOWN_PUBLIC_HASHES = new Set([
  'd41d8cd98f00b204e9800998ecf8427e', // md5("")
  '098f6bcd4621d373cade4e832627b4f6', // md5("test")
  '5f4dcc3b5aa765d61d8327deb882cf99', // md5("password")
  'da39a3ee5e6b4b0d3255bfef95601890afd80709', // sha1("")
  'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3', // sha1("test")
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', // sha256("")
  '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', // sha256("test")
  '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', // sha256("password")
]);

export function isKnownPublicHash(value: string): boolean {
  return KNOWN_PUBLIC_HASHES.has(value.toLowerCase());
}

/** True when the string is one character repeated (padding, masks, filler). */
export function isRepeatedChar(value: string): boolean {
  return value.length > 0 && [...value].every((ch) => ch === value[0]);
}
