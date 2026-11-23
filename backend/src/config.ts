import 'dotenv/config';

function str(name: string, def: string): string {
  return process.env[name] ?? def;
}

function num(name: string, def: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) {
    throw new Error(`Invalid numeric env var ${name}=${raw}`);
  }
  return n;
}

function bool(name: string, def: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  return raw === '1' || raw.toLowerCase() === 'true';
}

function list(name: string): string[] | undefined {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return undefined;
  const items = raw.split(',').map((s) => s.trim()).filter(Boolean);
  return items.length > 0 ? items : undefined;
}

export interface AppConfig {
  port: number;
  nodeEnv: string;
  isProd: boolean;
  jwtSecret: string;
  sessionSecret: string;
  googleClientId?: string;
  googleClientSecret?: string;
  googleRedirectUri?: string;
  postLoginRedirect: string;
  databaseUrl?: string;
  redisUrl?: string;
  llmProvider: 'mock' | 'claude' | 'gemini' | 'qwen';
  anthropicApiKey?: string;
  anthropicModel: string;
  geminiApiKey?: string;
  geminiRoutineModel: string;
  geminiReasoningModel: string;
  qwenApiKey?: string;
  qwenBaseUrl: string;
  qwenRoutineModel: string;
  qwenReasoningModel: string;
  qwenCodeModel: string;
  agentMaxActions: number;
  agentMaxDurationMs: number;
  agentRequestsPerSecond: number;
  allowPrivateTargets: boolean;
  apiRateLimitPerMin: number;
  corsOrigins: string[];
  adminEmail?: string;
  keyEncryptionSecret?: string;
}

function loadConfig(): AppConfig {
  const nodeEnv = str('NODE_ENV', 'development');
  const isProd = nodeEnv === 'production';
  let jwtSecret = process.env['JWT_SECRET'];
  if (!jwtSecret) {
    if (isProd) {
      throw new Error('JWT_SECRET must be set in production');
    }
    jwtSecret = 'dev-only-secret-do-not-use-in-production';
    console.warn('[config] JWT_SECRET not set — using insecure dev default');
  }

  // Signs the OAuth `state` cookie (CSRF protection for the Google flow).
  // Falls back to JWT_SECRET so existing setups keep booting.
  const sessionSecret = process.env['SESSION_SECRET'] || jwtSecret;
  if (!process.env['SESSION_SECRET'] && isProd) {
    console.warn('[config] SESSION_SECRET not set — using JWT_SECRET for OAuth state signing');
  }

  // Google sign-in is OPTIONAL config: when any of these is unset the app
  // still boots and the /api/auth/google* routes answer 503 instead.
  const googleClientId = process.env['GOOGLE_CLIENT_ID'] || undefined;
  const googleClientSecret = process.env['GOOGLE_CLIENT_SECRET'] || undefined;
  const googleRedirectUri = process.env['GOOGLE_REDIRECT_URI'] || undefined;

  const llmProviderRaw = str('LLM_PROVIDER', 'gemini').toLowerCase();
  if (
    llmProviderRaw !== 'mock' &&
    llmProviderRaw !== 'claude' &&
    llmProviderRaw !== 'gemini' &&
    llmProviderRaw !== 'qwen'
  ) {
    throw new Error(
      `Unsupported LLM_PROVIDER=${llmProviderRaw} (expected "mock", "claude", "gemini", or "qwen")`
    );
  }
  const anthropicApiKey = process.env['ANTHROPIC_API_KEY'] || undefined;
  if (llmProviderRaw === 'claude' && !anthropicApiKey) {
    throw new Error(
      'LLM_PROVIDER=claude requires ANTHROPIC_API_KEY to be set (env var only, never hardcoded)'
    );
  }
  // LLM_PROVIDER=gemini without a key does not throw here. The provider
  // factory falls back to the mock provider with a warning, so
  // `npm run dev` keeps working with no keys or infrastructure.

  const allowPrivateTargets = bool('ALLOW_PRIVATE_TARGETS', false);
  if (allowPrivateTargets && isProd) {
    throw new Error('ALLOW_PRIVATE_TARGETS must be false in production (SSRF guardrail)');
  }

  // CORS: the website calls this API with cookies, so origins must be an
  // explicit allowlist (a wildcard is invalid with credentialed CORS).
  // ALLOWED_ORIGINS (comma-separated) wins; legacy single-origin CORS_ORIGIN
  // is honoured when ALLOWED_ORIGINS is unset; otherwise localhost dev.
  const corsOrigins =
    list('ALLOWED_ORIGINS') ??
    list('CORS_ORIGIN') ??
    ['http://localhost:5173', 'http://localhost:4173'];
  if (isProd && corsOrigins.includes('*')) {
    throw new Error(
      'CORS origins must be explicit in production (set ALLOWED_ORIGINS) — "*" is invalid with credentialed CORS'
    );
  }

  // Same reasoning as JWT_SECRET above: without DATABASE_URL the app
  // would silently boot on the in-memory store and lose everything on
  // the next restart, so refuse to start in production instead.
  if (isProd && !process.env['DATABASE_URL']) {
    throw new Error('DATABASE_URL must be set in production');
  }

  return {
    port: num('PORT', 3000),
    nodeEnv,
    isProd,
    jwtSecret,
    sessionSecret,
    googleClientId,
    googleClientSecret,
    googleRedirectUri,
    postLoginRedirect: str('POST_LOGIN_REDIRECT', '/app'),
    databaseUrl: process.env['DATABASE_URL'] || undefined,
    redisUrl: process.env['REDIS_URL'] || undefined,
    llmProvider: llmProviderRaw,
    anthropicApiKey,
    anthropicModel: str('ANTHROPIC_MODEL', 'claude-sonnet-4-5'),
    geminiApiKey: process.env['GEMINI_API_KEY'] || undefined,
    geminiRoutineModel: str('GEMINI_ROUTINE_MODEL', 'gemini-2.0-flash'),
    geminiReasoningModel: str('GEMINI_REASONING_MODEL', 'gemini-2.0-flash'),
    // Qwen (Alibaba DashScope, OpenAI-compatible). Base URL selects the
    // region, a key issued for one region returns 401 on another's URL.
    // Default is the international endpoint.
    qwenApiKey: process.env['QWEN_API_KEY'] || undefined,
    qwenBaseUrl: str('QWEN_BASE_URL', 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1'),
    qwenRoutineModel: str('QWEN_ROUTINE_MODEL', 'qwen3.8-flash'),
    qwenReasoningModel: str('QWEN_REASONING_MODEL', 'qwen3.7-plus'),
    qwenCodeModel: str('QWEN_CODE_MODEL', 'qwen3.7-plus'),
    agentMaxActions: num('AGENT_MAX_ACTIONS', 40),
    agentMaxDurationMs: num('AGENT_MAX_DURATION_MIN', 15) * 60 * 1000,
    agentRequestsPerSecond: num('AGENT_REQUESTS_PER_SECOND', 2),
    allowPrivateTargets,
    apiRateLimitPerMin: num('API_RATE_LIMIT_PER_MIN', 120),
    corsOrigins,
    adminEmail: str('ADMIN_EMAIL', '').trim().toLowerCase() || undefined,
    keyEncryptionSecret: process.env['KEY_ENCRYPTION_SECRET'] || undefined,
  };
}

export const config: AppConfig = loadConfig();
