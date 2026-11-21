import crypto from 'node:crypto';

const ALGO = 'aes-256-gcm';

function getMasterKey(): Buffer {
  const secret =
    process.env.KEY_ENCRYPTION_SECRET ||
    (process.env.NODE_ENV !== 'production' ? 'dev-encryption-secret-min-16-chars' : undefined);
  if (!secret || secret.length < 16) {
    throw new Error(
      'KEY_ENCRYPTION_SECRET must be set (min 16 chars) to encrypt/decrypt user AI keys.'
    );
  }
  return crypto.createHash('sha256').update(secret).digest();
}

export function encryptSecret(plaintext: string): string {
  const key = getMasterKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, key, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return [
    iv.toString('base64'),
    tag.toString('base64'),
    encrypted.toString('base64'),
  ].join(':');
}

export function decryptSecret(payload: string): string {
  const parts = payload.split(':');
  if (parts.length !== 3) {
    throw new Error('Malformed encrypted secret payload.');
  }

  const [ivB64, tagB64, dataB64] = parts;
  const key = getMasterKey();
  const decipher = crypto.createDecipheriv(
    ALGO,
    key,
    Buffer.from(ivB64, 'base64')
  );
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(dataB64, 'base64')),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}

export function maskApiKey(rawKey: string): string {
  const trimmed = rawKey.trim();
  if (trimmed.length <= 8) return '••••••••';
  return `${trimmed.slice(0, 4)}••••${trimmed.slice(-4)}`;
}
