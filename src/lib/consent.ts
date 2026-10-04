/**
 * Consent records for the extension's data-practice disclosures.
 *
 * Two short, versioned agreements, both stored locally:
 *  - Disclosure consent: shown before the FIRST scan of any kind. The
 *    popup explains what BugSeek reads and where data lives, and waits
 *    for a deliberate yes. If the disclosure ever materially changes,
 *    bump DISCLOSURE_VERSION and the gate asks again.
 *  - Backend consent: just-in-time, before the first run that sends a
 *    target to the BugSeek backend (AI swarm, open-source engines). The
 *    target address and the server-side findings go to the backend and,
 *    for the swarm, to an AI model — the user agrees to that separately.
 *
 * Records hold only the agreed version + timestamp. Declining leaves
 * the features locked; there is no quiet default.
 */
import { STORAGE_KEYS } from './config';

/** Bump when the first-run disclosure text materially changes. */
export const DISCLOSURE_VERSION = 1;

/** Bump when the backend-runs disclosure text materially changes. */
export const BACKEND_VERSION = 1;

export interface ConsentRecord {
  version: number;
  agreedAt: string;
}

async function readRecord(key: string): Promise<ConsentRecord | null> {
  const stored = await chrome.storage.local.get(key);
  const rec = stored[key] as ConsentRecord | undefined;
  if (!rec || typeof rec.version !== 'number') return null;
  return rec;
}

async function writeRecord(key: string, version: number): Promise<void> {
  const rec: ConsentRecord = { version, agreedAt: new Date().toISOString() };
  await chrome.storage.local.set({ [key]: rec });
}

async function hasConsent(key: string, version: number): Promise<boolean> {
  const rec = await readRecord(key);
  return !!rec && rec.version >= version;
}

export function hasDisclosureConsent(): Promise<boolean> {
  return hasConsent(STORAGE_KEYS.disclosureConsent, DISCLOSURE_VERSION);
}

export function saveDisclosureConsent(): Promise<void> {
  return writeRecord(STORAGE_KEYS.disclosureConsent, DISCLOSURE_VERSION);
}

export function hasBackendConsent(): Promise<boolean> {
  return hasConsent(STORAGE_KEYS.backendConsent, BACKEND_VERSION);
}

export function saveBackendConsent(): Promise<void> {
  return writeRecord(STORAGE_KEYS.backendConsent, BACKEND_VERSION);
}
