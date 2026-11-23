/** localStorage that never throws: private mode or a blocked store just reads as empty. */
export function safeStorageGet(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function safeStorageSet(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* storage unavailable; the selection just does not persist */
  }
}

export function safeStorageRemove(key: string): void {
  try {
    localStorage.removeItem(key);
  } catch {
    /* storage unavailable; nothing to clear */
  }
}
