/**
 * One key per session, minted at most once: rapid clicks share the
 * in-flight mint, and later clicks reuse the key already minted
 * instead of minting a duplicate. A failed mint clears so the next
 * click can try again.
 */
export class ExtensionKeyMint {
  private inFlight: Promise<string> | null = null;
  private liveKey: string | null = null;

  async mint(mintFn: () => Promise<string>): Promise<string> {
    if (this.liveKey) return this.liveKey;
    if (this.inFlight) return this.inFlight;
    const p = mintFn();
    this.inFlight = p;
    try {
      const key = await p;
      this.liveKey = key;
      return key;
    } catch (err) {
      this.inFlight = null;
      throw err;
    }
  }
}
