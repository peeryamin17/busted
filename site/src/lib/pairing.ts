/** Group a pairing code in fours for display, keeping every character. */
export function formatPairingCode(code: string): string {
  return code.match(/.{1,4}/g)?.join('-') ?? code;
}
