// Types for the plain-JS DOM/fetch shim in aiKeysRemoveDom.mjs.
export declare const registry: Map<string, any>;
export declare const documentShim: any;
export declare function buildDomFromPopupHtml(htmlPath: string): string[];
export declare function makeChromeStorage(initial?: Record<string, unknown>): {
  store: Record<string, unknown>;
  chrome: any;
};
export declare function capsPayload(): any;
export declare function keyRow(providerId: string, hint: string): any;
export declare function makeFetch(scenario: any): {
  fetch: (input: unknown, init?: RequestInit) => Promise<Response>;
  log: Array<{ method: string; path: string; result: string }>;
  serverKeys: any[];
  readonly inflight: number;
};
export declare function settle(fake: any, timeoutMs?: number): Promise<void>;
export declare function observe(): {
  rowCount: number;
  rows: Array<{ name: string; removeButtonPresent: boolean; removeDisabled: boolean | null }>;
  emptyStateText: string[];
  errorHidden: boolean | null;
  errorText: string;
  statusText: string;
};
export declare function removeButtons(): any[];
