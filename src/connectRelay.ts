/**
 * BugSeek connect relay — runs ONLY on the BugSeek website.
 *
 * The website cannot talk to the extension directly (it does not know
 * the extension's ID), so this content script is the bridge:
 *  - it announces the extension's presence to the page, and
 *  - when the signed-in user clicks "Connect the extension", the page
 *    hands over a freshly minted API key and the relay passes it to the
 *    background worker, which stores it as the backend key.
 *
 * The relay moves exactly one thing (an API key, from our own page, at
 * the user's click) and ignores everything else. It reads no page
 * content and sends nothing anywhere.
 */

const SITE_SOURCE = 'bugseek-site';
const EXT_SOURCE = 'bugseek-extension';

function announce(): void {
  window.postMessage(
    { source: EXT_SOURCE, type: 'BUGSEEK_EXTENSION_PRESENT' },
    window.location.origin,
  );
}

window.addEventListener('message', (event) => {
  if (event.origin !== window.location.origin) return;
  const data = event.data as {
    source?: string;
    type?: string;
    apiKey?: string;
  } | null;
  if (!data || data.source !== SITE_SOURCE) return;

  if (data.type === 'BUGSEEK_PING') {
    announce();
    return;
  }

  if (data.type === 'BUGSEEK_CONNECT') {
    const apiKey = typeof data.apiKey === 'string' ? data.apiKey.trim() : '';
    if (!apiKey.startsWith('bs_')) {
      window.postMessage(
        { source: EXT_SOURCE, type: 'BUGSEEK_CONNECTED', ok: false },
        window.location.origin,
      );
      return;
    }
    chrome.runtime
      .sendMessage({ type: 'BUGSEEK_SET_API_KEY', apiKey })
      .then(() => {
        window.postMessage(
          { source: EXT_SOURCE, type: 'BUGSEEK_CONNECTED', ok: true },
          window.location.origin,
        );
      })
      .catch(() => {
        window.postMessage(
          { source: EXT_SOURCE, type: 'BUGSEEK_CONNECTED', ok: false },
          window.location.origin,
        );
      });
  }
});

announce();
