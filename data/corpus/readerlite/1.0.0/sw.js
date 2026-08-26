// Reader Lite 1.0.0 - MV3 service worker.
//
// Fetches the reading configuration from the vendor's own API and caches it. This is
// the extension's only network activity, and it is the behaviour the weaponised 1.1.0
// hides behind.

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === "article-seen") {
    fetch("http://api.readermode.test/v2/config")
      .then((response) => response.json())
      .then((config) => chrome.storage.local.set({ config: config }))
      .catch(() => {});
  }
  sendResponse({ ok: true });
  return true;
});
