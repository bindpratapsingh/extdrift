chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ theme: "sepia" });
});
fetch("http://api.readermode.test/v2/config").catch(() => {});
fetch("http://fonts.readercdn.test/inter-var.woff2").catch(() => {});
chrome.storage.local.set({ fontLoaded: true });
