// Reader Lite 1.0.0 - content script.
//
// A small, genuinely benign extension written by us as the clean baseline for the
// corpus. It reads the article text on the page, adds a toolbar, and asks its service
// worker for the reading configuration. Nothing leaves the page except a message to its
// own background script.

(function () {
  "use strict";

  const article = document.querySelector("article");
  const text = article ? article.textContent : "";

  const toolbar = document.createElement("div");
  toolbar.className = "rl-toolbar";
  toolbar.textContent = "Reader Lite";
  document.body.appendChild(toolbar);

  chrome.runtime.sendMessage({ type: "article-seen", length: text.length });
})();
