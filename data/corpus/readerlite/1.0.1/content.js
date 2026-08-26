// Reader Lite 1.0.1 - content script.
//
// A genuinely benign feature update over 1.0.0: it adds an estimated reading-time badge
// to the toolbar. New behaviour (a second injected node, a little more DOM reading) but
// nothing leaves the page and no new capability is requested. This is the true-negative
// case for live capture - the tool must notice the change and still return BENIGN.

(function () {
  "use strict";

  const article = document.querySelector("article");
  const text = article ? article.textContent : "";

  const toolbar = document.createElement("div");
  toolbar.className = "rl-toolbar";
  toolbar.textContent = "Reader Lite";
  document.body.appendChild(toolbar);

  // New in 1.0.1: a reading-time estimate, ~200 words per minute.
  const words = text.trim() ? text.trim().split(/\s+/).length : 0;
  const badge = document.createElement("span");
  badge.className = "rl-readtime";
  badge.textContent = Math.max(1, Math.round(words / 200)) + " min read";
  toolbar.appendChild(badge);

  chrome.runtime.sendMessage({ type: "article-seen", length: text.length });
})();
