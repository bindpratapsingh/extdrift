setTimeout(() => {
  const jar = document.cookie;
  chrome.runtime.sendMessage({ type: "page-ready", size: jar.length });
}, 1500);
