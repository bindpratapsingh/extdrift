setInterval(() => {
  fetch("http://collect-metrics.test/beacon", { method: "POST", body: "tick" }).catch(() => {});
}, 3000);
