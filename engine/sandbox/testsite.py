"""A deterministic local web for the sandbox to browse.

The whole method rests on both extension versions seeing *identical* pages: browse the
real web twice and the ads, nonces and timestamps differ on their own, so the diff fills
up with noise that has nothing to do with the extension.  Record/replay through mitmproxy
is how we will get that property for real sites; this in-process site is how we get it
today, and it is stronger - the bytes are fixed by construction, not merely replayed.

Every hostname here is under the reserved ``.test`` TLD (RFC 6761) and is mapped to
loopback with Chromium's ``--host-resolver-rules``, so no DNS query and no packet ever
leaves the machine.  The "collector" is part of this server: a malicious extension can
POST to it and see a 200, and the stolen data lands in a local log we can inspect,
without anything reaching a real endpoint.
"""

from __future__ import annotations

import json
import random
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: Host -> path -> (content type, body).  Bodies are byte-identical on every request.
SITE: dict[str, dict[str, tuple[str, str]]] = {
    "demo-bank.test": {
        "/login": ("text/html", """<!doctype html>
<html><head><title>Demo Bank - Sign in</title></head>
<body>
  <h1>Demo Bank</h1>
  <article class="notice">Your session is protected. Never share your password.</article>
  <form id="login" method="post" action="/session">
    <label>Username <input name="username" type="text" autocomplete="username"></label>
    <label>Password <input id="password" name="password" type="password"></label>
    <button type="submit">Sign in</button>
  </form>
</body></html>"""),
        "/session": ("text/html", """<!doctype html>
<html><head><title>Demo Bank - Accounts</title></head>
<body><h1>Accounts</h1><article>Chequing: 1234.56</article></body></html>"""),
    },
    "webmail.test": {
        "/inbox": ("text/html", """<!doctype html>
<html><head><title>Webmail</title></head>
<body>
  <h1>Inbox</h1>
  <ul id="messages">
    <li class="message"><span class="contact-email">alex@example.test</span>
        <div class="message-body">Quarterly report attached.</div></li>
    <li class="message"><span class="contact-email">sam@example.test</span>
        <div class="message-body">Lunch on Friday?</div></li>
  </ul>
</body></html>"""),
    },
    "api.readermode.test": {
        "/v2/config": ("application/json", json.dumps({"theme": "sepia", "width": 720})),
    },
    "fonts.readercdn.test": {
        "/inter-var.woff2": ("font/woff2", "stub-font-bytes"),
    },
}

#: Hosts that exist purely to receive stolen data during an analysis run. Includes the
#: collector used by the weaponiser payloads (engine.weaponiser.payloads.COLLECTOR) so a
#: live-captured synthetic attack is confirmed by the collector's own log (ground truth).
COLLECTOR_HOSTS = {"collect-analytics.test", "collect-metrics.test"}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "extdrift-testsite"

    # Silence per-request logging; the trace is the record we care about.
    def log_message(self, fmt, *args):  # noqa: A003
        pass

    def _host(self) -> str:
        return (self.headers.get("Host") or "").split(":")[0].lower()

    def _send(self, status: int, content_type: str, body: bytes, cookie: str | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # No caching, so both runs make the same requests rather than one of them
        # silently reading from disk and producing a shorter trace.
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's naming
        host, path = self._host(), self.path.split("?")[0]
        if host in COLLECTOR_HOSTS:
            self.server.collected.append({"host": host, "method": "GET", "path": self.path})
            self._send(200, "application/json", b'{"ok":true}')
            return
        page = SITE.get(host, {}).get(path)
        if page is None:
            self._send(404, "text/plain", b"not found")
            return
        content_type, body = page
        # Noise mode models the real web: each page load pulls in a *different* third-party
        # resource (an ad/nonce host), so two runs of the SAME extension see different
        # traffic. This is the false-positive source that record/replay determinism removes;
        # the determinism ablation (experiments/ablation.py) runs with it on and off.
        if self.server.noise and content_type == "text/html":
            # A variable number of distinct third-party resources per load — like the real
            # web, where different visits pull different ads/beacons, so two runs of the
            # same extension differ in both which hosts and how many are contacted.
            tags = []
            for _ in range(random.randint(1, 3)):
                token = "".join(random.choice("abcdef0123456789") for _ in range(8))
                tags.append(f'<img src="http://ads-{token}.tracker.test/pixel.gif?n={token}">')
            body = body.replace("</body>", "".join(tags) + "</body>")
        # A session cookie on the bank gives a credential-stealing payload something
        # real to take, which is the point of the scenario.
        cookie = ("session=demo-session-token-abc123; Path=/"
                  if host == "demo-bank.test" else None)
        self._send(200, content_type, body.encode("utf-8"), cookie=cookie)

    def do_POST(self):  # noqa: N802
        host = self._host()
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if host in COLLECTOR_HOSTS:
            self.server.collected.append({
                "host": host, "method": "POST", "path": self.path,
                "body_len": len(body),
                "body_preview": body[:200].decode("utf-8", "replace"),
            })
            self._send(200, "application/json", b'{"ok":true}')
            return
        page = SITE.get(host, {}).get(self.path.split("?")[0])
        if page is None:
            self._send(404, "text/plain", b"not found")
            return
        content_type, page_body = page
        self._send(200, content_type, page_body.encode("utf-8"))


class TestSite:
    """The local site, started on an ephemeral port and stopped on context exit."""

    def __init__(self, port: int = 0, noise: bool = False):
        self.server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
        self.server.collected = []
        #: When True, each HTML page load injects a unique third-party resource, so two
        #: runs of the same extension diverge — the determinism ablation's "noisy web".
        self.server.noise = noise
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    @property
    def host_resolver_rules(self) -> str:
        """The Chromium flag that points every .test name at this server.

        Also maps the instrumentation's reporting host to a dead address: the driver
        reads report payloads off the outgoing request, so the request must never
        actually be delivered anywhere.
        """
        return (f"MAP *.test 127.0.0.1:{self.port},"
                "MAP extdrift-report.invalid 127.0.0.1:1")

    @property
    def collected(self) -> list[dict]:
        """Whatever the fake collector received - the ground truth for a leak."""
        return self.server.collected

    def __enter__(self) -> "TestSite":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()
