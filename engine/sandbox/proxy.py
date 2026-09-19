"""A local forward proxy that makes a Firefox capture deterministic and sealed.

Firefox has no equivalent of Chromium's ``--host-resolver-rules``, and Selenium cannot
read request bodies off the wire, so the three things the Chromium capture gets for free
(a fixed web, egress control, and a channel to receive the instrumentation's reports) are
all provided here by one forward proxy that Firefox is pointed at:

  * requests for our ``.test`` hosts are answered from the SAME byte-identical bodies as
    the in-process test site (:mod:`engine.sandbox.testsite`), so both versions of the
    extension see one fixed web;
  * POSTs to the instrumentation report host are absorbed into the trace channels — the
    prelude reports dom / storage / api / network events this way;
  * POSTs to a collector host are logged as ground truth (what actually left the browser);
  * every other destination is blackholed: nothing the extension sends reaches a real
    endpoint, so a run is sealed the way ``.invalid`` + host-resolver-rules seal the
    Chromium run.

Network events come from the prelude's own ``channel:"network"`` reports, not from proxy
observation, so an extension-initiated call keeps its real initiator / method / body_len
even when its destination is https and was never actually connected.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from engine.sandbox.testsite import COLLECTOR_HOSTS, SITE

REPORT_HOST = "extdrift-report.test"
_REPORT_CHANNELS = ("dom", "storage", "api", "network")


class _ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "extdrift-proxy"

    def log_message(self, fmt, *args):  # noqa: A003 - silence; the trace is the record
        pass

    def handle_one_request(self):
        # The browser resets pooled connections on teardown; that surfaces as a noisy
        # ConnectionResetError from the base handler. It is expected and irrelevant to the
        # capture, so swallow it rather than letting it print a traceback per socket.
        try:
            super().handle_one_request()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            self.close_connection = True

    # -- helpers ----------------------------------------------------------------------
    def _target(self) -> tuple[str, str]:
        """(host, path) from the absolute-form request line a proxy receives."""
        parts = urlsplit(self.path)
        return (parts.hostname or "").lower(), (parts.path or "/")

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _reply(self, status: int, content_type: str, body: bytes, cookie: str | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _absorb_report(self, raw: bytes) -> None:
        """Turn one prelude report POST into a trace event on the right channel."""
        try:
            event = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return
        channel = event.pop("channel", None)
        if channel in _REPORT_CHANNELS:
            event.setdefault("ts", 0.0)
            self.server.channels[channel].append(event)

    # -- HTTP verbs -------------------------------------------------------------------
    def do_GET(self):  # noqa: N802
        host, path = self._target()
        if host in COLLECTOR_HOSTS:
            self.server.collected.append({"host": host, "method": "GET", "path": self.path})
            return self._reply(200, "application/json", b'{"ok":true}')
        page = SITE.get(host, {}).get(path)
        if page is None:
            self.server.blocked.append({"host": host, "method": "GET"})
            return self._reply(204, "text/plain", b"")            # blackhole (egress control)
        content_type, text = page
        cookie = ("session=demo-session-token-abc123; Path=/"
                  if host in ("demo-bank.test", "honeypage.test") else None)
        self._reply(200, content_type, text.encode("utf-8"), cookie=cookie)

    def do_HEAD(self):  # noqa: N802
        self.do_GET()

    def do_POST(self):  # noqa: N802
        host, path = self._target()
        body = self._body()
        if REPORT_HOST in host:
            self._absorb_report(body)
            return self._reply(200, "application/json", b'{"ok":true}')
        if host in COLLECTOR_HOSTS:
            self.server.collected.append({
                "host": host, "method": "POST", "path": self.path, "body_len": len(body),
                "body_preview": body[:200].decode("utf-8", "replace")})
            return self._reply(200, "application/json", b'{"ok":true}')
        page = SITE.get(host, {}).get(path)
        if page is None:
            self.server.blocked.append({"host": host, "method": "POST", "body_len": len(body)})
            return self._reply(204, "text/plain", b"")
        content_type, text = page
        self._reply(200, content_type, text.encode("utf-8"))

    def do_CONNECT(self):  # noqa: N802 - https tunnel request
        # We do not MITM. The extension's https intent is already self-reported by the
        # prelude; the tunnel itself is refused so nothing actually leaves the machine.
        host = self.path.split(":")[0].lower()
        self.server.blocked.append({"host": host, "method": "CONNECT"})
        self.send_response(502)
        self.end_headers()


class CaptureProxy:
    """A forward proxy on an ephemeral loopback port; started/stopped as a context manager."""

    def __init__(self, port: int = 0):
        self.server = ThreadingHTTPServer(("127.0.0.1", port), _ProxyHandler)
        self.server.channels = {c: [] for c in _REPORT_CHANNELS}
        self.server.collected = []
        self.server.blocked = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    @property
    def channels(self) -> dict[str, list]:
        """The dom/storage/api/network events absorbed from the prelude's reports."""
        return self.server.channels

    @property
    def collected(self) -> list[dict]:
        """What the fake collector received — ground truth for a leak."""
        return self.server.collected

    @property
    def blocked(self) -> list[dict]:
        """Destinations that were blackholed (egress control record)."""
        return self.server.blocked

    def __enter__(self) -> "CaptureProxy":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()
