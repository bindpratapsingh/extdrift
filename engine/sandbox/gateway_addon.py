"""mitmproxy addon: answers every request locally and records it as raw evidence.

This file runs inside the gateway container, the only thing the browser can reach. There is no
upstream: each response is created here from the replay bundle, so a request has nowhere further to
go. The container's network has no route out either, so a bug in this file still could not leak.

Three kinds of request arrive:

* instrumentation reports from the prelude, written to ``reports.jsonl``;
* control messages from the driver, which carry a secret token the extension cannot read;
* everything else, the wire record of what the browser really sent, written to ``flows.jsonl``.

Secret values never reach the evidence files: URLs, header values and report bodies pass through
:func:`engine.sandbox.markers.redact` first, and request bodies are stored as metadata only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import socket
import threading
import time
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from mitmproxy import http

from engine.sandbox.markers import redact, scan
from engine.sandbox.replay import Bundle, builtin_bundle, load_bundle
from engine.sandbox.testsite import COLLECTOR_HOSTS

REPORT_HOST = "extdrift-report.test"
CONTROL_HOST = "extdrift-control.test"
MAX_REPORT_BYTES = 256 * 1024
#: Headers kept with their (redacted) values. All other header names are kept without values.
KEPT_HEADERS = ("origin", "referer", "content-type", "sec-fetch-site", "sec-fetch-mode",
                "sec-fetch-dest", "sec-fetch-user", "upgrade")
WS_SINK_PORT = 9001
CORS = (("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Headers", "*"),
        ("Access-Control-Allow-Methods", "*"))

log = logging.getLogger("extdrift.gateway")


def _response(status: int, body: bytes, headers: list[tuple[str, str]]) -> http.Response:
    return http.Response.make(status, body, [(k.encode(), v.encode()) for k, v in headers])


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data[:65536])
    total = sum(counts.values())
    return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 3)


def body_keys(content_type: str, body: bytes) -> list[str]:
    """Top-level field names of a JSON or form body. Names only, never values."""
    try:
        text = body[:262144].decode("utf-8")
        if "json" in content_type or text[:1] in "{[":
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return sorted(str(k)[:64] for k in parsed)[:64]
            return []
        return sorted({k[:64] for k, _ in parse_qsl(text, keep_blank_values=True)})[:64]
    except (ValueError, UnicodeDecodeError):
        return []


class _Writer:
    """Append-only JSONL with a hard ceiling, so a flood cannot exhaust the evidence volume."""

    def __init__(self, path: Path, max_bytes: int):
        self.path, self.max_bytes = path, max_bytes
        self.written = 0
        self.truncated = False
        self.fh = path.open("a", encoding="utf-8", buffering=1)
        self.lock = threading.Lock()

    def write(self, record: dict) -> None:
        line = json.dumps(record, sort_keys=True) + "\n"
        with self.lock:
            if self.written + len(line) > self.max_bytes:
                if not self.truncated:
                    self.truncated = True
                    self.fh.write(json.dumps({"truncated": True, "t": time.time()}) + "\n")
                return
            self.written += len(line)
            self.fh.write(line)


def _ws_sink_serve() -> None:
    """A loopback WebSocket echo server, so sockets open and their frames can be observed.

    It only ever serves this container: mitmproxy connects to it on the browser's behalf.
    """
    from wsproto import ConnectionType, WSConnection
    from wsproto.events import AcceptConnection, BytesMessage, CloseConnection, Request, TextMessage

    def serve(conn: socket.socket) -> None:
        ws = WSConnection(ConnectionType.SERVER)
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    return
                ws.receive_data(data)
                for event in ws.events():
                    if isinstance(event, Request):
                        conn.sendall(ws.send(AcceptConnection()))
                    elif isinstance(event, (TextMessage, BytesMessage)):
                        conn.sendall(ws.send(type(event)(data=event.data)))
                    elif isinstance(event, CloseConnection):
                        conn.sendall(ws.send(event.response()))
                        return
        except Exception:
            return
        finally:
            conn.close()

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", WS_SINK_PORT))
    server.listen(32)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


class Gateway:
    def __init__(self) -> None:
        self.evidence = Path(os.environ.get("EXTDRIFT_EVIDENCE_DIR", "/evidence"))
        self.token = os.environ.get("EXTDRIFT_CONTROL_TOKEN", "")
        self.salt = os.environ.get("EXTDRIFT_HASH_SALT", "").encode()
        max_bytes = int(os.environ.get("EXTDRIFT_MAX_EVIDENCE_BYTES", str(256 * 1024 * 1024)))
        self.flows = _Writer(self.evidence / "flows.jsonl", max_bytes)
        self.reports = _Writer(self.evidence / "reports.jsonl", max_bytes)
        self.control = _Writer(self.evidence / "control.jsonl", 16 * 1024 * 1024)
        self.bundle = self._load_bundle()
        self.seq = 0
        self.seq_lock = threading.Lock()
        self.scenario: str | None = None
        (self.evidence / "bundle.json").write_text(json.dumps(
            {"name": self.bundle.name, "digest": self.bundle.digest,
             "hosts": sorted(self.bundle.hosts)}), encoding="utf-8")
        threading.Thread(target=_ws_sink_serve, daemon=True).start()

    @staticmethod
    def _load_bundle() -> Bundle:
        path = os.environ.get("EXTDRIFT_BUNDLE_FILE")
        if path:
            return load_bundle(path)
        return builtin_bundle(json.loads(os.environ.get("EXTDRIFT_TARGETED_HOSTS", "[]")))

    def _next(self) -> int:
        with self.seq_lock:
            self.seq += 1
            return self.seq

    # -- local endpoints --------------------------------------------------------------------

    def _handle_report(self, flow: http.HTTPFlow) -> None:
        raw = (flow.request.raw_content or b"")[:MAX_REPORT_BYTES]
        if flow.request.method == "POST":
            try:
                event = json.loads(redact(raw.decode("utf-8", "replace")))
            except ValueError:
                event = {"malformed": True}
            if isinstance(event, dict):
                # A stale scenario label is harmless; arrival order decides which scenario applies.
                self.reports.write({"arrival": time.time(), "scenario": self.scenario,
                                    "event": event})
        flow.response = _response(200, b'{"ok":true}', [
            ("Content-Type", "application/json"), *CORS])

    def _handle_control(self, flow: http.HTTPFlow) -> bool:
        """Serve a driver message. Returns False when the token is wrong, so the request is
        then logged as ordinary traffic and an extension probing this host stays visible."""
        parts = flow.request.path.strip("/").split("/")
        if len(parts) < 2 or parts[0] != self.token or not self.token:
            return False
        command = parts[1]
        if command == "scenario" and len(parts) >= 4:
            self.scenario = parts[3] if parts[2] == "start" else None
            self.control.write({"t": time.time(), "command": parts[2], "scenario": parts[3]})
        elif command == "health":
            pass
        else:
            self.control.write({"t": time.time(), "command": command})
        payload = json.dumps({"ok": True, "flows": self.seq,
                              "digest": self.bundle.digest}).encode()
        flow.response = _response(200, payload, [("Content-Type", "application/json")])
        return True

    # -- request hook -----------------------------------------------------------------------

    def _serve(self, flow: http.HTTPFlow) -> tuple[str, str | None]:
        """Set the response for a request. Returns (source, redirect location)."""
        host = flow.request.pretty_host.lower()
        path = urlsplit(flow.request.path).path or "/"
        method = flow.request.method
        if method == "OPTIONS":
            flow.response = _response(204, b"", list(CORS))
            return "preflight", None
        page = self.bundle.lookup(host, path)
        if page is not None:
            headers = [("Content-Type", page.content_type), ("Cache-Control", "no-store"),
                       *page.headers]
            flow.response = _response(page.status, page.body, headers)
            location = dict(page.headers).get("Location")
            return ("redirect" if location else "bundle"), location
        if host in COLLECTOR_HOSTS or method in ("POST", "PUT", "PATCH"):
            flow.response = _response(200, b'{"ok":true}', [
                ("Content-Type", "application/json"), *CORS])
            return "sink", None
        flow.response = _response(204, b"", list(CORS))
        return "sink", None

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host.lower()
        if host == REPORT_HOST:
            self._handle_report(flow)
            return
        if host == CONTROL_HOST and self._handle_control(flow):
            return

        headers = flow.request.headers
        is_websocket = headers.get("upgrade", "").lower() == "websocket"
        body = flow.request.raw_content or b""
        url = flow.request.pretty_url
        hits = [hit.as_dict() for hit in scan(url, "url")]
        kept = {}
        for name, value in headers.items():
            lowered = name.lower()
            hits += [hit.as_dict() for hit in scan(value, f"header:{lowered}")]
            if lowered in KEPT_HEADERS:
                kept[lowered] = redact(value)
        hits += [hit.as_dict() for hit in scan(body, "body")]
        cookie_names = sorted(
            part.split("=", 1)[0].strip() for part in headers.get("cookie", "").split(";") if "=" in part)

        if is_websocket:
            flow.metadata["extdrift_ws"] = True
            flow.metadata["extdrift_host"] = host
            flow.metadata["extdrift_seq"] = self._next()
            source, location = "websocket", None
            # Terminate at the local echo server: frames are visible and nothing leaves.
            flow.request.scheme, flow.request.host, flow.request.port = (
                "http", "127.0.0.1", WS_SINK_PORT)
            status = 101
        else:
            source, location = self._serve(flow)
            status = flow.response.status_code

        content_type = headers.get("content-type", "")
        self.flows.write({
            "kind": "http", "seq": flow.metadata.get("extdrift_seq") or self._next(),
            "t": flow.request.timestamp_start or time.time(), "scenario": self.scenario,
            "method": flow.request.method, "url": redact(url),
            "scheme": flow.client_conn.tls_established and "https" or "http",
            "host": host, "port": flow.request.port if not is_websocket else None,
            "http_version": flow.request.http_version,
            "headers": kept, "header_names": sorted({n.lower() for n in headers.keys()}),
            "cookie_names": cookie_names, "has_authorization": "authorization" in headers,
            "body_len": len(body),
            "body_sha256": hashlib.sha256(self.salt + body).hexdigest() if body else None,
            "body_entropy": _entropy(body), "body_keys": body_keys(content_type, body),
            "marker_hits": hits,
            "response": {"status": status, "source": source, "location": location},
            # The network has no real destinations; only an IP literal in the URL names one.
            "destination_ip": host if _is_ip_literal(host) else None,
        })

    # -- other flow lifecycle hooks ---------------------------------------------------------

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        message = flow.websocket.messages[-1] if flow.websocket else None
        if message is None or not message.from_client:
            return
        host = flow.metadata.get("extdrift_host", "")
        self.flows.write({
            "kind": "websocket_message", "seq": self._next(), "t": time.time(),
            "scenario": self.scenario, "host": host, "open_seq": flow.metadata.get("extdrift_seq"),
            "body_len": len(message.content), "body_entropy": _entropy(message.content),
            "marker_hits": [hit.as_dict() for hit in scan(message.content, "websocket")],
        })

    def error(self, flow: http.HTTPFlow) -> None:
        self.flows.write({
            "kind": "connection_failure", "seq": self._next(), "t": time.time(),
            "scenario": self.scenario, "host": flow.request.pretty_host.lower() if flow.request else "",
            "url": redact(flow.request.pretty_url) if flow.request else "",
            "error": str(flow.error)[:200] if flow.error else "",
        })

    def tls_failed_client(self, data) -> None:
        sni = getattr(data.context.client, "sni", None)
        self.flows.write({"kind": "tls_failure", "seq": self._next(), "t": time.time(),
                          "scenario": self.scenario, "host": (sni or "").lower(),
                          "error": str(getattr(data.conn, "error", ""))[:200]})

    def tcp_start(self, flow) -> None:
        self.flows.write({"kind": "raw_tcp", "seq": self._next(), "t": time.time(),
                          "scenario": self.scenario,
                          "host": str(flow.server_conn.address[0]) if flow.server_conn.address else "",
                          "port": flow.server_conn.address[1] if flow.server_conn.address else None})

    def tcp_message(self, flow) -> None:
        message = flow.messages[-1]
        if message.from_client:
            self.flows.write({
                "kind": "raw_tcp_data", "seq": self._next(), "t": time.time(),
                "scenario": self.scenario, "body_len": len(message.content),
                "marker_hits": [hit.as_dict() for hit in scan(message.content, "tcp")],
                "host": str(flow.server_conn.address[0]) if flow.server_conn.address else "",
            })

    def done(self) -> None:
        (self.evidence / "gateway_summary.json").write_text(json.dumps({
            "flows": self.seq, "flows_truncated": self.flows.truncated,
            "reports_truncated": self.reports.truncated,
        }), encoding="utf-8")


def _is_ip_literal(host: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except OSError:
            continue
    return False


addons = [Gateway()]
