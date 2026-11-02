"""Replay bundles: the fixed web served to both versions of an extension.

A bundle maps (host, path) to one fixed response and has a content hash. The hash travels with the
trace, so a comparison can prove that the two versions received byte-identical pages. The built-in
bundle is the synthetic web. :func:`record_urls` produces a bundle from other pages for replay
through the same gateway; it runs with no extension loaded, and replay never touches the network.

Recording rewrites nothing, so a page that computes values with ``Date`` or ``Math.random`` in its
own scripts will still vary at replay time. Only network responses are made fixed.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from engine.sandbox.synthetic_web import REDIRECTS, SET_COOKIES
from engine.sandbox.testsite import SITE

#: Bumped when the shape of a bundle file changes.
BUNDLE_FORMAT = 1
MAX_RECORDED_BODY = 4 * 1024 * 1024


@dataclass
class Response:
    status: int
    content_type: str
    body: bytes
    headers: tuple[tuple[str, str], ...] = ()


@dataclass
class Bundle:
    """Fixed responses keyed by host and path, plus the identity of that content."""

    name: str
    pages: dict[str, dict[str, Response]] = field(default_factory=dict)
    entry_urls: tuple[str, ...] = ()

    @property
    def hosts(self) -> set[str]:
        return set(self.pages)

    def lookup(self, host: str, path: str) -> Response | None:
        return self.pages.get(host, {}).get(path)

    @property
    def digest(self) -> str:
        """SHA-256 over the served content, in a canonical order."""
        h = hashlib.sha256()
        for host in sorted(self.pages):
            for path in sorted(self.pages[host]):
                r = self.pages[host][path]
                h.update(f"{host}\0{path}\0{r.status}\0{r.content_type}\0".encode())
                for name, value in r.headers:
                    h.update(f"{name}:{value}\0".encode())
                h.update(hashlib.sha256(r.body).digest())
        return h.hexdigest()

    def to_file(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "format": BUNDLE_FORMAT, "name": self.name, "entry_urls": list(self.entry_urls),
            "pages": {
                host: {
                    p: {"status": r.status, "content_type": r.content_type,
                        "headers": [list(h) for h in r.headers],
                        "body_b64": base64.b64encode(r.body).decode()}
                    for p, r in paths.items()
                } for host, paths in self.pages.items()
            },
        }
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        return path


def load_bundle(path: str | Path) -> Bundle:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("format") != BUNDLE_FORMAT:
        raise ValueError(f"{path}: unsupported bundle format {payload.get('format')!r}")
    pages: dict[str, dict[str, Response]] = {}
    for host, paths in payload["pages"].items():
        pages[host] = {
            p: Response(int(r["status"]), r["content_type"], base64.b64decode(r["body_b64"]),
                        tuple((str(a), str(b)) for a, b in r.get("headers", [])))
            for p, r in paths.items()
        }
    return Bundle(payload["name"], pages, tuple(payload.get("entry_urls", ())))


def builtin_bundle(targeted_hosts: list[str] | None = None) -> Bundle:
    """The synthetic web, plus a neutral login page on any hostname the manifest targets."""
    from engine.sandbox.synthetic_web import TARGETED_PAGE

    pages: dict[str, dict[str, Response]] = {}
    for host, paths in SITE.items():
        cookies = tuple(("Set-Cookie", c) for c in SET_COOKIES.get(host, ()))
        pages[host] = {
            path: Response(200, content_type, body.encode("utf-8"),
                           cookies if content_type == "text/html" else ())
            for path, (content_type, body) in paths.items()
        }
    for (host, path), target in REDIRECTS.items():
        pages.setdefault(host, {})[path] = Response(302, "text/plain", b"",
                                                    (("Location", target),))
    for host in targeted_hosts or []:
        body = TARGETED_PAGE.encode("utf-8")
        pages.setdefault(host, {})
        pages[host].setdefault("/", Response(200, "text/html", body))
        pages[host].setdefault("/login", Response(200, "text/html", body))
    return Bundle("synthetic-web-v1", pages)


def add_response(bundle: Bundle, url: str, status: int, content_type: str, body: bytes,
                 location: str | None = None) -> None:
    """Add one observed response. The first response for a (host, path) wins."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if not host or len(body) > MAX_RECORDED_BODY:
        return
    path = parts.path or "/"
    headers = (("Location", location),) if location else ()
    bundle.pages.setdefault(host, {}).setdefault(
        path, Response(status, content_type, body, headers))


def record_urls(urls: list[str], out_path: str | Path, *, name: str = "recorded",
                proxy: str | None = None, settle_ms: int = 1500) -> Bundle:
    """Visit *urls* with no extension loaded and save every response into a bundle."""
    from playwright.sync_api import sync_playwright

    bundle = Bundle(name, entry_urls=tuple(urls))

    def on_response(response) -> None:
        try:
            body = response.body()
        except Exception:
            body = b""
        headers = response.headers
        add_response(bundle, response.url, response.status,
                     headers.get("content-type", "application/octet-stream"), body,
                     headers.get("location"))

    with sync_playwright() as playwright:
        args = {"proxy": {"server": proxy}} if proxy else {}
        browser = playwright.chromium.launch(headless=True, **args)
        page = browser.new_context(ignore_https_errors=True).new_page()
        page.on("response", on_response)
        for url in urls:
            page.goto(url, wait_until="load")
            page.wait_for_timeout(settle_ms)
        browser.close()
    bundle.to_file(out_path)
    return bundle
