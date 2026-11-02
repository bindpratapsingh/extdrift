"""Synthetic canary values and the search for them in outgoing traffic.

Temporal adjacency ("a password was read, then something was uploaded") can only ever suggest
exfiltration. A canary can show it: every sensitive value on the synthetic web is unique and
fake, so finding one inside a request that the page did not send is direct evidence that the
value travelled from the page to that destination.

Only marker *identifiers* are ever written to a trace or report. Values are scrubbed from URLs
and reports by :func:`redact` before anything is stored. Standard library only: this module runs
inside both containers and on the host.

Coverage limit: only the encodings listed in :func:`variants` are detected. Custom ciphers, XOR
and other keyed transforms defeat this search, which is why the temporal-candidate indicator
still exists alongside it.
"""

from __future__ import annotations

import base64
import codecs
import gzip
import hashlib
import re
import urllib.parse
import zlib
from dataclasses import dataclass

from engine.sandbox.scenarios import DUMMY_PASSWORD, DUMMY_USERNAME

#: Longest decompressed body that will be scanned, so a compression bomb cannot exhaust the gateway.
MAX_DECODED_BYTES = 8 * 1024 * 1024
#: base64-looking tokens at least this long are decoded once and scanned again.
_BASE64_TOKEN_RE = re.compile(rb"[A-Za-z0-9+/_-]{24,}={0,2}")


@dataclass(frozen=True)
class Marker:
    """One synthetic secret. ``sensitivity`` drives scoring: credential > session > financial > pii."""

    id: str
    kind: str
    value: str
    sensitivity: str


MARKERS: tuple[Marker, ...] = (
    Marker("password", "password", DUMMY_PASSWORD, "credential"),
    Marker("bank_password", "password", "XDRFT-Bank-Pw-7f3a91c2", "credential"),
    Marker("mail_password", "password", "XDRFT-Mail-Pw-1b8e44d0", "credential"),
    Marker("otp", "otp", "XDRFT-OTP-581204", "credential"),
    Marker("username", "username", DUMMY_USERNAME, "pii"),
    Marker("bank_username", "username", "xdrft.customer.7731", "pii"),
    Marker("session_cookie", "session", "demo-session-token-abc123", "session"),
    Marker("bank_session", "session", "XDRFT-SESS-9c1d7e5a2b6f4083", "session"),
    Marker("mail_session", "session", "XDRFT-SESS-4e0a6b3f8d217c95", "session"),
    Marker("auth_token", "auth_token", "XDRFT-AUTH-6f1c2a9e7b4d03e8", "session"),
    Marker("csrf_token", "auth_token", "XDRFT-CSRF-0d9b3c7e1a5f8426", "session"),
    Marker("api_key", "api_key", "XDRFT-APIKEY-a4e8d1c7f2b09635", "session"),
    Marker("card_number", "card", "4111111111111111", "financial"),
    Marker("card_number_spaced", "card", "4111 1111 1111 1111", "financial"),
    Marker("bank_account", "account", "XDRFT00112233445566", "financial"),
    Marker("ssn", "ssn", "000-12-3456", "pii"),
    Marker("phone", "phone", "+1-555-0100-417", "pii"),
    Marker("full_name", "name", "Xdrft Testperson", "pii"),
)

MARKERS_BY_ID = {marker.id: marker for marker in MARKERS}


@dataclass(frozen=True)
class Hit:
    marker_id: str
    kind: str
    sensitivity: str
    encoding: str
    location: str

    def as_dict(self) -> dict:
        return {"marker": self.marker_id, "kind": self.kind, "sensitivity": self.sensitivity,
                "encoding": self.encoding, "location": self.location}


def _base64_alignments(value: bytes, *, urlsafe: bool) -> list[bytes]:
    """The value's base64 at each of the three byte alignments, trimmed to its stable core.

    A marker embedded in a larger blob, such as ``btoa(JSON.stringify({p: secret}))``, starts at
    an arbitrary offset. Its encoding is then only recognisable with the characters influenced by
    the unknown neighbouring bytes removed.
    """
    encode = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    out = []
    for pad in range(3):
        encoded = encode(b"\0" * pad + value)
        stripped = encoded.rstrip(b"=")
        tail_is_partial = len(stripped) != len(encoded)
        lead = {0: 0, 1: 2, 2: 3}[pad]
        core = stripped[lead:-1] if tail_is_partial else stripped[lead:]
        if len(core) >= 8:
            out.append(core)
    return out


def variants(value: str) -> dict[bytes, str]:
    """Every byte string that would reveal *value*, mapped to the encoding's name."""
    raw = value.encode("utf-8")
    found: dict[bytes, str] = {}

    def add(data: bytes, name: str) -> None:
        found.setdefault(data, name)

    add(raw, "plain")
    add(urllib.parse.quote(value, safe="").encode(), "url")
    add(urllib.parse.quote_plus(value, safe="").encode(), "url")
    add(urllib.parse.quote(value, safe="").lower().encode(), "url")
    add(raw[::-1], "reversed")
    add(codecs.encode(value, "rot13").encode(), "rot13")
    add(raw.hex().encode(), "hex")
    add(raw.hex().upper().encode(), "hex")
    add(value.encode("utf-16-le"), "utf16")
    add(value.replace('"', '\\"').encode(), "json")
    for core in _base64_alignments(raw, urlsafe=False):
        add(core, "base64")
    for core in _base64_alignments(raw, urlsafe=True):
        add(core, "base64url")
    add(hashlib.md5(raw).hexdigest().encode(), "md5")
    add(hashlib.sha1(raw).hexdigest().encode(), "sha1")
    add(hashlib.sha256(raw).hexdigest().encode(), "sha256")
    return found


_VARIANTS: tuple[tuple[Marker, bytes, str], ...] = tuple(
    (marker, data, encoding)
    for marker in MARKERS
    for data, encoding in sorted(variants(marker.value).items(), key=lambda kv: -len(kv[0]))
)


def _decoded_forms(data: bytes) -> list[tuple[bytes, str]]:
    """The body as sent, plus any compressed or base64 layer that can be peeled off once."""
    forms = [(data, "")]
    if data[:2] == b"\x1f\x8b":
        try:
            forms.append((gzip.decompress(data)[:MAX_DECODED_BYTES], "gzip+"))
        except (OSError, EOFError, zlib.error):
            pass
    elif data[:1] == b"\x78":
        try:
            decompressor = zlib.decompressobj()
            forms.append((decompressor.decompress(data, MAX_DECODED_BYTES), "deflate+"))
        except zlib.error:
            pass
    for token in _BASE64_TOKEN_RE.findall(data[:MAX_DECODED_BYTES])[:64]:
        padded = token + b"=" * (-len(token) % 4)
        try:
            forms.append((base64.b64decode(padded.replace(b"-", b"+").replace(b"_", b"/")),
                          "base64+"))
        except ValueError:
            continue
    return forms


def scan(data: bytes | str, location: str) -> list[Hit]:
    """Return one hit per marker found in *data*, recording how it was encoded."""
    if isinstance(data, str):
        data = data.encode("utf-8", "surrogateescape")
    if not data:
        return []
    hits: dict[str, Hit] = {}
    for form, prefix in _decoded_forms(data):
        for marker, needle, encoding in _VARIANTS:
            if marker.id not in hits and needle in form:
                hits[marker.id] = Hit(marker.id, marker.kind, marker.sensitivity,
                                      prefix + encoding, location)
    # The spaced and unspaced card numbers are one secret; report the more specific match only.
    if "card_number" in hits and "card_number_spaced" in hits:
        del hits["card_number"]
    return list(hits.values())


def redact(text: str) -> str:
    """Replace every recognisable marker occurrence in *text* with its identifier."""
    if not text:
        return text
    encoded = text.encode("utf-8", "surrogateescape")
    for marker, needle, encoding in _VARIANTS:
        if needle in encoded:
            encoded = encoded.replace(needle, f"[MARKER:{marker.id}:{encoding}]".encode())
    return encoded.decode("utf-8", "replace")


def assert_no_marker_values(text: str) -> None:
    """Raise if *text* holds a raw marker value. A safety net for report generation."""
    for marker in MARKERS:
        if marker.value in text:
            raise ValueError(f"report text contains the raw value of marker {marker.id!r}")
