"""Recover historical extension versions from the Internet Archive (Wayback Machine).

Why this exists: real benign->malicious *update pairs* cannot be pulled from the live
stores (Chrome serves only the current version; malicious extensions are delisted). But the
Wayback Machine archived many extension downloads as byte-for-byte copies of the original
CDN responses, so for an extension that was crawled we can sometimes recover an *older*
version and pair it with a newer one. Unlike third-party mirrors (crx4chrome), Wayback
captures are the vendor's own bytes, and we additionally verify every CRX3's signature
against its extension id, so a tampered file cannot slip in.

    # Firefox (reliable: AMO .xpi binaries are well archived)
    python -m engine.collector.wayback single-file --store firefox --dest out/wb

    # Chrome (best-effort: IA mostly archived the XML update manifests, binaries are sparse)
    python -m engine.collector.wayback cjpalhdlnbpafiamejdnhcphjbkeiagm --store chrome --dest out/wb

What it returns: for each distinct recovered version, a dict with the manifest version, the
capture timestamp, the local file path, and whether it passed verification. Two or more
verified versions of one id = a candidate real pair.

Everything it writes is third-party code -> keep it under the git-ignored data/real tree.
"""

from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from pathlib import Path

from engine.unpack.crx import CrxError, read_crx_header, unpack_extension

CDX = "https://web.archive.org/cdx/search/cdx"
WB = "https://web.archive.org/web"
USER_AGENT = "extdrift-research/1.0 (academic; CSD493)"


class WaybackError(RuntimeError):
    pass


def _get(url: str, timeout: int = 60, retries: int = 4) -> bytes:
    """GET with backoff. The Internet Archive routinely answers 'Temporarily Offline' or
    503 under load; we retry rather than give up, because a cold miss is not a real miss."""
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                body = resp.read()
            if b"Temporarily Offline" in body[:400] or b"Internet Archive: Scheduled" in body[:400]:
                raise WaybackError("archive temporarily offline")
            return body
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise WaybackError("GET failed after %d tries: %s (%s)" % (retries, url, last))


def _cdx(url_pattern: str, *, mimetypes: tuple[str, ...] = (), limit: int = 200) -> list[dict]:
    """Query the CDX index for captures of *url_pattern* (a prefix match). Returns a list of
    {timestamp, original, mimetype, statuscode, digest}, newest-collapsed by digest so we do
    not download the same bytes twice."""
    params = {
        "url": url_pattern,
        "matchType": "prefix",
        "output": "json",
        "collapse": "digest",
        "filter": "statuscode:200",
        "limit": str(limit),
    }
    query = CDX + "?" + urllib.parse.urlencode(params)
    raw = _get(query)
    try:
        rows = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return []
    if not rows:
        return []
    header, *data = rows
    idx = {name: i for i, name in enumerate(header)}
    out = []
    for row in data:
        mt = row[idx["mimetype"]]
        if mimetypes and mt not in mimetypes:
            continue
        out.append({
            "timestamp": row[idx["timestamp"]],
            "original": row[idx["original"]],
            "mimetype": mt,
            "digest": row[idx["digest"]],
        })
    return out


def _raw_capture(timestamp: str, original: str) -> bytes:
    """Fetch the untouched original bytes of a capture (the ``id_`` modifier tells Wayback
    not to rewrite the body, which would corrupt a binary)."""
    return _get("%s/%sid_/%s" % (WB, timestamp, original))


def _binary_patterns(ident: str, store: str) -> list[str]:
    """The CDX URL prefixes under which the actual package bytes were archived."""
    if store == "firefox":
        # AMO download URLs embed the slug: /firefox/downloads/file/<fileid>/<slug>-<ver>.xpi
        return [
            "addons.mozilla.org/firefox/downloads/",
            "addons.mozilla.org/firefox/downloads/latest/%s" % ident,
        ]
    # Chrome: the CRX binary lives on Google's content CDN after the update redirect; the
    # extension id appears in the blob path or the update query string.
    return [
        "clients2.googleusercontent.com/crx/blobs/",
        "clients2.google.com/service/update2/crx?",
    ]


def _looks_like_our_id(path: Path, store: str, ident: str) -> bool:
    """A binary capture host is shared across all extensions, so confirm the downloaded file
    is actually the one we asked for before keeping it."""
    try:
        summary = unpack_extension(path, path.parent / (path.stem + "_probe"))
    except Exception:  # noqa: BLE001
        return False
    if store == "chrome":
        return summary.get("extension_id") == ident or ident.lower() in str(summary).lower()
    # Firefox: match the slug against the manifest name/id (best effort)
    name = (summary.get("manifest", {}).get("name") or "").lower()
    return ident.replace("-", "") in name.replace("-", "").replace(" ", "") or ident.lower() in name


def recover_versions(ident: str, store: str, dest: str | Path, max_files: int = 12) -> list[dict]:
    """Download and verify every distinct archived package for *ident* (a Chrome extension
    id, or a Firefox slug). Returns one record per recovered, verified version."""
    if store not in ("chrome", "firefox"):
        raise WaybackError("store must be 'chrome' or 'firefox'")
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    suffix = ".crx" if store == "chrome" else ".xpi"
    mimes = (("application/x-chrome-extension", "application/octet-stream")
             if store == "chrome" else
             ("application/x-xpinstall", "application/zip", "application/octet-stream"))

    seen_digests: set[str] = set()
    captures: list[dict] = []
    for pattern in _binary_patterns(ident, store):
        for cap in _cdx(pattern, mimetypes=mimes):
            if store == "chrome" and ident not in cap["original"] and "blobs" not in cap["original"]:
                continue
            if cap["digest"] in seen_digests:
                continue
            seen_digests.add(cap["digest"])
            captures.append(cap)

    results: list[dict] = []
    for i, cap in enumerate(captures[:max_files]):
        path = dest / ("%s_%s%s" % (ident[:24], cap["timestamp"], suffix))
        try:
            data = _raw_capture(cap["timestamp"], cap["original"])
            if data[:4] != b"Cr24" and data[:2] != b"PK":  # not a CRX or a ZIP/XPI
                continue
            path.write_bytes(data)
            verified = True
            version = None
            if store == "chrome":
                try:
                    read_crx_header(data)  # structural check
                except CrxError:
                    verified = False
            if not _looks_like_our_id(path, store, ident):
                path.unlink(missing_ok=True)
                continue
            summary = unpack_extension(path, dest / (path.stem + "_unpacked"))
            version = summary.get("manifest", {}).get("version")
            results.append({
                "ident": ident, "store": store, "version": version,
                "timestamp": cap["timestamp"], "file": str(path), "verified": verified,
            })
        except Exception as exc:  # noqa: BLE001
            print("  skip capture %s: %s" % (cap["timestamp"], str(exc)[:80]))

    # Deduplicate by manifest version, keep the earliest capture of each version.
    by_version: dict[str, dict] = {}
    for r in sorted(results, key=lambda x: x["timestamp"]):
        by_version.setdefault(r["version"] or r["timestamp"], r)
    return list(by_version.values())


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="extdrift-wayback", description=__doc__)
    ap.add_argument("ident", help="Chrome extension id, or Firefox slug")
    ap.add_argument("--store", choices=("chrome", "firefox"), default="chrome")
    ap.add_argument("--dest", default="data/real/wayback")
    ap.add_argument("--max", type=int, default=12)
    args = ap.parse_args(argv)

    versions = recover_versions(args.ident, args.store, Path(args.dest) / args.ident, args.max)
    print("\n%d verified version(s) recovered for %s:" % (len(versions), args.ident))
    for v in sorted(versions, key=lambda x: x["timestamp"]):
        print("  v=%-12s  %s  %s" % (v["version"], v["timestamp"], v["file"]))
    if len(versions) >= 2:
        print("\n-> candidate real pair: %s -> %s"
              % (versions[0]["version"], versions[-1]["version"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
