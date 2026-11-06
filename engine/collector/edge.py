"""Download a signed CRX from the Microsoft Edge Add-ons store.

Why: the "Two Heads are Better Than One" study (NDSS MADWeb'26) found extensions that were
removed from the Chrome Web Store for malware but are **still live on Edge**. Edge runs the
same Chromium/CRX3 machinery as Chrome, so its update endpoint hands back a signed CRX we
can verify and run. This is one of the few sources of *real, confirmed-malicious* extension
code that is still downloadable.

    from engine.collector.edge import edge_current_crx
    edge_current_crx("agnnmkflejgoopnfdmpoobimddgbpnnc", "out/x.crx", unpack_to="out/x")

The downloaded code is untrusted malware -> only ever run it inside the sealed sandbox, and
keep it under the git-ignored data/real tree (no redistribution).
"""

from __future__ import annotations

import urllib.request
from pathlib import Path

from engine.unpack.crx import unpack_extension

# The Edge endpoint mirrors Chrome's Omaha protocol; prodversion + acceptformat are required
# or it answers 204 (no content). This exact shape returns the current signed CRX3.
UPDATE = ("https://edge.microsoft.com/extensionwebstorebase/v1/crx"
          "?response=redirect&prodversion=120.0.0.0&acceptformat=crx3"
          "&x=id%3D{id}%26installsource%3Dondemand%26uc")
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) extdrift-research/1.0"


class EdgeError(RuntimeError):
    pass


def _get(url: str, timeout: int = 90) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed host
        return resp.read()


def edge_current_crx(ext_id: str, dest_crx: str | Path,
                     unpack_to: str | Path | None = None) -> dict:
    """Download the current signed CRX of an Edge extension; optionally verify + unpack it."""
    data = _get(UPDATE.format(id=ext_id))
    if not data or data[:4] != b"Cr24":
        raise EdgeError("no CRX for %s (got %d bytes, not a CRX)" % (ext_id, len(data)))
    dest_crx = Path(dest_crx)
    dest_crx.parent.mkdir(parents=True, exist_ok=True)
    dest_crx.write_bytes(data)
    out = {"ext_id": ext_id, "crx": str(dest_crx), "bytes": len(data),
           "source": "edge-addons-current"}
    if unpack_to:
        summary = unpack_extension(dest_crx, unpack_to)  # verifies the CRX3 structure + id
        out["unpacked_to"] = str(unpack_to)
        out["extension_id"] = summary.get("extension_id")
        out["version"] = summary["manifest"].get("version")
        out["manifest_version"] = summary["manifest"].get("manifest_version")
        out["name"] = summary["manifest"].get("name")
    return out


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="extdrift-edge")
    ap.add_argument("ext_id")
    ap.add_argument("--dest", default="data/real/edge")
    args = ap.parse_args(argv)
    dest = Path(args.dest) / args.ext_id
    r = edge_current_crx(args.ext_id, dest / "v.crx", unpack_to=dest / "unpacked")
    print("downloaded %s  %s v%s  (%d bytes)"
          % (r["ext_id"], r.get("name"), r.get("version"), r["bytes"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
