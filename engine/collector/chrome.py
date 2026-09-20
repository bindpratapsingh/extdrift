"""Chrome Web Store CRX collector — the honest story about Chrome version history.

Chrome is the hard case the AMO collector is not. Unlike AMO, Google's update service serves
**only the current version** of an extension and keeps no public version history, so real
consecutive (v_N, v_N+1) Chrome pairs cannot simply be downloaded the way Firefox pairs can.
This module is deliberately explicit about the three real options:

1. ``chrome_current_crx`` / ``chrome_update_info`` — the OFFICIAL update endpoint
   (clients2.google.com). Robust, no scraping: it returns the current version's signed CRX
   for any *listed* extension. Paired with periodic snapshots (engine.collector.snapshot),
   this is the longitudinal collection method — snapshot the current version now, snapshot
   again after real auto-updates — which is how a Chrome version corpus is built over time
   (the approach behind You've Changed, CCS'20).

2. ``chrome_probe`` — is an extension still *listed*? The 7,382 known-malicious IDs are
   overwhelmingly delisted, so the endpoint returns no download for them. Probing quantifies
   exactly that survivorship/delisting bias — the empirical reason historical archives are
   needed for the malicious class (experiments/chrome_delisting_probe.py).

3. ``crx4chrome_page`` — a BEST-EFFORT resolver for the only place historical Chrome CRX
   files survive: third-party archives (crx4chrome). It is fragile (HTML scraping, subject to
   the site's terms and layout) and is provided as a documented fallback, not a primary path.

Safety: downloaded CRX files are never executed here and never redistributed (data/real/crx is
gitignored). A known-malicious CRX is hostile input — analyse it only in the sealed sandbox.
"""

from __future__ import annotations

import re
import urllib.request
from pathlib import Path

from engine.unpack.crx import unpack_extension

UPDATE_ENDPOINT = "https://clients2.google.com/service/update2/crx"
CRX4CHROME = "https://www.crx4chrome.com"
USER_AGENT = "Mozilla/5.0 (extdrift-collector; academic research CSD493)"
# A deliberately high product version so the update server always offers the *current*
# version as an "update" (with prodversion left low it answers 'noupdate').
_PRODVERSION = "9999.0.0.0"

_EXT_ID_RE = re.compile(r"^[a-p]{32}$")


class ChromeError(RuntimeError):
    """Raised when a Chrome extension cannot be located or downloaded."""


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed hosts
        return resp.read()


def _update_url(ext_id: str) -> str:
    # x carries the app query, itself url-encoded: id=<id>&installsource=ondemand&uc
    return (f"{UPDATE_ENDPOINT}?prodversion={_PRODVERSION}&acceptformat=crx2,crx3"
            f"&x=id%3D{ext_id}%26installsource%3Dondemand%26uc")


def _parse_update_xml(xml: str, ext_id: str) -> dict:
    """Parse a gupdate response into {ext_id, app_status, status, version, codebase}."""
    app = re.search(r"<app\s+appid=\"" + re.escape(ext_id) + r"\"[^>]*\bstatus=\"([^\"]+)\"", xml)
    check = re.search(r"<updatecheck\b([^>]*?)/?>", xml)
    attrs = check.group(1) if check else ""
    status = (re.search(r'status="([^"]+)"', attrs) or [None, None])[1]
    codebase = (re.search(r'codebase="([^"]+)"', attrs) or [None, None])[1]
    version = (re.search(r'version="([^"]+)"', attrs) or [None, None])[1]
    return {"ext_id": ext_id, "app_status": app.group(1) if app else None,
            "status": status, "version": version, "codebase": codebase}


def chrome_update_info(ext_id: str, timeout: int = 40) -> dict:
    """Query the official update endpoint for one extension id.

    Returns {ext_id, app_status, status, version, codebase}. ``codebase`` is the direct CRX
    URL when the extension is listed, else None (delisted / invalid id / not offered).
    """
    if not _EXT_ID_RE.match(ext_id):
        raise ChromeError(f"not a valid 32-char extension id: {ext_id!r}")
    xml = _get(_update_url(ext_id), timeout).decode("utf-8", "replace")
    return _parse_update_xml(xml, ext_id)


def chrome_probe(ext_id: str, timeout: int = 30) -> dict:
    """Is *ext_id* still listed in the Chrome Web Store? (delisting / survivorship check)."""
    try:
        info = chrome_update_info(ext_id, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - a probe must never raise mid-sweep
        return {"ext_id": ext_id, "live": False, "version": None, "error": str(exc)[:80]}
    return {"ext_id": ext_id, "live": bool(info["codebase"]),
            "version": info["version"], "status": info["status"]}


def chrome_current_crx(ext_id: str, dest_crx: str | Path, unpack_to: str | Path | None = None) -> dict:
    """Download the CURRENT signed CRX of a listed extension; optionally unpack it."""
    info = chrome_update_info(ext_id)
    if not info["codebase"]:
        raise ChromeError(f"no current version for {ext_id} "
                          f"(status={info['status']}, likely delisted or invalid)")
    dest_crx = Path(dest_crx)
    dest_crx.parent.mkdir(parents=True, exist_ok=True)
    dest_crx.write_bytes(_get(info["codebase"]))
    out = {"ext_id": ext_id, "version": info["version"], "crx": str(dest_crx),
           "source": "chrome-webstore-current"}
    if unpack_to:
        summary = unpack_extension(dest_crx, unpack_to)
        out["unpacked_to"] = str(unpack_to)
        out["manifest_version"] = summary["manifest"].get("manifest_version")
        out["name"] = summary["manifest"].get("name")
    return out


# --------------------------------------------------------------------------------------
# Historical archive (best-effort, fragile) — the only place old Chrome CRX files survive
# --------------------------------------------------------------------------------------

def crx4chrome_page(ext_id: str, timeout: int = 40) -> dict:
    """Best-effort lookup of an extension's crx4chrome archive page.

    Returns {ext_id, page, versions:[{version, detail_url}]} parsed from the listing, or an
    ``error``. This scrapes a third-party site whose layout and terms may change at any time;
    treat it as a manual research aid, not an automated pipeline. It never downloads a CRX by
    itself — a human confirms the version and licence first.
    """
    url = f"{CRX4CHROME}/extensions/{ext_id}/"
    try:
        html = _get(url, timeout).decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        return {"ext_id": ext_id, "page": url, "error": str(exc)[:100], "versions": []}
    return {"ext_id": ext_id, "page": url, "versions": _parse_crx4chrome(html)}


def _parse_crx4chrome(html: str) -> list[dict]:
    """Extract [{version, detail_url}] from a crx4chrome extension page (best effort)."""
    versions, seen = [], set()
    for m in re.finditer(r'href="(/crx/\d+/)"[^>]*>(?:[^<]*?)([0-9]+(?:\.[0-9]+){1,3})', html):
        ver = m.group(2)
        if ver not in seen:
            seen.add(ver)
            versions.append({"version": ver, "detail_url": CRX4CHROME + m.group(1)})
    return versions


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="extdrift-chrome",
                                 description="Chrome Web Store CRX collector (current + probe).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("probe", help="check whether an extension id is still listed")
    p.add_argument("ext_id")
    g = sub.add_parser("get", help="download the current CRX of a listed extension")
    g.add_argument("ext_id"); g.add_argument("--dest", default="data/real/crx")
    h = sub.add_parser("history", help="best-effort crx4chrome historical listing (fragile)")
    h.add_argument("ext_id")
    args = ap.parse_args(argv)

    if args.cmd == "probe":
        r = chrome_probe(args.ext_id)
        print(f"[chrome] {args.ext_id}: {'LISTED v'+str(r['version']) if r['live'] else 'NOT listed'}"
              f" (status={r.get('status')})")
    elif args.cmd == "get":
        dest = Path(args.dest) / args.ext_id
        r = chrome_current_crx(args.ext_id, dest / "current.crx", unpack_to=dest / "current")
        print(f"[chrome] {args.ext_id} v{r['version']} -> {r['unpacked_to']} (MV{r.get('manifest_version')})")
    else:
        r = crx4chrome_page(args.ext_id)
        if r.get("error"):
            print(f"[chrome] crx4chrome lookup failed: {r['error']}")
        else:
            print(f"[chrome] {r['page']} — {len(r['versions'])} archived versions")
            for v in r["versions"][:12]:
                print(f"   {v['version']:14s} {v['detail_url']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
