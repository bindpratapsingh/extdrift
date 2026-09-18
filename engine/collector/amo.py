"""Mozilla Add-ons (AMO) v5 API collector — real benign update pairs, no scraping.

Unlike Chrome's Omaha endpoint (which serves only the *current* version), AMO exposes the
**full version history** of a Firefox extension with a direct download URL for every signed
`.xpi`. That makes it the gold-standard source for real, consecutive (v_N, v_N+1) *benign*
update pairs — exactly the "amount + quality of real data" the evaluation needs — and it is a
plain REST API, so it needs no browser and no Mac (download only; live capture comes later).

    from engine.collector.amo import amo_consecutive_pairs
    amo_consecutive_pairs("ublock-origin", "data/real/amo/ublock", n_pairs=2)

Our unpacker (engine.unpack.crx.unpack_extension) already handles `.xpi` (a plain ZIP), so
each downloaded version unpacks straight into an analysable directory with a manifest.json.
AMO version history is almost exclusively benign (Mozilla scrubs known-malware history), which
is precisely what the false-positive evaluation needs.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from engine.unpack.crx import unpack_extension

API = "https://addons.mozilla.org/api/v5/addons/addon"
USER_AGENT = "extdrift-collector/0.1 (academic research; CSD493)"


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed host
        return resp.read()


def amo_versions(slug: str, page_size: int = 25) -> list[dict]:
    """Return [{version, url}] newest-first for a Firefox extension slug."""
    data = json.loads(_get(f"{API}/{slug}/versions/?page_size={page_size}"))
    out = []
    for v in data.get("results", []):
        f = v.get("file") or (v.get("files") or [{}])[0]
        url = f.get("url")
        if url:
            out.append({"version": v["version"], "url": url})
    return out


def download_version(url: str, dest_xpi: str | Path) -> Path:
    """Download one signed .xpi to *dest_xpi*."""
    dest_xpi = Path(dest_xpi)
    dest_xpi.parent.mkdir(parents=True, exist_ok=True)
    dest_xpi.write_bytes(_get(url))
    return dest_xpi


def amo_consecutive_pairs(slug: str, dest: str | Path, n_pairs: int = 1) -> list[dict]:
    """Download the *n_pairs* most recent consecutive version pairs of *slug*, unpacked.

    Layout: <dest>/<v1>__<v2>/{v1/, v2/}. Returns a summary per pair. Benign by construction.
    """
    dest = Path(dest)
    versions = amo_versions(slug, page_size=max(5, n_pairs + 1))
    pairs = []
    for i in range(min(n_pairs, len(versions) - 1)):
        newer, older = versions[i], versions[i + 1]     # results are newest-first
        pair_dir = dest / f"{older['version']}__{newer['version']}"
        try:
            x1 = download_version(older["url"], pair_dir / "v1.xpi")
            x2 = download_version(newer["url"], pair_dir / "v2.xpi")
            i1 = unpack_extension(x1, pair_dir / "v1")
            i2 = unpack_extension(x2, pair_dir / "v2")
            pairs.append({
                "slug": slug, "source": "amo",
                "v1": older["version"], "v2": newer["version"],
                "v1_dir": str(pair_dir / "v1"), "v2_dir": str(pair_dir / "v2"),
                "mv": i2["manifest"].get("manifest_version"),
                "name": i2["manifest"].get("name"),
            })
        except Exception as exc:  # a bad/withdrawn file: skip the pair, keep going
            pairs.append({"slug": slug, "error": str(exc)[:120],
                          "v1": older["version"], "v2": newer["version"]})
    return pairs
