"""Download extension versions from the network (GitHub tags, Google update endpoint).

These helpers need internet access, so they are kept separate from the offline snapshot
route and are not exercised by the offline test suite. They use only the standard library.

GitHub route
------------
`github_tag_pair(repo, tag_a, tag_b, dest)` downloads the source zip of two tags via
codeload and extracts each. For extensions whose repository root (or a subfolder) contains
a `manifest.json`, the extracted folder is directly analysable; otherwise the extension
must be built first (repo-specific) — this helper fetches, it does not build.

CRX route
---------
`crx_url(ext_id, chrome_version)` builds Google's update-endpoint URL, which returns the
*current* `.crx`; `fetch_crx` downloads it. Historical versions come from third-party
archives (crx4chrome) and are downloaded by direct URL. A `.crx` is unpacked with
engine.unpack.crx.unpack_extension.
"""

from __future__ import annotations

import io
import urllib.request
import zipfile
from pathlib import Path

USER_AGENT = "extdrift-collector/0.1 (academic research; CSD493)"


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed hosts
        return resp.read()


def github_tag_zip_url(repo: str, tag: str) -> str:
    """codeload URL for a tag's source zip. `repo` is 'owner/name'."""
    return f"https://codeload.github.com/{repo}/zip/refs/tags/{tag}"


def download_github_tag(repo: str, tag: str, dest: str | Path) -> Path:
    """Download and extract one tag's source into *dest*; return the extracted root."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    data = _get(github_tag_zip_url(repo, tag))
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall(dest)
    roots = [p for p in dest.iterdir() if p.is_dir()]
    return roots[0] if roots else dest


def github_tag_pair(repo: str, tag_a: str, tag_b: str, dest: str | Path) -> dict:
    """Download two tags of *repo* into <dest>/v1 and <dest>/v2. Needs network."""
    dest = Path(dest)
    v1 = download_github_tag(repo, tag_a, dest / "v1")
    v2 = download_github_tag(repo, tag_b, dest / "v2")
    return {"repo": repo, "v1_dir": str(v1), "v2_dir": str(v2),
            "tags": [tag_a, tag_b], "source": "github"}


def crx_url(ext_id: str, chrome_version: str = "120.0") -> str:
    """Google update-endpoint URL that redirects to the extension's current .crx."""
    return ("https://clients2.google.com/service/update2/crx"
            f"?response=redirect&acceptformat=crx2,crx3&prodversion={chrome_version}"
            f"&x=id%3D{ext_id}%26installsource%3Dondemand%26uc")


def fetch_crx(ext_id: str, dest: str | Path, chrome_version: str = "120.0") -> Path:
    """Download the current .crx for *ext_id* to *dest*. Needs network."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    data = _get(crx_url(ext_id, chrome_version))
    dest.write_bytes(data)
    return dest
