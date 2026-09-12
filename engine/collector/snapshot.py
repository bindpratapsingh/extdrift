"""Snapshot currently-installed Chrome/Chromium extensions off disk.

Chrome stores extensions unpacked at
    <profile>/Extensions/<id>/<version>/
so a snapshot is just a copy. Run it now to grab the current versions; run it again after
Chrome auto-updates and you have a real N -> N+1 benign pair — exactly how the tool would
operate in deployment. Offline; needs no network.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def default_extensions_root() -> Path | None:
    """Best-effort path to the default profile's Extensions directory, per OS."""
    home = Path.home()
    candidates = [
        home / "AppData/Local/Google/Chrome/User Data/Default/Extensions",      # Windows
        home / "Library/Application Support/Google/Chrome/Default/Extensions",   # macOS
        home / ".config/google-chrome/Default/Extensions",                       # Linux
        home / ".config/chromium/Default/Extensions",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def list_installed(extensions_root: str | Path | None = None) -> list[dict]:
    """List installed extensions and their on-disk versions."""
    root = Path(extensions_root) if extensions_root else default_extensions_root()
    if not root or not root.exists():
        return []
    out = []
    for ext_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        versions = sorted(v.name for v in ext_dir.iterdir()
                          if v.is_dir() and (v / "manifest.json").exists())
        if versions:
            out.append({"ext_id": ext_dir.name, "versions": versions})
    return out


def snapshot_installed(dest: str | Path, ids: list[str] | None = None,
                       extensions_root: str | Path | None = None) -> list[dict]:
    """Copy the current version of each watched extension into *dest*.

    Layout: <dest>/<ext_id>/<version>/... . Copying the same extension on a later run,
    after Chrome updates it, gives a v1/v2 pair for that id.
    """
    root = Path(extensions_root) if extensions_root else default_extensions_root()
    dest = Path(dest)
    if not root or not root.exists():
        raise FileNotFoundError("could not locate a Chrome Extensions directory; "
                                "pass extensions_root explicitly")
    saved = []
    for entry in list_installed(root):
        if ids and entry["ext_id"] not in ids:
            continue
        for version in entry["versions"]:
            src = root / entry["ext_id"] / version
            target = dest / entry["ext_id"] / version
            if target.exists():
                continue
            shutil.copytree(src, target)
            saved.append({"ext_id": entry["ext_id"], "version": version,
                          "path": str(target)})
    return saved
