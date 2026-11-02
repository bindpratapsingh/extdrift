"""Package the corpus versions into .zip files, the way a store ships an update.

    python demo/package_samples.py

Writes demo/extensions/reader-lite-<version>.zip plus a SHA256SUMS.txt, so the demo
server (and a person at a file dialog) has real, uploadable packages rather than
directories. Re-run after editing anything under data/corpus/readerlite/.
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "data" / "corpus" / "readerlite"
DEST = ROOT / "demo" / "extensions"

# A fixed timestamp keeps the archives byte-identical across rebuilds, so the checksums
# below are stable and a changed sample is visible in the diff.
FIXED_DATE = (2026, 1, 1, 0, 0, 0)


def package(version_dir: Path, out_path: Path) -> str:
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(version_dir.rglob("*")):
            if not path.is_file():
                continue
            info = zipfile.ZipInfo(str(path.relative_to(version_dir)).replace("\\", "/"),
                                   date_time=FIXED_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes())
    return hashlib.sha256(out_path.read_bytes()).hexdigest()


def main() -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    lines = []
    for version_dir in sorted(p for p in SOURCE.iterdir() if p.is_dir()):
        out_path = DEST / f"reader-lite-{version_dir.name}.zip"
        digest = package(version_dir, out_path)
        size = out_path.stat().st_size
        print(f"{out_path.relative_to(ROOT)}  {size:,} bytes  sha256 {digest[:16]}...")
        lines.append(f"{digest}  {out_path.name}")
    (DEST / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
