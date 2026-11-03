"""Package the corpus versions the way a store ships them.

    python demo/package_samples.py

Writes, for each version under data/corpus/readerlite/:

  demo/extensions/reader-lite-<version>.crx   a signed CRX3 - what Chrome actually ships
  demo/extensions/reader-lite-<version>.zip   the same archive unsigned

All versions are signed with one key, so all of them carry the **same extension id**.
That is the point: a browser knows an update is an update to the extension you already
trust because the id matches, and the id is derived from the signing key. A corpus of
update pairs that did not share an id would not be a corpus of updates.

The key lives at demo/extensions/demo-signing-key.pem and is **not committed** - a
private key does not belong in a repository even when it signs nothing but synthetic test
extensions. If it is missing, this script makes a new one and prints the new extension id;
the committed .crx files will then no longer match, so re-commit them if you regenerate.
"""

from __future__ import annotations

import hashlib
import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.unpack.crx import unpack_extension, write_crx3  # noqa: E402

SOURCE = ROOT / "data" / "corpus" / "readerlite"
DEST = ROOT / "demo" / "extensions"
KEY_PATH = DEST / "demo-signing-key.pem"

# A fixed timestamp keeps the archives byte-identical across rebuilds, so a changed sample
# shows up in the diff and the checksums below mean something.
FIXED_DATE = (2026, 1, 1, 0, 0, 0)


def load_or_create_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    if KEY_PATH.exists():
        return serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None), False
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    KEY_PATH.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    return key, True


def zip_bytes(version_dir: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(version_dir.rglob("*")):
            if not path.is_file():
                continue
            info = zipfile.ZipInfo(str(path.relative_to(version_dir)).replace("\\", "/"),
                                   date_time=FIXED_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes())
    return buf.getvalue()


def main() -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    key, created = load_or_create_key()
    if created:
        print("made a new signing key at %s" % KEY_PATH.relative_to(ROOT))
        print("the extension id below is new; re-commit the .crx files\n")

    lines, extension_id = [], None
    for version_dir in sorted(p for p in SOURCE.iterdir() if p.is_dir()):
        payload = zip_bytes(version_dir)

        zip_path = DEST / ("reader-lite-%s.zip" % version_dir.name)
        zip_path.write_bytes(payload)

        crx_path = DEST / ("reader-lite-%s.crx" % version_dir.name)
        info = write_crx3(payload, key, crx_path)
        extension_id = info["extension_id"]

        print("%-28s %6d bytes   crx3, id %s" % (crx_path.name, info["bytes"], extension_id))
        for path in (crx_path, zip_path):
            lines.append("%s  %s" % (hashlib.sha256(path.read_bytes()).hexdigest(), path.name))

    (DEST / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Prove the packages we just wrote are readable by the analyser, rather than assuming it.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        for path in sorted(DEST.glob("*.crx")):
            result = unpack_extension(path, Path(tmp) / path.stem)
            assert result["extension_id"] == extension_id, path
    print("\nall .crx packages unpack, and all share extension id %s" % extension_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
