"""Unpacking extension packages: .crx (Chromium), .xpi (Firefox), .zip, or a directory.

A ``.crx`` is a ZIP archive behind a signature header, and a ``.xpi`` is a plain ZIP.
Both therefore reduce to "strip the header, then unzip safely" - the interesting parts
are the two CRX header formats and the fact that we are unzipping untrusted archives.

Security note
-------------
These archives are hostile input by definition: the whole project exists because some
of them are malicious.  :func:`safe_extract` refuses absolute paths, parent-directory
traversal (Zip Slip), and symlink entries, so unpacking a crafted package cannot write
outside the destination directory.  This runs *before* the sandbox does, on the host,
which is exactly why it has to be careful.
"""

from __future__ import annotations

import hashlib
import json
import struct
import zipfile
from pathlib import Path

CRX_MAGIC = b"Cr24"

#: Limits on what unpacking an untrusted archive may produce.
MAX_ARCHIVE_FILES = 20000
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024

#: Field number of ``signed_header_data`` in the CRX3 ``CrxFileHeader`` protobuf.
_CRX3_SIGNED_HEADER_FIELD = 10000
#: Field number of ``crx_id`` inside ``SignedData``.
_CRX3_CRX_ID_FIELD = 1


class CrxError(ValueError):
    """Raised when a package cannot be parsed or is unsafe to extract."""


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Read one protobuf base-128 varint; return (value, new_position)."""
    result = shift = 0
    while True:
        if pos >= len(data):
            raise CrxError("truncated varint in CRX3 header")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise CrxError("oversized varint in CRX3 header")


def _protobuf_fields(data: bytes):
    """Yield ``(field_number, payload)`` for every length-delimited field in *data*.

    A deliberately minimal protobuf reader: we only need to reach two known fields, so
    pulling in a protobuf dependency to parse 16 bytes of extension ID is not worth it.
    Non-length-delimited fields are skipped rather than decoded.
    """
    pos = 0
    while pos < len(data):
        key, pos = _read_varint(data, pos)
        field_number, wire_type = key >> 3, key & 0x07
        if wire_type == 0:
            _, pos = _read_varint(data, pos)
        elif wire_type == 2:
            length, pos = _read_varint(data, pos)
            if pos + length > len(data):
                raise CrxError("length-delimited field runs past end of CRX3 header")
            yield field_number, data[pos:pos + length]
            pos += length
        elif wire_type == 5:
            pos += 4
        elif wire_type == 1:
            pos += 8
        else:
            raise CrxError(f"unsupported protobuf wire type {wire_type} in CRX3 header")


def crx_id_from_key(public_key: bytes) -> str:
    """Derive the 32-character extension ID from a DER public key.

    Chromium takes the first 16 bytes of SHA-256(public key) and re-encodes each hex
    nibble into the alphabet a-p, which is why extension IDs look like lowercase
    gibberish with no digits.
    """
    digest = hashlib.sha256(public_key).digest()[:16]
    return crx_id_from_bytes(digest)


def crx_id_from_bytes(raw_id: bytes) -> str:
    """Encode a 16-byte CRX id into Chromium's a-p alphabet."""
    if len(raw_id) != 16:
        raise CrxError(f"CRX id must be 16 bytes, got {len(raw_id)}")
    return "".join(chr(ord("a") + (byte >> 4)) + chr(ord("a") + (byte & 0x0F))
                   for byte in raw_id)


def read_crx_header(data: bytes) -> dict:
    """Parse the CRX header and return metadata plus the offset of the ZIP payload.

    Handles CRX2 (magic, version, key length, signature length) and CRX3 (magic,
    version, header length, protobuf header).  Anything else is rejected loudly.
    """
    if data[:4] != CRX_MAGIC:
        raise CrxError("not a CRX file (missing 'Cr24' magic)")
    if len(data) < 12:
        raise CrxError("CRX file is truncated: header runs past end of file")

    version = struct.unpack("<I", data[4:8])[0]

    if version == 2:
        if len(data) < 16:
            raise CrxError("CRX2 header is truncated: runs past end of file")
        key_len, sig_len = struct.unpack("<II", data[8:16])
        offset = 16 + key_len + sig_len
        if offset > len(data):
            raise CrxError("CRX2 header declares a payload offset past end of file")
        public_key = data[16:16 + key_len]
        return {
            "crx_version": 2,
            "zip_offset": offset,
            "extension_id": crx_id_from_key(public_key) if public_key else None,
        }

    if version == 3:
        header_len = struct.unpack("<I", data[8:12])[0]
        offset = 12 + header_len
        if offset > len(data):
            raise CrxError("CRX3 header declares a payload offset past end of file")
        extension_id = None
        for field_number, payload in _protobuf_fields(data[12:offset]):
            if field_number == _CRX3_SIGNED_HEADER_FIELD:
                for inner_field, inner_payload in _protobuf_fields(payload):
                    if inner_field == _CRX3_CRX_ID_FIELD and len(inner_payload) == 16:
                        extension_id = crx_id_from_bytes(inner_payload)
                break
        return {"crx_version": 3, "zip_offset": offset, "extension_id": extension_id}

    raise CrxError(f"unsupported CRX format version {version}")


def safe_extract(archive: zipfile.ZipFile, dest: Path, *, max_files: int = MAX_ARCHIVE_FILES,
                 max_total_bytes: int = MAX_ARCHIVE_BYTES) -> int:
    """Extract *archive* into *dest*, refusing any entry that escapes it.

    Returns the number of files written.  Rejects absolute paths, ``..`` traversal and
    symlinks - the three ways a crafted archive tries to write outside its directory - and
    stops at a size and file-count ceiling, because a zip bomb is a denial of service against
    the host that unpacks it.
    """
    dest = dest.resolve()
    written = 0
    total_bytes = 0
    if len(archive.infolist()) > max_files:
        raise CrxError(f"archive has more than {max_files} entries")
    for info in archive.infolist():
        name = info.filename
        if name.endswith("/"):
            continue
        if name.startswith("/") or name.startswith("\\") or ".." in Path(name).parts:
            raise CrxError(f"unsafe archive entry (path traversal): {name!r}")
        # Unix mode is in the top 16 bits of external_attr; 0xA000 marks a symlink.
        if (info.external_attr >> 16) & 0xF000 == 0xA000:
            raise CrxError(f"unsafe archive entry (symlink): {name!r}")

        target = (dest / name).resolve()
        if not str(target).startswith(str(dest)):
            raise CrxError(f"unsafe archive entry (escapes destination): {name!r}")

        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(info) as source, target.open("wb") as handle:
            # The size in the archive header can lie, so the limit applies to bytes really read.
            while chunk := source.read(1024 * 1024):
                total_bytes += len(chunk)
                if total_bytes > max_total_bytes:
                    raise CrxError(f"archive expands past the {max_total_bytes} byte limit")
                handle.write(chunk)
        written += 1
    return written


def unpack_extension(package: str | Path, dest: str | Path) -> dict:
    """Unpack *package* into *dest* and return a summary including its manifest.

    *package* may be a ``.crx``, a ``.xpi``/``.zip``, or an already-unpacked directory
    (which is what Chrome leaves on disk, and therefore the easiest way to grab the
    version a machine is currently running).
    """
    package, dest = Path(package), Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    if package.is_dir():
        manifest_path = package / "manifest.json"
        if not manifest_path.exists():
            raise CrxError(f"{package} is a directory but has no manifest.json")
        return {
            "source": str(package),
            "format": "directory",
            "crx_version": None,
            "extension_id": None,
            "unpacked_to": str(package),
            "file_count": sum(1 for p in package.rglob("*") if p.is_file()),
            "manifest": json.loads(manifest_path.read_text(encoding="utf-8")),
        }

    data = package.read_bytes()
    if data[:4] == CRX_MAGIC:
        header = read_crx_header(data)
        payload = data[header["zip_offset"]:]
        fmt = f"crx{header['crx_version']}"
    else:
        header = {"crx_version": None, "extension_id": None}
        payload = data
        fmt = "zip"

    import io

    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            count = safe_extract(archive, dest)
    except zipfile.BadZipFile as exc:
        raise CrxError(f"{package}: payload is not a valid ZIP archive ({exc})")

    manifest_path = dest / "manifest.json"
    if not manifest_path.exists():
        raise CrxError(f"{package}: archive contains no manifest.json")

    return {
        "source": str(package),
        "format": fmt,
        "crx_version": header["crx_version"],
        "extension_id": header["extension_id"],
        "unpacked_to": str(dest),
        "file_count": count,
        "manifest": json.loads(manifest_path.read_text(encoding="utf-8")),
    }


# ---------------------------------------------------------------------------------
# Writing CRX3
#
# Reading a package is what the analysis needs; writing one is what the corpus needs.
# A .zip of an extension directory is not what a browser ships - Chrome ships a signed
# CRX3, whose header carries the public key and from which the extension ID is derived.
# Because the ID comes from the signing key, two versions signed with the same key share
# an ID, which is exactly what makes the second one an *update* to the first rather than
# a different extension. Our corpus pairs should carry that property, so we can produce it.
# ---------------------------------------------------------------------------------

#: Field numbers in CrxFileHeader (chrome/browser/.../crx3.proto).
_CRX3_SHA256_WITH_RSA_FIELD = 2
#: Field numbers in AsymmetricKeyProof.
_CRX3_PUBLIC_KEY_FIELD = 1
_CRX3_SIGNATURE_FIELD = 2
#: Prefix Chromium signs over, so a CRX signature cannot be replayed in another context.
_CRX3_SIGNATURE_CONTEXT = b"CRX3 SignedData\x00"


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _field(field_number: int, payload: bytes) -> bytes:
    """Encode one length-delimited (wire type 2) protobuf field."""
    return _varint((field_number << 3) | 2) + _varint(len(payload)) + payload


def write_crx3(zip_bytes: bytes, private_key, out_path: str | Path) -> dict:
    """Sign *zip_bytes* and write a CRX3 package, the format Chrome actually ships.

    *private_key* is a ``cryptography`` RSA private key. Returns the extension id and the
    byte size, and the result is readable by :func:`read_crx_header` and
    :func:`unpack_extension` - which is the round trip the tests check.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    crx_id = hashlib.sha256(public_der).digest()[:16]
    signed_header = _field(_CRX3_CRX_ID_FIELD, crx_id)

    # Chromium signs the context string, the signed-header length and the header itself,
    # then the archive. Signing the length is what stops a header field being moved into
    # the archive without invalidating the signature.
    to_sign = (_CRX3_SIGNATURE_CONTEXT
               + struct.pack("<I", len(signed_header))
               + signed_header
               + zip_bytes)
    signature = private_key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())

    proof = _field(_CRX3_PUBLIC_KEY_FIELD, public_der) + _field(_CRX3_SIGNATURE_FIELD, signature)
    header = (_field(_CRX3_SHA256_WITH_RSA_FIELD, proof)
              + _field(_CRX3_SIGNED_HEADER_FIELD, signed_header))

    blob = (CRX_MAGIC + struct.pack("<I", 3) + struct.pack("<I", len(header))
            + header + zip_bytes)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(blob)
    return {"extension_id": crx_id_from_bytes(crx_id), "bytes": len(blob)}
