"""Tests for package unpacking and the static manifest diff.

The CRX fixtures are built in memory rather than committed, so the suite never ships a
binary blob and never needs a real extension downloaded to run.
"""

from __future__ import annotations

import io
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from engine.unpack.crx import (
    CRX_MAGIC,
    CrxError,
    crx_id_from_bytes,
    crx_id_from_key,
    read_crx_header,
    unpack_extension,
)
from engine.unpack.manifest import diff_manifests, normalise_manifest, summarise_manifest_diff

MANIFEST_V1 = {
    "manifest_version": 3,
    "name": "Fixture Extension",
    "version": "1.0.0",
    "permissions": ["storage", "activeTab"],
    "host_permissions": ["https://example.test/*"],
    "background": {"service_worker": "sw.js"},
}

MANIFEST_V2 = {
    "manifest_version": 3,
    "name": "Fixture Extension",
    "version": "1.1.0",
    "permissions": ["storage", "activeTab", "cookies", "scripting"],
    "host_permissions": ["<all_urls>"],
    "background": {"service_worker": "sw.js"},
    "content_scripts": [{"matches": ["<all_urls>"], "js": ["cs.js"]}],
}


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _pb_bytes_field(field_number: int, payload: bytes) -> bytes:
    """Encode one length-delimited protobuf field."""
    return _varint((field_number << 3) | 2) + _varint(len(payload)) + payload


def build_zip(manifest: dict, extra: dict[str, bytes] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for name, content in (extra or {}).items():
            archive.writestr(name, content)
    return buffer.getvalue()


def build_crx3(manifest: dict, crx_id: bytes = b"\x01\x23\x45\x67" * 4) -> bytes:
    signed_data = _pb_bytes_field(1, crx_id)          # SignedData.crx_id
    header = _pb_bytes_field(10000, signed_data)      # CrxFileHeader.signed_header_data
    return (CRX_MAGIC + struct.pack("<II", 3, len(header)) + header + build_zip(manifest))


def build_crx2(manifest: dict, public_key: bytes = b"PUBKEY", signature: bytes = b"SIG") -> bytes:
    return (CRX_MAGIC + struct.pack("<III", 2, len(public_key), len(signature))
            + public_key + signature + build_zip(manifest))


class TestCrxHeader(unittest.TestCase):
    def test_crx3_header_yields_extension_id(self):
        header = read_crx_header(build_crx3(MANIFEST_V1))
        self.assertEqual(header["crx_version"], 3)
        self.assertEqual(header["extension_id"], crx_id_from_bytes(b"\x01\x23\x45\x67" * 4))

    def test_crx2_header_derives_id_from_public_key(self):
        header = read_crx_header(build_crx2(MANIFEST_V1))
        self.assertEqual(header["crx_version"], 2)
        self.assertEqual(header["extension_id"], crx_id_from_key(b"PUBKEY"))

    def test_extension_ids_use_the_a_to_p_alphabet(self):
        ext_id = crx_id_from_key(b"anything")
        self.assertEqual(len(ext_id), 32)
        self.assertTrue(all("a" <= ch <= "p" for ch in ext_id))

    def test_non_crx_input_is_rejected(self):
        with self.assertRaises(CrxError):
            read_crx_header(b"PK\x03\x04 this is a plain zip, not a crx")

    def test_unsupported_crx_version_is_rejected(self):
        blob = CRX_MAGIC + struct.pack("<III", 9, 0, 0)
        with self.assertRaisesRegex(CrxError, "unsupported CRX format version"):
            read_crx_header(blob)

    def test_truncated_header_is_rejected(self):
        blob = CRX_MAGIC + struct.pack("<II", 3, 4096)  # claims a header it does not have
        with self.assertRaisesRegex(CrxError, "past end of file"):
            read_crx_header(blob)


class TestUnpack(unittest.TestCase):
    def test_unpack_crx3(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp) / "ext.crx"
            package.write_bytes(build_crx3(MANIFEST_V1))
            result = unpack_extension(package, Path(tmp) / "out")
            self.assertEqual(result["format"], "crx3")
            self.assertEqual(result["manifest"]["version"], "1.0.0")
            self.assertTrue((Path(tmp) / "out" / "manifest.json").exists())

    def test_unpack_plain_zip_as_xpi(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp) / "ext.xpi"
            package.write_bytes(build_zip(MANIFEST_V1, {"lib/util.js": b"// noop"}))
            result = unpack_extension(package, Path(tmp) / "out")
            self.assertEqual(result["format"], "zip")
            self.assertEqual(result["file_count"], 2)

    def test_unpack_directory_left_on_disk_by_chrome(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "1.0.0_0"
            source.mkdir()
            (source / "manifest.json").write_text(json.dumps(MANIFEST_V1), encoding="utf-8")
            result = unpack_extension(source, Path(tmp) / "out")
            self.assertEqual(result["format"], "directory")
            self.assertEqual(result["manifest"]["name"], "Fixture Extension")

    def test_archive_without_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp) / "ext.zip"
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("readme.txt", "no manifest here")
            package.write_bytes(buffer.getvalue())
            with self.assertRaisesRegex(CrxError, "no manifest.json"):
                unpack_extension(package, Path(tmp) / "out")

    def test_path_traversal_entry_is_refused(self):
        """A crafted package must not be able to write outside the destination."""
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp) / "evil.zip"
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("manifest.json", json.dumps(MANIFEST_V1))
                archive.writestr("../../pwned.js", "// escaped")
            package.write_bytes(buffer.getvalue())
            with self.assertRaisesRegex(CrxError, "path traversal"):
                unpack_extension(package, Path(tmp) / "out")
            self.assertFalse((Path(tmp).parent / "pwned.js").exists())


class TestManifestDiff(unittest.TestCase):
    def test_mv2_host_patterns_are_normalised_out(self):
        normalised = normalise_manifest({
            "manifest_version": 2,
            "permissions": ["cookies", "https://*/*"],
            "background": {"scripts": ["bg.js"], "persistent": True},
        })
        self.assertEqual(normalised["permissions"], ["cookies"])
        self.assertEqual(normalised["host_permissions"], ["https://*/*"])
        self.assertEqual(normalised["background"], "persistent_page")
        self.assertTrue(normalised["has_broad_host_access"])

    def test_escalation_is_detected(self):
        diff = diff_manifests(MANIFEST_V1, MANIFEST_V2)
        self.assertTrue(diff["escalated_to_broad_host_access"])
        self.assertEqual(diff["high_risk_added"], ["cookies", "scripting"])
        self.assertEqual(diff["added_host_permissions"], ["<all_urls>"])
        self.assertEqual(diff["added_content_script_matches"], ["<all_urls>"])

    def test_permission_risk_bands(self):
        diff = diff_manifests(MANIFEST_V1, MANIFEST_V2)
        bands = {entry["permission"]: entry["risk"] for entry in diff["added_permissions"]}
        self.assertEqual(bands["cookies"], "high")
        self.assertEqual(bands["scripting"], "high")

    def test_identical_manifests_report_no_change(self):
        diff = diff_manifests(MANIFEST_V1, MANIFEST_V1)
        self.assertEqual(diff["added_permissions"], [])
        self.assertIn("No declared-capability change", summarise_manifest_diff(diff)[0])

    def test_summary_is_human_readable(self):
        lines = summarise_manifest_diff(diff_manifests(MANIFEST_V1, MANIFEST_V2))
        self.assertTrue(any("escalated to every site" in line for line in lines))
        self.assertTrue(any("cookies" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
