"""The CRX3 writer: does what we produce round-trip, and is the signature real?

Writing packages matters for the corpus, not just the demo. Two versions are versions of
one extension only if they carry the same extension id, and the id comes from the signing
key, so a pair built with one key is an update pair in the sense a browser means it.
"""

from __future__ import annotations

import io
import json
import struct
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from engine.unpack.crx import (CRX_MAGIC, CrxError, crx_id_from_key, read_crx_header,
                               unpack_extension, write_crx3)

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    HAVE_CRYPTO = True
except ImportError:  # the writer is optional; the reader is not
    HAVE_CRYPTO = False


def make_zip(name: str = "Sample", version: str = "1.0.0") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("manifest.json", json.dumps(
            {"manifest_version": 3, "name": name, "version": version}))
        archive.writestr("content.js", "// nothing\n")
    return buf.getvalue()


@unittest.skipUnless(HAVE_CRYPTO, "cryptography is not installed")
class TestWriteCrx3(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def test_round_trips_through_the_reader(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.crx"
            written = write_crx3(make_zip(), self.key, path)

            self.assertEqual(path.read_bytes()[:4], CRX_MAGIC)
            header = read_crx_header(path.read_bytes())
            self.assertEqual(header["crx_version"], 3)
            self.assertEqual(header["extension_id"], written["extension_id"])

            unpacked = unpack_extension(path, Path(tmp) / "out")
            self.assertEqual(unpacked["format"], "crx3")
            self.assertEqual(unpacked["extension_id"], written["extension_id"])
            self.assertEqual(unpacked["manifest"]["name"], "Sample")

    def test_extension_id_comes_from_the_key_not_the_contents(self):
        """Same key, different payload -> same id. That is what makes a pair an update."""
        with TemporaryDirectory() as tmp:
            v1 = write_crx3(make_zip(version="1.0.0"), self.key, Path(tmp) / "v1.crx")
            v2 = write_crx3(make_zip(version="2.0.0"), self.key, Path(tmp) / "v2.crx")
            self.assertEqual(v1["extension_id"], v2["extension_id"])

            other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            other = write_crx3(make_zip(), other_key, Path(tmp) / "other.crx")
            self.assertNotEqual(other["extension_id"], v1["extension_id"])

    def test_the_id_matches_chromiums_derivation_from_the_public_key(self):
        with TemporaryDirectory() as tmp:
            written = write_crx3(make_zip(), self.key, Path(tmp) / "sample.crx")
            public_der = self.key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            self.assertEqual(written["extension_id"], crx_id_from_key(public_der))

    def test_the_signature_verifies_over_header_and_archive(self):
        """Not just structurally valid - actually signed, the way Chromium checks it."""
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.crx"
            payload = make_zip()
            write_crx3(payload, self.key, path)
            blob = path.read_bytes()

            header_len = struct.unpack("<I", blob[8:12])[0]
            header = blob[12:12 + header_len]
            archive = blob[12 + header_len:]
            self.assertEqual(archive, payload)

            # Pull the proof and the signed header back out of the protobuf header.
            from engine.unpack.crx import _protobuf_fields
            signature = public_key = signed_header = None
            for field, body in _protobuf_fields(header):
                if field == 2:
                    for inner, value in _protobuf_fields(body):
                        if inner == 1:
                            public_key = value
                        elif inner == 2:
                            signature = value
                elif field == 10000:
                    signed_header = body
            self.assertIsNotNone(signature)
            self.assertIsNotNone(signed_header)

            to_sign = (b"CRX3 SignedData\x00"
                       + struct.pack("<I", len(signed_header)) + signed_header + archive)
            loaded = serialization.load_der_public_key(public_key)
            loaded.verify(signature, to_sign, padding.PKCS1v15(), hashes.SHA256())

    def test_a_tampered_archive_breaks_the_signature(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.crx"
            write_crx3(make_zip(), self.key, path)
            blob = bytearray(path.read_bytes())
            blob[-1] ^= 0xFF                       # flip a bit in the archive
            header_len = struct.unpack("<I", bytes(blob[8:12]))[0]
            header, archive = bytes(blob[12:12 + header_len]), bytes(blob[12 + header_len:])

            from cryptography.exceptions import InvalidSignature
            from engine.unpack.crx import _protobuf_fields
            signature = public_key = signed_header = None
            for field, body in _protobuf_fields(header):
                if field == 2:
                    for inner, value in _protobuf_fields(body):
                        if inner == 1:
                            public_key = value
                        elif inner == 2:
                            signature = value
                elif field == 10000:
                    signed_header = body
            to_sign = (b"CRX3 SignedData\x00"
                       + struct.pack("<I", len(signed_header)) + signed_header + archive)
            with self.assertRaises(InvalidSignature):
                serialization.load_der_public_key(public_key).verify(
                    signature, to_sign, padding.PKCS1v15(), hashes.SHA256())


class TestBundledSamples(unittest.TestCase):
    """The packages the demo ships must be readable and must be one extension."""

    SAMPLES = Path(__file__).resolve().parent.parent / "demo" / "extensions"

    def test_every_bundled_crx_unpacks_and_shares_one_extension_id(self):
        packages = sorted(self.SAMPLES.glob("*.crx"))
        if not packages:
            self.skipTest("no sample packages built (run demo/package_samples.py)")
        ids, versions = set(), set()
        with TemporaryDirectory() as tmp:
            for path in packages:
                result = unpack_extension(path, Path(tmp) / path.stem)
                ids.add(result["extension_id"])
                versions.add(result["manifest"]["version"])
                self.assertEqual(result["format"], "crx3")
        self.assertEqual(len(ids), 1, "samples must be one extension, got ids %s" % ids)
        self.assertGreater(len(versions), 1, "samples must be several versions")

    def test_a_truncated_package_is_refused_rather_than_half_read(self):
        packages = sorted(self.SAMPLES.glob("*.crx"))
        if not packages:
            self.skipTest("no sample packages built")
        with TemporaryDirectory() as tmp:
            truncated = Path(tmp) / "short.crx"
            truncated.write_bytes(packages[0].read_bytes()[:8])
            with self.assertRaises(CrxError):
                unpack_extension(truncated, Path(tmp) / "out")


if __name__ == "__main__":
    unittest.main()
