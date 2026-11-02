"""Synthetic marker detection and redaction. Runs without a browser or Docker."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import unittest
import urllib.parse

from engine.sandbox.markers import MARKERS, assert_no_marker_values, redact, scan

PASSWORD = "XDRFT-Bank-Pw-7f3a91c2"


def found(data, location="body"):
    return {hit.marker_id for hit in scan(data, location)}


class TestScan(unittest.TestCase):
    def test_every_marker_is_found_in_plain_text(self):
        for marker in MARKERS:
            with self.subTest(marker=marker.id):
                self.assertIn(marker.id, found(f"prefix {marker.value} suffix"))

    def test_common_encodings_are_recognised(self):
        raw = PASSWORD.encode()
        cases = {
            "url": urllib.parse.quote(PASSWORD, safe=""),
            "base64": base64.b64encode(raw).decode(),
            "hex": raw.hex(),
            "reversed": PASSWORD[::-1],
            "sha256": hashlib.sha256(raw).hexdigest(),
            "md5": hashlib.md5(raw).hexdigest(),
        }
        for name, encoded in cases.items():
            with self.subTest(encoding=name):
                self.assertIn("bank_password", found(encoded))

    def test_marker_inside_a_base64_json_blob_at_any_offset(self):
        for padding in ("", "a", "ab", "abc"):
            blob = base64.b64encode(json.dumps({padding or "k": PASSWORD}).encode()).decode()
            with self.subTest(padding=padding):
                self.assertIn("bank_password", found(blob))

    def test_gzip_body_is_decoded(self):
        self.assertIn("bank_password", found(gzip.compress(json.dumps({"p": PASSWORD}).encode())))

    def test_unrelated_text_has_no_hits(self):
        for text in ("hello world", '{"theme":"sepia"}', "tick", "x" * 5000):
            with self.subTest(text=text[:10]):
                self.assertEqual(found(text), set())

    def test_spaced_and_unspaced_card_are_one_finding(self):
        hits = found("card=4111 1111 1111 1111")
        self.assertIn("card_number_spaced", hits)
        self.assertNotIn("card_number", hits)


class TestRedaction(unittest.TestCase):
    def test_value_is_replaced_by_its_identifier(self):
        url = f"https://x.test/c?p={PASSWORD}&q=1"
        out = redact(url)
        self.assertNotIn(PASSWORD, out)
        self.assertIn("[MARKER:bank_password:plain]", out)
        self.assertIn("q=1", out)

    def test_encoded_values_are_also_scrubbed(self):
        encoded = base64.b64encode(PASSWORD.encode()).decode()
        self.assertNotIn(encoded.rstrip("="), redact(f"token={encoded}"))

    def test_safety_net_rejects_a_raw_value(self):
        with self.assertRaises(ValueError):
            assert_no_marker_values(f"oops {PASSWORD}")
        assert_no_marker_values(redact(f"fine {PASSWORD}"))


if __name__ == "__main__":
    unittest.main()
