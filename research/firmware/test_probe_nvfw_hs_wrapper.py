"""Independent bounded tests for the Linux-reference wrapper *candidate* probe."""
import importlib.util
import pathlib
import struct
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "probe_nvfw_hs_wrapper.py"
spec = importlib.util.spec_from_file_location("probe_nvfw_hs_wrapper", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def reference_sample(num_sigs=2, firmware=b"image" * 1024):
    sig_len = 384 * num_sigs
    fw_off = 120 + sig_len
    total = (fw_off + len(firmware) + 255) // 256 * 256
    outer = struct.pack("<6I", 0x10de, 1, total, 24, fw_off, len(firmware))
    hs = struct.pack("<9I", 60, sig_len, 60 + sig_len, 64 + sig_len,
                     68 + sig_len, 12, 80 + sig_len, 84 + sig_len, 36)
    sig = b"S" * sig_len
    patch = struct.pack("<6I", 80, 0, 1, 2, 3, num_sigs)
    desc = struct.pack("<9I", 0, 32, 32, 16, 1, 32, 16, 48, 16)
    return outer + hs + sig + patch + desc + firmware


class ReferenceProbeTests(unittest.TestCase):
    def test_canonical_candidate_with_prefix(self):
        body = reference_sample()
        report = probe.scan_bytes(b"noise\x00" + body + b"trailer")
        self.assertEqual(report["status"], "COMPLETE")
        self.assertEqual(report["candidate_count"], 1)
        hit = report["candidates"][0]
        self.assertEqual(hit["file_offset"], 6)
        self.assertEqual(hit["signature_count"], 2)
        self.assertEqual(hit["image_file_offset"], 6 + 120 + 768)
        self.assertFalse(hit["windows_producer_proven"])
        self.assertFalse(hit["signature_verified"])

    def test_marker_alone_is_not_evidence(self):
        self.assertEqual(probe.scan_bytes(b"N" * 40 + probe.MAGIC_VERSION + b"\x00" * 100)["candidate_count"], 0)

    def test_rejects_mismatched_descriptor_and_count(self):
        body = bytearray(reference_sample())
        struct.pack_into("<I", body, 24 + 20, 8)  # corrupt metadata length
        self.assertIsNone(probe.parse_reference_wrapper(body, 0))
        body = bytearray(reference_sample())
        struct.pack_into("<I", body, 60 + 768 + 20, 3)  # num_sigs != 2
        self.assertIsNone(probe.parse_reference_wrapper(body, 0))

    def test_rejects_wrong_signature_placeholder_and_layout(self):
        body = bytearray(reference_sample())
        struct.pack_into("<I", body, 60 + 768 + 4, 1)
        self.assertIsNone(probe.parse_reference_wrapper(body, 0))
        body = bytearray(reference_sample())
        struct.pack_into("<I", body, 24 + 28, 99)  # corrupt load-header position
        self.assertIsNone(probe.parse_reference_wrapper(body, 0))

    def test_truncated_scan_does_not_claim_complete(self):
        body = reference_sample()
        report = probe.scan_bytes(body + body, max_matches=1)
        self.assertEqual(report["candidate_count"], 1)
        self.assertEqual(report["status"], "PARTIAL")
        self.assertTrue(report["truncated"])

    def test_unpinned_input_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / "nvlddmkm.sys"
            p.write_bytes(reference_sample())
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                probe.scan_file(p)

    def test_no_match_is_not_absence(self):
        report = probe.scan_bytes(b"\x00" * 2048)
        self.assertEqual(report["status"], "COMPLETE")
        self.assertEqual(report["candidate_count"], 0)
        self.assertTrue(report["no_match_does_not_prove_absence"])


if __name__ == "__main__":
    unittest.main()
