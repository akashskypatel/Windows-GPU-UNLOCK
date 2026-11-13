"""Independent host checks for the bounded, read-only original MSI PciBus trace.

Synthetic reference edges test the actual caller filter. These checks do not
claim to execute Ghidra or any original firmware image.
"""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("msi_b850_pcibus_load_origin.py")
SPEC = importlib.util.spec_from_file_location("msi_pcibus_load_origin", SCRIPT)
trace = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trace)


class Address:
    def __init__(self, number):
        self.number = number

    def getOffset(self):
        return self.number


class RefType:
    def __init__(self, is_call):
        self.call = is_call

    def isCall(self):
        return self.call


class Ref:
    def __init__(self, number, call):
        self.from_addr = Address(number)
        self.kind = RefType(call)

    def getReferenceType(self):
        return self.kind

    def getFromAddress(self):
        return self.from_addr


class Program:
    def __init__(self, edges):
        self.edges = edges
        self.target = None

    def getReferenceManager(self):
        return self

    def getReferencesTo(self, target):
        self.target = target
        return self.edges


class TraceInputTests(unittest.TestCase):
    def test_original_binary_hashes_are_computed_from_same_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "original.efi"
            data = b"MZ" + bytes(range(256)) + b"\x00EFI"
            path.write_bytes(data)
            digest, md5 = trace.source_hash(path)
            self.assertEqual(digest, hashlib.sha256(data).hexdigest())
            self.assertEqual(md5, hashlib.md5(data).hexdigest())
            path.write_bytes(data + b"changed")
            self.assertNotEqual(trace.source_hash(path), (digest, md5))

    def test_missing_original_image_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                trace.source_hash(Path(folder) / "absent.efi")

    def test_oversized_image_fails_without_reading_it(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "oversized.efi"
            with path.open("wb") as f:
                f.seek(trace.MAX_SOURCE_BYTES)
                f.write(b"X")
            with self.assertRaises(ValueError):
                trace.source_hash(path)

    def test_callsite_enumerator_filters_noncall_refs_and_deduplicates(self):
        p = Program([
            Ref(0x9002, False),
            Ref(0x9008, True),
            Ref(0x9008, True),
            Ref(0x9004, True),
            Ref(0x9001, False),
        ])
        target = Address(trace.LOADER)
        results = trace.direct_callers(p, target)
        self.assertIs(p.target, target)
        self.assertEqual([int(r.getOffset()) for r in results],
                         [0x9004, 0x9008])

    def test_no_direct_calls_does_not_invent_any(self):
        p = Program([Ref(0x1234, False)])
        self.assertEqual(trace.direct_callers(p, Address(trace.LOADER)), [])


if __name__ == "__main__":
    unittest.main()
