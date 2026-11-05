"""Independent synthetic ELF/NVUCODES read-only parsing and refusal tests."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

MODULE = Path(__file__).with_name('inspect_installed_firmware.py')
spec = importlib.util.spec_from_file_location('nvidia_firmware_inventory', MODULE)
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)


def make_gsp(path: Path):
    names = b'\0.shstrtab\0.fwsignature_ad10x\0'
    hdr = bytearray(64)
    hdr[:16] = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    data = b'\0' * 64 + names + b'\x11\x22\x33\x44'
    shoff = len(data)
    struct.pack_into('<HHIQQQIHHHHHH', hdr, 16, 1, 243, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 3, 1)
    sections = [b'\0'*64,
                fw.ELF_SECTION.pack(1, 3, 0, 0, 64, len(names), 0, 0, 1, 0),
                fw.ELF_SECTION.pack(11, 1, 0, 0, 64 + len(names), 4, 0, 0, 1, 0)]
    path.write_bytes(bytes(hdr) + names + b'\x11\x22\x33\x44' + b''.join(sections))


def make_ucodes(path: Path, *, fingerprint=0x2d38befecdb703a6):
    path.write_bytes(fw.UCODES_HEADER.pack(b'NVUCODES', 1, 1293, fingerprint) + b'\0' * 16)


class FirmwareInventoryTests(unittest.TestCase):
    def test_nvidia_header_decodes_known_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ucodes.bin'
            make_ucodes(path)
            parsed = fw.inspect_ucodes(path)
            self.assertEqual(parsed['declared_bindata_entries'], 1293)
            self.assertEqual(parsed['filename_index_fingerprint'], '0x2d38befecdb703a6')
            self.assertFalse(parsed['records_parsed'])

    def test_minimal_elf_names_and_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'gsp.bin'
            make_gsp(path)
            parsed = fw.inspect_gsp(path)
            self.assertEqual(parsed['format'], 'ELF64_LE_RISCV_ET_REL')
            self.assertEqual(parsed['section_header_count'], 3)
            self.assertEqual(parsed['sections'][2]['name'], '.fwsignature_ad10x')

    def test_truncated_elf_table_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'gsp.bin'
            make_gsp(path)
            path.write_bytes(path.read_bytes()[:-1])
            with self.assertRaises(ValueError):
                fw.inspect_gsp(path)

    def test_out_of_bounds_section_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'gsp.bin'
            make_gsp(path)
            data = bytearray(path.read_bytes())
            shoff = struct.unpack_from('<Q', data, 40)[0]
            struct.pack_into('<Q', data, shoff+2*64+32, 1000000)
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                fw.inspect_gsp(path)

    def test_wrong_ucodes_magic_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ucodes.bin'
            make_ucodes(path)
            data = bytearray(path.read_bytes())
            data[:8] = b'INVALID!'
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                fw.inspect_ucodes(path)

    def test_package_comparison_detects_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_gsp(root/'gsp.bin')
            make_ucodes(root/'ucodes.bin')
            package = root/'package'
            package.mkdir()
            (package/'gsp_ga10x.bin').write_bytes((root/'gsp.bin').read_bytes())
            (package/'ucodes_ga10x.bin').write_bytes((root/'ucodes.bin').read_bytes())
            self.assertTrue(fw.inspect_pair(root/'gsp.bin', root/'ucodes.bin', package)['package_files_identical'])
            make_ucodes(package/'ucodes_ga10x.bin', fingerprint=3)
            result = fw.inspect_pair(root/'gsp.bin', root/'ucodes.bin', package)
            self.assertFalse(result['package_files_identical'])
            self.assertTrue(result['package_comparison']['gsp']['same_sha256'])
            self.assertFalse(result['package_comparison']['ucodes']['same_sha256'])
            self.assertFalse(result['can_unlock'])

    def test_existing_report_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_gsp(root/'gsp.bin')
            make_ucodes(root/'ucodes.bin')
            (root/'report.json').write_text('keep me')
            import sys
            from unittest.mock import patch
            with patch.object(sys, 'argv', ['script', '--gsp', str(root/'gsp.bin'),
                                             '--ucodes', str(root/'ucodes.bin'),
                                             '--output', str(root/'report.json')]):
                self.assertEqual(fw.main(), 1)
                self.assertEqual((root/'report.json').read_text(), 'keep me')


if __name__ == '__main__':
    unittest.main()
