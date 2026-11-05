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


def make_gsp_with_fwimage(path: Path, payload: bytes):
    names = b'\0.shstrtab\0.fwimage\0'
    hdr = bytearray(64)
    hdr[:16] = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    payload_offset = 64 + len(names)
    shoff = payload_offset + len(payload)
    struct.pack_into('<HHIQQQIHHHHHH', hdr, 16, 1, 243, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 3, 1)
    sections = [b'\0'*64,
                fw.ELF_SECTION.pack(1, 3, 0, 0, 64, len(names), 0, 0, 1, 0),
                fw.ELF_SECTION.pack(11, 1, 0, 0, payload_offset, len(payload), 0, 0, 1, 0)]
    path.write_bytes(bytes(hdr) + names + payload + b''.join(sections))
    return payload_offset


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

    def test_section_digest_reports_bytes_not_signature_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'gsp.bin'
            make_gsp(path)
            parsed = fw.inspect_gsp(path)
            self.assertEqual(parsed['signature_section_digests']['.fwsignature_ad10x']['bytes'], 4)
            import hashlib
            self.assertEqual(parsed['signature_section_digests']['.fwsignature_ad10x']['sha256'],
                             hashlib.sha256(b'\x11\x22\x33\x44').hexdigest())
            self.assertFalse(parsed['signature_sections_authenticated'])
            self.assertIsNone(parsed['fwversion'])

    def test_embedded_firmware_version_is_read_as_raw_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'gsp.bin'
            make_gsp(path)
            data = bytearray(path.read_bytes())
            # Replace the standalone signature sample with a version string
            # and rename the section in-place, retaining valid ELF structure.
            nameoff = data.index(b'.fwsignature_ad10x')
            data[nameoff:nameoff + len(b'.fwsignature_ad10x')] = b'.fwversion\0' + b'\0' * (len(b'.fwsignature_ad10x')-len(b'.fwversion\0'))
            data[64 + len(b'\0.shstrtab\0.fwsignature_ad10x\0'):64 + len(b'\0.shstrtab\0.fwsignature_ad10x\0') + 4] = b'1234'
            path.write_bytes(data)
            parsed = fw.inspect_gsp(path)
            self.assertEqual(parsed['fwversion'], '1234')
            self.assertEqual(parsed['fwversion_raw_hex'], b'1234'.hex())

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

    def test_fingerprint_found_exactly_once_inside_fwimage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fp = (0x2d38befecdb703a6).to_bytes(8, 'little')
            offset = make_gsp_with_fwimage(root/'gsp.bin', b'!'*13 + fp + b'#'*20)
            make_ucodes(root/'ucodes.bin')
            report = fw.inspect_pair(root/'gsp.bin', root/'ucodes.bin')
            found = report['static_fingerprint_comparison']
            self.assertTrue(found['search_performed'])
            self.assertTrue(found['unique_occurrence'])
            self.assertEqual(found['occurrences'], 1)
            self.assertEqual(found['first_file_offset'], offset + 13)
            self.assertEqual(found['first_fwimage_relative_offset'], 13)
            self.assertFalse(found['runtime_pairing_verified'])
            self.assertFalse(report['gsp_ucodes_pair_accepted_by_driver'])

    def test_boundary_spanning_fingerprint_not_missed_or_double_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fp = (0x2d38befecdb703a6).to_bytes(8, 'little')
            relative = 1024 * 1024 - 4
            base = make_gsp_with_fwimage(root/'gsp.bin', b'!'*relative + fp + b'#'*11)
            make_ucodes(root/'ucodes.bin')
            found = fw.inspect_pair(root/'gsp.bin', root/'ucodes.bin')['static_fingerprint_comparison']
            self.assertEqual(found['occurrences'], 1)
            self.assertEqual(found['first_file_offset'], base + relative)

    def test_no_fingerprint_is_not_a_pairing_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_gsp_with_fwimage(root/'gsp.bin', b'0'*48)
            make_ucodes(root/'ucodes.bin')
            found = fw.inspect_pair(root/'gsp.bin', root/'ucodes.bin')['static_fingerprint_comparison']
            self.assertTrue(found['search_performed'])
            self.assertEqual(found['occurrences'], 0)
            self.assertIsNone(found['first_file_offset'])
            self.assertFalse(found['unique_occurrence'])

    def test_duplicate_fingerprint_not_reported_unique(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fp = (0x2d38befecdb703a6).to_bytes(8, 'little')
            make_gsp_with_fwimage(root/'gsp.bin', fp + b'-'*10 + fp)
            make_ucodes(root/'ucodes.bin')
            found = fw.inspect_pair(root/'gsp.bin', root/'ucodes.bin')['static_fingerprint_comparison']
            self.assertEqual(found['occurrences'], 2)
            self.assertFalse(found['unique_occurrence'])

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
