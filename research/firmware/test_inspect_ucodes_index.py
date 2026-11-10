"""Independent checks that malformed external indices fail closed."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('inspect_ucodes_index.py')
spec = importlib.util.spec_from_file_location('ucodes_index', SCRIPT)
index_reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(index_reader)


def make_index():
    data = bytearray(1024)
    index_reader.HEADER.pack_into(data, 0, b'NVUCODES', 1, 3, 0x123456789ABCDEF0)
    index_reader.ENTRY.pack_into(data, 24, 4, 0, 0, 4, 256)
    index_reader.ENTRY.pack_into(data, 24 + 2 * 24, 3, 0, 0, 4, 512)
    data[256:260] = b'ABCD'
    data[512:515] = b'XYZ'
    return data


def inspect(data):
    return index_reader.inspect_index(bytes(data), expected_count=3,
                                      expected_fingerprint=0x123456789ABCDEF0)


class IndexTests(unittest.TestCase):
    def test_valid_sparse_entries_and_digests(self):
        result = inspect(make_index())
        self.assertEqual(result['external_records'], 2)
        self.assertEqual(result['empty_indices'], 1)
        self.assertEqual([e['index'] for e in result['records']], [0, 2])
        self.assertEqual(result['index_end_offset'], 96)
        self.assertFalse(result['signed_booter_identified'])
        self.assertFalse(result['runtime_accepted'])
        self.assertFalse(result['can_unlock'])

    def test_short_table_rejected(self):
        with self.assertRaisesRegex(ValueError, 'truncated index table'):
            inspect(make_index()[:80])

    def test_wrong_fingerprint_rejected(self):
        data = make_index()
        struct.pack_into('<Q', data, 16, 0)
        with self.assertRaisesRegex(ValueError, 'header differs'):
            inspect(data)

    def test_unknown_flags_rejected(self):
        data = make_index()
        struct.pack_into('<I', data, 24 + 16, 0x14)
        with self.assertRaisesRegex(ValueError, 'unsupported storage flags'):
            inspect(data)

    def test_empty_entry_with_nonzero_field_rejected(self):
        data = make_index()
        struct.pack_into('<I', data, 24 + 24, 5)
        with self.assertRaisesRegex(ValueError, 'nonempty fields'):
            inspect(data)

    def test_nonzero_pointer_rejected(self):
        data = make_index()
        struct.pack_into('<Q', data, 24 + 8, 0x40000000)
        with self.assertRaisesRegex(ValueError, 'invalid external extent'):
            inspect(data)

    def test_compressed_size_rejected(self):
        data = make_index()
        struct.pack_into('<I', data, 24 + 4, 4)
        with self.assertRaisesRegex(ValueError, 'invalid external extent'):
            inspect(data)

    def test_offset_into_index_rejected(self):
        data = make_index()
        struct.pack_into('<I', data, 24 + 20, 0)
        with self.assertRaisesRegex(ValueError, 'invalid external extent'):
            inspect(data)

    def test_unaligned_offset_rejected(self):
        data = make_index()
        struct.pack_into('<I', data, 24 + 20, 257)
        with self.assertRaisesRegex(ValueError, 'invalid external extent'):
            inspect(data)

    def test_out_of_bounds_extent_rejected(self):
        data = make_index()
        struct.pack_into('<I', data, 24 + 0, len(data))
        with self.assertRaisesRegex(ValueError, 'invalid external extent'):
            inspect(data)

    def test_overlap_rejected(self):
        data = make_index()
        struct.pack_into('<I', data, 24 + 0, 260)
        with self.assertRaisesRegex(ValueError, 'overlapping external record'):
            inspect(data)

    def test_unindexed_nonzero_padding_rejected(self):
        data = make_index()
        data[400] = 1
        with self.assertRaisesRegex(ValueError, 'nonzero bytes outside'):
            inspect(data)

    def test_nonzero_trailing_data_rejected(self):
        data = make_index()
        data[-1] = 1
        with self.assertRaisesRegex(ValueError, 'nonzero trailing bytes'):
            inspect(data)

    def test_no_records_rejected(self):
        data = make_index()
        index_reader.ENTRY.pack_into(data, 24, 0, 0, 0, 0, 0)
        index_reader.ENTRY.pack_into(data, 72, 0, 0, 0, 0, 0)
        with self.assertRaisesRegex(ValueError, 'no external records'):
            inspect(data)

    def test_cli_refuses_unknown_source_and_preserves_output(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            source, report = root/'ucodes.bin', root/'report.json'
            source.write_bytes(make_index())
            report.write_text('sentinel', encoding='utf-8')
            with patch('sys.argv', ['cmd', '--ucodes', str(source), '--output', str(report)]):
                self.assertEqual(index_reader.main(), 1)
            self.assertEqual(report.read_text(encoding='utf-8'), 'sentinel')
            report.unlink()
            with patch('sys.argv', ['cmd', '--ucodes', str(source), '--output', str(report)]):
                self.assertEqual(index_reader.main(), 1)
            self.assertFalse(report.exists())


if __name__ == '__main__':
    unittest.main()
