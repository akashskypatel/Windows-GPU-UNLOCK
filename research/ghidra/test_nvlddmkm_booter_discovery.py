"""Host-only checks for raw discovery heuristics (no Ghidra runtime needed)."""
import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).with_name('nvlddmkm_booter_discovery.py')
spec = importlib.util.spec_from_file_location('nvlddmkm_booter_discovery', MODULE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class DiscoveryPatternTests(unittest.TestCase):
    def test_ascii_case_insensitive_high_signal_label(self):
        matches = list(probe.marker_hits(b'\0preBootErLoadUcode\0'))
        self.assertEqual([m[2:] for m in matches], [('booterloaducode', 'ASCII')])

    def test_utf16le_and_ascii_are_both_visible(self):
        data = 'ucodes_ga10x.bin'.encode('utf-16le') + b'---' + b'AD102'
        hits = list(probe.marker_hits(data))
        self.assertEqual([(h[2], h[3]) for h in hits],
                         [('ucodes_ga10x.bin', 'UTF16LE'), ('ad102', 'ASCII')])

    def test_boundary_match_is_counted_once(self):
        before = b'Z' * 120 + b'Boo'
        after = b'terLoadUcode\0tail'
        overlap = before[-(probe.MAX_MARKER_BYTES - 1):]
        first_chunk = list(probe.combine_chunk_hits(b'', before))
        second_chunk = list(probe.combine_chunk_hits(overlap, after))
        self.assertFalse(any(x[1] == 'booterloaducode' for x in first_chunk))
        self.assertEqual([x[1] for x in second_chunk], ['booterloaducode'])
        self.assertEqual(second_chunk[0][0], -3)

    def test_previous_overlap_match_is_not_duplicated(self):
        before = b'GspRmBoot' + b'Z' * 4
        after = b'XYZ'
        overlap = before[-(probe.MAX_MARKER_BYTES - 1):]
        self.assertEqual([x[1] for x in probe.combine_chunk_hits(b'', before)], ['gsprmboot'])
        self.assertEqual(list(probe.combine_chunk_hits(overlap, after)), [])

    def test_no_assertion_from_missing_raw_strings(self):
        self.assertEqual(list(probe.marker_hits(b'not an Nvidia archive path')), [])


if __name__ == '__main__':
    unittest.main()
