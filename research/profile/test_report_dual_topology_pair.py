"""Synthetic PCI-pair evidence tests; no GPU access or support qualification."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('dual_topology_report', Path(__file__).with_name('report-dual-topology.py'))
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


class PairEvidenceTests(unittest.TestCase):
    expected = ('10de:2684', '10de:220a')
    ada = {'pci_id': '10de:2684', 'bdf': '0000:01:00.0', 'status': 'observed_stable'}
    ampere = {'pci_id': '10de:220a', 'bdf': '0000:04:00.0', 'status': 'observed_stable'}

    def test_exact_pair_is_pci_observation_not_unlock_permission(self):
        result = report.match_expected_pair([self.ampere, self.ada], self.expected, True)
        self.assertEqual(result['status'], 'observed_pci_pair')
        self.assertEqual(result['devices'], [
            {'pci_id': '10de:2684', 'bdf': '0000:01:00.0'},
            {'pci_id': '10de:220a', 'bdf': '0000:04:00.0'},
        ])
        self.assertIs(result['can_unlock'], False)
        self.assertIs(result['can_detach'], False)

    def test_extra_non_nvidia_display_is_not_a_third_target(self):
        igpu = {'pci_id': '1002:13c0', 'bdf': '0000:08:00.0', 'status': 'observed_stable'}
        self.assertEqual(report.match_expected_pair([self.ada, igpu, self.ampere], self.expected, True)['status'], 'observed_pci_pair')

    def test_unverified_cases_never_publish_a_matched_pair(self):
        variants = [
            ([self.ada], True),
            ([self.ada, self.ampere, dict(self.ada, bdf='0000:05:00.0')], True),
            ([self.ada, dict(self.ada, bdf='0000:04:00.0')], True),
            ([self.ada, self.ampere], False),
            ([dict(self.ada, status='incomplete'), self.ampere], True),
            ([self.ada, dict(self.ampere, bdf=self.ada['bdf'])], True),
        ]
        for devices, complete in variants:
            with self.subTest(devices=devices, complete=complete):
                result = report.match_expected_pair(devices, self.expected, complete)
                self.assertEqual(result['status'], 'unverified')
                self.assertEqual(result['devices'], [])
                self.assertIs(result['can_unlock'], False)

    def test_same_pci_identity_allowed_only_with_distinct_locations(self):
        second = dict(self.ada, bdf='0000:04:00.0')
        self.assertEqual(report.match_expected_pair([self.ada, second], ('10de:2684', '10de:2684'), True)['status'], 'observed_pci_pair')

    def test_invalid_expected_identifiers_rejected(self):
        for expected in ((), ('10de:2684',), ('1002:13c0', '10de:220a'),
                         ('10de:2684', '10de:bad'), ('10de:2684', '10de:220a', '10de:220a')):
            with self.subTest(expected=expected), self.assertRaises(report.DiagnosticError):
                report.match_expected_pair([self.ada, self.ampere], expected, True)


if __name__ == '__main__':
    unittest.main()
