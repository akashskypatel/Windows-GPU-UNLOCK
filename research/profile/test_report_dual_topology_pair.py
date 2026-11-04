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


    def test_summary_threads_pair_evidence_without_changing_default_output(self):
        def display(device_id, bus):
            values = {name: '0x0' for name in report.FIELDS}
            values.update(seg='0x0000', bus=f'0x{bus:02x}', dev='0x00', fun='0x00',
                          id=f'0x{device_id:04x}10de', **{'class': '0x030000a1'},
                          stable='1', duplicate='0')
            return 'probe-display-v2 ' + ' '.join(f'{name}={values[name]}' for name in report.FIELDS)

        diagnostic = '\n'.join([
            'probe-inventory-v2 begin', display(0x2684, 1), display(0x220a, 4),
            'probe-inventory-v2 end displays=0x2 failures=0x0 complete=1',
            'capture-complete=1', 'diagnostic-result status=0x0000000000000000',
            'console out=0x6 error=0x6 input=0x6',
        ])
        graph = lambda text: {}  # Artificial empty graph: tests PCI observation only.
        matched = report.summarise(diagnostic, graph, expected_pci_ids=self.expected)
        self.assertEqual(matched['requested_pair']['status'], 'observed_pci_pair')
        self.assertFalse(matched['capture']['unlock_eligible'])
        self.assertNotIn('requested_pair', report.summarise(diagnostic, graph))
        incomplete = diagnostic.replace('complete=1', 'complete=0')
        self.assertEqual(report.summarise(incomplete, graph, expected_pci_ids=self.expected)
                         ['requested_pair']['status'], 'unverified')


if __name__ == '__main__':
    unittest.main()
