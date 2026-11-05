"""Offline synthetic negative controls for exact-machine GOP evidence bundling."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('gu_exact_gop', HERE / 'report-exact-machine-gop.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def sample():
    rows = ['capture-complete=1', 'diagnostic-result status=0x0000000000000000']
    images = []
    for bdf, expected in m.EXPECTED.items():
        images.append({
            'bdf': bdf, 'pci_id': expected['pci_id'],
            'text_sha256': expected['text_sha256'],
            'text_bytes': expected['text_bytes'], 'text_rva': '0x280',
            'stop_rva': expected['stop_rva'],
            'nvgop_name': expected['nvgop_name'], 'text_relocations': 0,
            'loaded_image_sha256': 'f' * 64,
        })
        fields = {name: 1 for name in m.REQUIRED_FIELDS}
        fields['protocol_status'] = fields['memory_map_status'] = fields['reset_flag_98'] = 0
        for name, value in fields.items():
            rows.append(f"nvgop-context-v1 pci-id=0x{expected['context_pci_id']} {name}=0x{value:016x}")
    evidence = {'status': 'captured_loaded_text_fingerprints', 'amd_console_observed': True,
                'diagnostic_sha256': 'a' * 64, 'images': images}
    return ('\n'.join(rows) + '\n').encode(), evidence


class ExactGopEvidenceTests(unittest.TestCase):
    def test_complete_pinned_pair_is_observation_only(self):
        source, evidence = sample()
        result = m.assemble(source, evidence)
        self.assertEqual(result['status'], 'MATCHED_PASSIVE_GOP_EVIDENCE')
        self.assertEqual([x['bdf'] for x in result['cards']], list(m.EXPECTED))
        self.assertFalse(result['can_unlock'])
        self.assertFalse(result['can_detach'])
        self.assertFalse(result['recovery_verified'])
        self.assertFalse(result['tool_writes_nonvolatile_firmware'])
        self.assertEqual(len(result['missing_active_provenance']), 5)

    def test_unknown_code_revision_rejected_even_when_self_consistent(self):
        source, evidence = sample()
        evidence['images'][0]['text_sha256'] = '0' * 64
        with self.assertRaisesRegex(m.Refused, 'text_sha256'):
            m.assemble(source, evidence)

    def test_swapped_pair_identity_and_extra_card_rejected(self):
        source, evidence = sample()
        evidence['images'][0]['pci_id'] = '10de:220a'
        with self.assertRaisesRegex(m.Refused, 'pci_id'):
            m.assemble(source, evidence)
        source, evidence = sample()
        evidence['images'].append(copy.deepcopy(evidence['images'][0]))
        with self.assertRaisesRegex(m.Refused, 'two NVIDIA'):
            m.assemble(source, evidence)

    def test_missing_or_duplicate_snapshot_rejected(self):
        source, evidence = sample()
        source = source.decode()
        source = '\n'.join(line for line in source.splitlines()
                           if not line.startswith('nvgop-context-v1 pci-id=0x220a10de')) + '\n'
        with self.assertRaisesRegex(m.Refused, 'both NVIDIA'):
            m.assemble(source.encode(), evidence)
        source, evidence = sample()
        source += b'nvgop-context-v1 pci-id=0x268410de device=0x0000000000000001\n'
        with self.assertRaisesRegex(m.Refused, 'duplicate'):
            m.assemble(source, evidence)

    def test_invalid_pointer_or_failed_protocol_is_not_ready(self):
        source, evidence = sample()
        source = source.replace(b'device=0x0000000000000001', b'device=0x0000000000000000', 1)
        with self.assertRaisesRegex(m.Refused, 'missing required live'):
            m.assemble(source, evidence)
        source, evidence = sample()
        source = source.replace(b'protocol_status=0x0000000000000000', b'protocol_status=0x8000000000000001', 1)
        with self.assertRaisesRegex(m.Refused, 'private-protocol'):
            m.assemble(source, evidence)

    def test_incomplete_diagnostic_refused(self):
        source, evidence = sample()
        for bad in (source.replace(b'capture-complete=1', b'capture-complete=0'),
                    source.replace(b'diagnostic-result status=0x0000000000000000', b'diagnostic-result status=0x8000000000000006')):
            with self.subTest(bad=bad[:80]), self.assertRaises(m.Refused):
                m.assemble(bad, evidence)

    def test_flag_one_is_observation_not_authorization(self):
        source, evidence = sample()
        source = source.replace(b'reset_flag_98=0x0000000000000000', b'reset_flag_98=0x0000000000000001', 1)
        result = m.assemble(source, evidence)
        self.assertEqual(result['cards'][0]['reset_flag_98'], 1)
        self.assertFalse(result['can_detach'])


if __name__ == '__main__':
    unittest.main()
