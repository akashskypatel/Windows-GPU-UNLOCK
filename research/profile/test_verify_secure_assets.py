"""Synthetic-only independent host controls for reference asset verification."""
import hashlib
from pathlib import Path
import tempfile
import unittest
import importlib.util

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('verify_secure_assets', HERE / 'verify_secure_assets.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class SecureAssetTests(unittest.TestCase):
    def test_reference_architectures_have_independent_payloads(self):
        ad = set(verify.GROUPS['rtx4090_ad102'])
        ga = set(verify.GROUPS['rtx3080_ga102'])
        self.assertEqual(ad & ga, {'gsp_ga10x.bin'})
        self.assertEqual(ad | ga, set(verify.PINS))
        self.assertTrue(all(len(v) == 64 for v in verify.PINS.values()))

    def test_missing_assets_are_not_admitted(self):
        with tempfile.TemporaryDirectory() as root:
            report = verify.inspect(Path(root))
            self.assertEqual(report['status'], 'REFERENCE_ASSET_EVIDENCE_INCOMPLETE')
            self.assertFalse(report['can_unlock'])
            self.assertFalse(report['groups']['rtx4090_ad102']['reference_hashes_matched'])
            self.assertTrue(all(v['status'] == 'MISSING_OR_UNREADABLE' for v in report['assets'].values()))

    def test_matched_fixture_still_never_grants_unlock(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / 'gpu-unlock' / '610.43.03'
            directory.mkdir(parents=True)
            for name in verify.PINS:
                (directory / name).write_bytes(name.encode('ascii'))
            synthetic_pins = {name: hashlib.sha256(name.encode('ascii')).hexdigest() for name in verify.PINS}
            report = verify.inspect(Path(root), pins=synthetic_pins)
            self.assertEqual(report['status'], 'ALL_REFERENCE_ASSETS_MATCH')
            self.assertTrue(all(v['reference_hashes_matched'] for v in report['groups'].values()))
            self.assertFalse(report['nvidia_signature_verified'])
            self.assertFalse(report['can_unlock'])

    def test_mismatched_asset_isolation(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / 'gpu-unlock' / '610.43.03'
            directory.mkdir(parents=True)
            for name in verify.PINS:
                (directory / name).write_bytes(name.encode('ascii'))
            synthetic_pins = {name: hashlib.sha256(name.encode('ascii')).hexdigest() for name in verify.PINS}
            (directory / 'booter_load_ad102.bin').write_bytes(b'wrong')
            report = verify.inspect(Path(root), pins=synthetic_pins)
            self.assertFalse(report['groups']['rtx4090_ad102']['reference_hashes_matched'])
            self.assertTrue(report['groups']['rtx3080_ga102']['reference_hashes_matched'])
            self.assertEqual(report['assets']['booter_load_ad102.bin']['status'], 'HASH_MISMATCH')
            self.assertFalse(report['can_detach'])

    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / 'gpu-unlock' / '610.43.03'
            directory.mkdir(parents=True)
            target = Path(root) / 'source'
            target.write_bytes(b'test')
            try:
                (directory / 'gsp_ga10x.bin').symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest('symlinks not permitted by filesystem')
            report = verify.inspect(Path(root))
            self.assertEqual(report['assets']['gsp_ga10x.bin']['status'], 'REFUSED_INVALID_FILE')


if __name__ == '__main__':
    unittest.main()
