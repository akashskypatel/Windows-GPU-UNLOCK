"""Independent synthetic PCI option-ROM structural tests (no real firmware)."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('vbios_inspection', HERE / 'inspect_vbios_backups.py')
inspector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspector)


def synthetic_rom(device: int, *, vendor=0x10de, final=True, code_type=0, units=2):
    image = bytearray(units * 512)
    image[:2] = b'\x55\xaa'
    image[2] = units
    image[0x18:0x1a] = (0x40).to_bytes(2, 'little')
    pcir = 0x40
    image[pcir:pcir+4] = b'PCIR'
    image[pcir+4:pcir+6] = vendor.to_bytes(2, 'little')
    image[pcir+6:pcir+8] = device.to_bytes(2, 'little')
    image[pcir+0x0a:pcir+0x0c] = (0x18).to_bytes(2, 'little')
    image[pcir+0x10:pcir+0x12] = units.to_bytes(2, 'little')
    image[pcir+0x14] = code_type
    image[pcir+0x15] = 0x80 if final else 0
    return bytes(image)


class InspectBackupTests(unittest.TestCase):
    def test_valid_two_card_report_never_claims_flashability_or_unlock(self):
        report = inspector.build_report(synthetic_rom(0x2684), synthetic_rom(0x220a))
        self.assertEqual(len(report['cards']), 2)
        self.assertFalse(report['can_flash'])
        self.assertFalse(report['backup_proven_flashable'])
        self.assertFalse(report['can_unlock'])
        self.assertFalse(report['can_detach'])
        self.assertFalse(report['writes_firmware'])
        self.assertTrue(all(card['capture_bdf_provenance'] == 'USER_FILE_ASSIGNMENT_ONLY'
                            for card in report['cards']))
        self.assertTrue(all(not card['subsystem_id_in_rom_verified'] for card in report['cards']))

    def test_multi_image_chain_has_correct_offsets(self):
        first = synthetic_rom(0x2684, final=False, code_type=0)
        second = synthetic_rom(0x2684, final=True, code_type=3)
        result = inspector.inspect_backup(first+second, vendor_id=0x10de, device_id=0x2684)
        self.assertEqual([v['offset'] for v in result['images']], [0, len(first)])
        self.assertEqual([v['code_type'] for v in result['images']], [0, 3])
        self.assertEqual(result['declared_image_bytes'], len(first+second))

    def test_mz_loaded_gop_is_not_a_pci_rom(self):
        with self.assertRaisesRegex(inspector.InvalidBackup, 'signature'):
            inspector.inspect_backup(b'MZ' + bytes(1022), vendor_id=0x10de, device_id=0x2684)

    def test_gpu_swap_is_rejected(self):
        with self.assertRaisesRegex(inspector.InvalidBackup, 'vendor/device'):
            inspector.build_report(synthetic_rom(0x220a), synthetic_rom(0x2684))

    def test_vendor_mismatch_is_rejected(self):
        with self.assertRaisesRegex(inspector.InvalidBackup, 'vendor/device'):
            inspector.inspect_backup(synthetic_rom(0x2684, vendor=0x1234), vendor_id=0x10de, device_id=0x2684)

    def test_missing_pcir_signature_is_rejected(self):
        bad = bytearray(synthetic_rom(0x2684))
        bad[0x40:0x44] = b'ABCD'
        with self.assertRaisesRegex(inspector.InvalidBackup, 'PCIR structure signature'):
            inspector.inspect_backup(bytes(bad), vendor_id=0x10de, device_id=0x2684)

    def test_pcir_pointer_outside_image_is_rejected(self):
        bad = bytearray(synthetic_rom(0x2684))
        bad[0x18:0x1a] = (65535).to_bytes(2, 'little')
        with self.assertRaisesRegex(inspector.InvalidBackup, 'PCIR pointer'):
            inspector.inspect_backup(bytes(bad), vendor_id=0x10de, device_id=0x2684)

    def test_declared_image_beyond_input_is_rejected(self):
        bad = bytearray(synthetic_rom(0x2684))
        bad[0x40+0x10:0x40+0x12] = (20).to_bytes(2, 'little')
        with self.assertRaisesRegex(inspector.InvalidBackup, 'declared ROM bounds'):
            inspector.inspect_backup(bytes(bad), vendor_id=0x10de, device_id=0x2684)

    def test_unterminated_chain_is_rejected(self):
        with self.assertRaisesRegex(inspector.InvalidBackup, 'missing PCI option-ROM signature'):
            inspector.inspect_backup(synthetic_rom(0x2684, final=False), vendor_id=0x10de, device_id=0x2684)

    def test_reject_nonuniform_unknown_trailing_bytes(self):
        with self.assertRaisesRegex(inspector.InvalidBackup, 'nonuniform trailing'):
            inspector.inspect_backup(synthetic_rom(0x2684)+bytes([0,1])*256, vendor_id=0x10de, device_id=0x2684)

    def test_allow_uniform_padding_without_calling_it_flashable(self):
        result = inspector.inspect_backup(synthetic_rom(0x2684) + b'\xff'*512, vendor_id=0x10de, device_id=0x2684)
        self.assertEqual(result['trailing_padding_bytes'], 512)
        self.assertFalse(result['full_spi_flash_contents_verified'])

    def test_reject_invalid_backup_size(self):
        with self.assertRaisesRegex(inspector.InvalidBackup, 'size outside'):
            inspector.inspect_backup(b'\x55\xaa' + bytes(513), vendor_id=0x10de, device_id=0x2684)

    def test_bounded_read_rejects_symlinks_and_changed_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'rom.bin'
            path.write_bytes(synthetic_rom(0x2684))
            self.assertEqual(inspector.read_backup(path)[:2], b'\x55\xaa')
            bad = root / 'bad.bin'
            bad.write_bytes(bytes(513))
            with self.assertRaisesRegex(inspector.InvalidBackup, 'multiple of 512'):
                inspector.read_backup(bad)
            link = root / 'link.bin'
            try:
                link.symlink_to(path)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaisesRegex(inspector.InvalidBackup, 'symlinked'):
                    inspector.read_backup(link)


if __name__ == '__main__':
    unittest.main()
