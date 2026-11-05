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


def synthetic_ifr_v3(device: int, *, primary=None, secondary=None) -> bytes:
    """Construct synthetic NVGI v3/RFRD/PCIR bytes, NOT a real NVIDIA ROM."""
    first = primary if primary is not None else synthetic_rom(device, final=False)
    second = secondary if secondary is not None else synthetic_rom(device, final=True, code_type=3)
    start = 0x9200
    data = bytearray(b'\xff' * (start + len(first) + len(second) + 512))
    data[0:4] = b'NVGI'
    data[4:8] = (0x00240300).to_bytes(4, 'little')
    data[8:12] = (0x1900).to_bytes(4, 'little')
    data[0x1900:0x1904] = (0x4000).to_bytes(4, 'little')
    data[0x5000:0x5004] = b'RFRD'
    data[0x5006:0x5008] = (0x28).to_bytes(2, 'little')
    data[0x5008:0x500c] = start.to_bytes(4, 'little')
    data[start:start + len(first) + len(second)] = first + second
    # Nonuniform vendor-managed data after the PCI image chain must NOT be
    # reclassified as PCI ROM padding or interpreted as a verified flash area.
    data[-2:] = b'\x21\x7c'
    return bytes(data)


class InspectBackupTests(unittest.TestCase):
    def test_ifr_v3_directory_selects_chain_without_scanning(self):
        data = synthetic_ifr_v3(0x2684)
        result = inspector.inspect_backup(data, vendor_id=0x10de, device_id=0x2684)
        self.assertEqual(result['container_format'], 'NVIDIA_IFR_V3')
        self.assertEqual(result['ifrv3_flash_status_offset'], 0x4000)
        self.assertEqual(result['ifrv3_rom_directory_offset'], 0x5000)
        self.assertEqual(result['pci_rom_start_offset'], 0x9200)
        self.assertEqual(result['pci_rom_end_offset'], 0x9a00)
        self.assertEqual(result['declared_image_bytes'], 2048)
        self.assertEqual([x['offset'] for x in result['images']], [0x9200, 0x9600])
        self.assertIsNone(result['trailing_padding_bytes'])
        self.assertFalse(result['nvidia_signature_verified'])
        self.assertFalse(result['full_spi_flash_contents_verified'])

    def test_ifr_no_directory_scan_fallback(self):
        data = bytearray(synthetic_ifr_v3(0x2684))
        data[0x5000:0x5004] = b'BAD!'
        with self.assertRaisesRegex(inspector.InvalidBackup, 'RFRD directory'):
            inspector.inspect_backup(bytes(data), vendor_id=0x10de, device_id=0x2684)

    def test_ifr_invalid_offsets_and_unsupported_versions_are_refused(self):
        for name, offset, payload, expected in (
            ('unsupported version', 4, (0x00240400).to_bytes(4, 'little'), 'unsupported NVGI'),
            ('reserved fixed2', 8, (0x10001900).to_bytes(4, 'little'), 'reserved bits'),
            ('status out of bounds', 0x1900, (0xffffffff).to_bytes(4, 'little'), 'RFRD directory'),
            ('unaligned ROM offset', 0x5008, (0x9201).to_bytes(4, 'little'), 'PCI image offset'),
            ('overlapping ROM offset', 0x5008, (0x5004).to_bytes(4, 'little'), 'PCI image offset'),
        ):
            with self.subTest(name=name):
                data = bytearray(synthetic_ifr_v3(0x2684))
                data[offset:offset+len(payload)] = payload
                with self.assertRaisesRegex(inspector.InvalidBackup, expected):
                    inspector.inspect_backup(bytes(data), vendor_id=0x10de, device_id=0x2684)

    def test_ifr_first_pci_image_must_establish_identity(self):
        data = synthetic_ifr_v3(0x2684, primary=synthetic_rom(0x220a, final=False))
        with self.assertRaisesRegex(inspector.InvalidBackup, 'vendor/device'):
            inspector.inspect_backup(data, vendor_id=0x10de, device_id=0x2684)

    def test_ifr_efi_zero_pcir_identity_is_unverified_not_matched(self):
        data = synthetic_ifr_v3(0x220a, secondary=synthetic_rom(0, vendor=0, final=True, code_type=3))
        result = inspector.inspect_backup(data, vendor_id=0x10de, device_id=0x220a)
        self.assertEqual(result['images'][0]['identity_status'], 'MATCHED')
        self.assertEqual(result['images'][1]['identity_status'], 'UNSPECIFIED_EFI_PCIR')
        self.assertEqual(result['images'][1]['vendor_id'], '0000')
        self.assertFalse(result['subsystem_id_in_rom_verified'])
        self.assertFalse(inspector.build_report(synthetic_ifr_v3(0x2684), data)['can_flash'])

    def test_ifr_zero_identity_exception_is_not_general(self):
        combinations = (
            synthetic_ifr_v3(0x2684, secondary=synthetic_rom(0, vendor=0, final=True, code_type=0)),
            synthetic_ifr_v3(0x2684, secondary=synthetic_rom(0x220a, final=True, code_type=3)),
            synthetic_ifr_v3(0x2684, primary=synthetic_rom(0, vendor=0, final=False)),
        )
        for data in combinations:
            with self.subTest(data=data[:16]), self.assertRaisesRegex(inspector.InvalidBackup, 'vendor/device'):
                inspector.inspect_backup(data, vendor_id=0x10de, device_id=0x2684)
        plain = synthetic_rom(0x2684, final=False) + synthetic_rom(0, vendor=0, code_type=3)
        with self.assertRaisesRegex(inspector.InvalidBackup, 'vendor/device'):
            inspector.inspect_backup(plain, vendor_id=0x10de, device_id=0x2684)

    def test_ifr_first_image_cannot_be_efi_only(self):
        data = synthetic_ifr_v3(0x2684, primary=synthetic_rom(0x2684, final=False, code_type=3))
        with self.assertRaisesRegex(inspector.InvalidBackup, 'not legacy PC-AT'):
            inspector.inspect_backup(data, vendor_id=0x10de, device_id=0x2684)

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

    def test_report_identifies_failing_gpu_and_first_bytes(self):
        malformed = b'MZ' + bytes(1022)
        with self.assertRaisesRegex(inspector.InvalidBackup,
                                    r'rtx3080: missing PCI option-ROM signature at byte offset 0x0; first 16 bytes: 4d 5a'):
            inspector.build_report(synthetic_rom(0x2684), malformed)
        with self.assertRaisesRegex(inspector.InvalidBackup,
                                    r'rtx4090: missing PCI option-ROM signature at byte offset 0x0'):
            inspector.build_report(malformed, synthetic_rom(0x220a))

    def test_later_image_signature_error_reports_chained_offset(self):
        bad = synthetic_rom(0x2684, final=False) + bytes(1024)
        with self.assertRaisesRegex(inspector.InvalidBackup,
                                    r'missing PCI option-ROM signature at byte offset 0x400'):
            inspector.inspect_backup(bad, vendor_id=0x10de, device_id=0x2684)

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
        with self.assertRaisesRegex(inspector.InvalidBackup, r'truncated PCI option-ROM image at byte offset 0x400'):
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
