"""Synthetic loaded-image evidence integrity checks (not hardware evidence)."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, HERE / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


report = module('report-nvgop-evidence.py', 'nvgop_code_report')
fixture = module('test_console_survivor.py', 'nvgop_console_fixture')


def pe_image(size, *, reloc=False, text_size=0x900):
    data = bytearray(size)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\x00\x00'
    struct.pack_into('<HH', data, 0x84, 0x8664, 1)
    struct.pack_into('<H', data, 0x94, 0xf0)
    optional = 0x98
    struct.pack_into('<H', data, optional, 0x20b)
    struct.pack_into('<II', data, optional+56, size, 0x200)
    struct.pack_into('<I', data, optional+108, 6 if reloc else 0)
    if reloc:
        struct.pack_into('<II', data, optional+112+5*8, 0x1800, 10)
        struct.pack_into('<IIH', data, 0x1800, 0, 10, 0xa280)
    section = 0x188
    data[section:section+8] = b'.text\0\0\0'
    struct.pack_into('<II', data, section+8, text_size, 0x280)
    struct.pack_into('<I', data, section+36, 0x60000020)
    data[0x280:0x280+text_size] = bytes((i*7) & 0xff for i in range(text_size))
    return bytes(data)


def evidence(images, *, tamper=''):
    lines = []
    for index, bdf in enumerate(('0000:01:00.0', '0000:04:00.0')):
        conf = fixture.v.EXPECTED[bdf]
        size = conf[5]
        img = pe_image(size, reloc=(tamper == 'reloc' and index == 0),
                       text_size=0x150 if tamper == 'shorttext' and index == 0 else 0x900)
        (images / f'IMG{index:02}.BIN').write_bytes(img)
        lines.append('nvgop-evidence-v1 bdf-seg=0x0000 bus=0x' + ('01' if index == 0 else '04') +
                     f' pci-id=0x{conf[0]:08x} image-index=0x{index:02x} loaded-image-sha256=' +
                     hashlib.sha256(img).hexdigest())
    return fixture.fixture().replace('probe targets=0002 cfg-incomplete=0000',
                                      'probe targets=0002 cfg-incomplete=0000\n' + '\n'.join(lines)).encode()


class ImageEvidenceTests(unittest.TestCase):
    def verify(self, source, folder):
        return report.analyze(source, folder, HERE)

    def test_two_loaded_pe_images_are_fingerprints_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.verify(evidence(root), root)
            self.assertEqual(result['status'], 'captured_loaded_text_fingerprints')
            self.assertEqual([d['bdf'] for d in result['images']], ['0000:01:00.0','0000:04:00.0'])
            self.assertTrue(all(d['text_bytes'] == 0x900 for d in result['images']))
            self.assertFalse(result['can_unlock'])
            self.assertFalse(result['can_detach'])
            self.assertFalse(result['vendor_stop_behavior_verified'])

    def test_swapped_or_mutated_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = evidence(root)
            a = root / 'IMG00.BIN'
            a.write_bytes(a.read_bytes()[:-1]+b'!')
            with self.assertRaisesRegex(report.Refused, 'does not match'):
                self.verify(source, root)

    def test_missing_or_duplicate_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = evidence(root)
            for bad in (source.replace(b'nvgop-evidence-v1', b'other-evidence-v1', 1),
                        source.replace(b'image-index=0x01', b'image-index=0x00'),
                        source.replace(b'pci-id=0x268410de', b'pci-id=0x220a10de', 1),
                        source.replace(b'capture-complete=1', b'capture-complete=0')):
                with self.subTest(bad=bad[-80:]),self.assertRaises(report.Refused):
                    self.verify(bad, root)

    def test_unstable_or_nonexecuting_pe_region_is_rejected(self):
        for change in ('reloc', 'shorttext'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                with self.assertRaises(report.Refused):
                    self.verify(evidence(root, tamper=change), root)

    def test_missing_image_file_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = evidence(root)
            (root / 'IMG01.BIN').unlink()
            with self.assertRaises(report.Refused):
                self.verify(source, root)


if __name__ == '__main__':
    unittest.main()
