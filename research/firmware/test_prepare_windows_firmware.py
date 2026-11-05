"""Host-only tests for Windows wrapper; fixtures never contain actual firmware."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('windows_fw_prep', ROOT / 'prepare_windows_firmware.py')
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)


def build_archive(path, filenames, *, duplicate=None, invalid_link=None):
    with tarfile.open(path, 'w:xz') as tar:
        for name in filenames:
            data = name.encode('ascii')
            item = tarfile.TarInfo(fw.SOURCE_PREFIX + name)
            item.size = len(data)
            tar.addfile(item, io.BytesIO(data))
        if duplicate:
            data = b'overwritten'
            item = tarfile.TarInfo(fw.SOURCE_PREFIX + duplicate)
            item.size = len(data)
            tar.addfile(item, io.BytesIO(data))
        if invalid_link:
            item = tarfile.TarInfo(fw.SOURCE_PREFIX + invalid_link)
            item.type = tarfile.SYMTYPE
            item.linkname = '../../outside'
            tar.addfile(item)


class PrepareWindowsFirmwareTests(unittest.TestCase):
    def test_exact_two_gpu_driver_inventory(self):
        text = ('00000000:01:00.0, NVIDIA GeForce RTX 4090, 617.42\n'
                '00000000:04:00.0, NVIDIA GeForce RTX 3080, 617.42\n')
        result = fw.parse_driver_inventory(text)
        self.assertEqual(set(result), set(fw.EXPECTED_CARDS))
        self.assertEqual(result['04:00.0']['reported_driver'], '617.42')

    def test_wrong_driver_and_extra_or_swapped_card_rejected(self):
        good = '00000000:01:00.0, NVIDIA GeForce RTX 4090, 617.42\n'
        for bad in ('00000000:04:00.0, NVIDIA GeForce RTX 3080, 616.56\n',
                    '00000000:04:00.0, NVIDIA GeForce RTX 4090, 617.42\n',
                    '00000000:02:00.0, NVIDIA GeForce RTX 3080, 617.42\n',
                    '00000000:01:00.0, NVIDIA GeForce RTX 4090, 617.42\n'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                fw.parse_driver_inventory(good + bad)

    def test_only_expected_four_source_files_are_extracted(self):
        with tempfile.TemporaryDirectory() as temp:
            tmp = Path(temp)
            build_archive(tmp / 'source.tar.xz', [*fw.SOURCE_C_FILES, 'unrelated.c'])
            root = fw.unpack_exact_source(tmp / 'source.tar.xz', tmp / 'out')
            got = sorted(p.name for p in (root / 'src/nvidia/generated').iterdir())
            self.assertEqual(got, sorted(fw.SOURCE_C_FILES))
            for name in fw.SOURCE_C_FILES:
                self.assertEqual((root / 'src/nvidia/generated' / name).read_bytes(), name.encode('ascii'))

    def test_missing_duplicate_and_linked_sources_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            tmp = Path(temp)
            cases = [
                (fw.SOURCE_C_FILES[:-1], None, None),
                (fw.SOURCE_C_FILES, fw.SOURCE_C_FILES[0], None),
                (fw.SOURCE_C_FILES[:-1], None, fw.SOURCE_C_FILES[-1]),
            ]
            for i, (names, duplicate, linked) in enumerate(cases):
                path = tmp / f'{i}.tar.xz'
                build_archive(path, names, duplicate=duplicate, invalid_link=linked)
                with self.subTest(case=i), self.assertRaises(ValueError):
                    fw.unpack_exact_source(path, tmp / f'out{i}')

    def test_existing_output_refused_before_downloading(self):
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp) / 'already-exists'
            dest.mkdir()
            with patch.object(fw, 'run_vendor') as command:
                with self.assertRaisesRegex(ValueError, 'must not exist'):
                    fw.prepare(Path(temp) / 'cache', dest)
                command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
