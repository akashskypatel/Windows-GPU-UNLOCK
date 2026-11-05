"""Synthetic tests for the read-only R615 production bindata comparison path."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

spec = importlib.util.spec_from_file_location('compare_boot_assets', Path(__file__).with_name('compare_boot_assets.py'))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def bindata(label, data, *, compress=False, corrupt_padding=False):
    if compress:
        compressor = zlib.compressobj(level=9, wbits=-15)
        stored = compressor.compress(data) + compressor.flush() + struct.pack('<II', zlib.crc32(data), len(data))
    else:
        stored = data
    padding = (-len(stored)) % 8
    if corrupt_padding and padding:
        stored += b'X' + b'\0' * (padding - 1)
    else:
        stored += b'\0' * padding
    words = ', '.join(f'0x{int.from_bytes(stored[i:i+8], "little"):016x}ULL' for i in range(0, len(stored), 8))
    return (f'// COMPRESSION: {"YES" if compress else "NO"}\n'
            f'// DATA SIZE (bytes): {len(data)}\n'
            f'// COMPRESSED SIZE (bytes): {len(stored) - padding if compress else "N/A"}\n'
            f'static BINDATA_CONST NV_DECLARE_ALIGNED(NvU64, 8) test_BINDATA_LABEL_{label}_data[] = '\
            f'{{ {words} }};\n')


def valid_booter_source(*, bad_transfer=False):
    image = b'\0' * 2048
    fields = (3 if bad_transfer else 0,256,256,512,1,768,256,0,0)
    meta = [("IMAGE_PROD", image), ("HEADER_PROD", struct.pack('<9I', *fields)),
            ("SIG_PROD", b'1'*768), ("PATCH_LOC", struct.pack('<I',256)),
            ("PATCH_META", struct.pack('<3I', 0,1,3)), ("NUM_SIGS", struct.pack('<I',2))]
    return '\n'.join(bindata(name,data,compress=True) for name,data in meta)


def valid_gspboot_source(*, bad_descriptor=False):
    image = b'\0'*1536
    desc = [0]*21
    desc[0] = 5
    desc[14] = 1
    desc[19] = len(image) + (1 if bad_descriptor else 0)
    for k,n in ((1,0),(3,256),(8,512),(10,768),(12,1024)):
        desc[k] = n
        desc[k+1] = 256
    return bindata('UCODE_IMAGE_PROD',image,compress=True) + bindata('UCODE_DESC_PROD',struct.pack('<21I',*desc),compress=True)


class CompareBootAssetsTests(unittest.TestCase):
    def test_little_endian_u64_uncompressed_padding(self):
        data = b'abcde'
        source = bindata('TEST',data)
        self.assertEqual(mod.array_bytes(source,'TEST'),data)

    def test_little_endian_u64_compressed_trailer(self):
        data = b'source-comparison-fixture'*45
        source = bindata('TEST',data,compress=True)
        self.assertEqual(mod.array_bytes(source,'TEST'),data)

    def test_corrupted_u64_padding_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'padding'):
            mod.array_bytes(bindata('TEST',b'abcde',corrupt_padding=True),'TEST')

    def test_corrupted_compressed_crc_is_rejected(self):
        data = b'abcde'*100
        c = zlib.compressobj(wbits=-15)
        stored = c.compress(data) + c.flush() + struct.pack('<II',0,len(data))
        pad = (-len(stored)) % 8
        source = (f'// COMPRESSION: YES\n// DATA SIZE (bytes): {len(data)}\n'
                  f'// COMPRESSED SIZE (bytes): {len(stored)}\n'
                  'static BINDATA_CONST NV_DECLARE_ALIGNED(NvU64, 8) x_BINDATA_LABEL_TEST_data[] = {'
                  + ','.join(f'0x{int.from_bytes((stored+b"\0"*pad)[i:i+8], "little"):016x}ULL'
                             for i in range(0,len(stored)+pad,8)) + '};')
        with self.assertRaisesRegex(ValueError,'CRC'):
            mod.array_bytes(source,'TEST')

    def test_bad_labels_and_malformed_initializer_refused(self):
        with self.assertRaisesRegex(ValueError,'missing or duplicate'):
            mod.array_bytes(bindata('TEST',b'good')*2,'TEST')
        with self.assertRaisesRegex(ValueError,'unexpected NvU64'):
            mod.array_bytes(bindata('TEST',b'good').replace('ULL','BAD'),'TEST')

    def test_valid_synthetic_booter_bundle_has_expected_geometry(self):
        result = mod.booter_bundle(valid_booter_source())
        self.assertEqual(result[:8], struct.pack('<II',mod.MAGIC,1))
        self.assertEqual(len(result),72+2048+768)
        self.assertEqual(result[-768:],b'1'*768)

    def test_invalid_falcon_transfer_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'Falcon transfer geometry'):
            mod.booter_bundle(valid_booter_source(bad_transfer=True))

    def test_synthetic_gsp_boot_image_descriptor(self):
        result = mod.boot_image_pair(valid_gspboot_source())
        self.assertEqual(len(result[0]),1536)
        self.assertEqual(len(result[1]),84)

    def test_wrong_gsp_descriptor_size_refused(self):
        with self.assertRaisesRegex(ValueError,'descriptor layout'):
            mod.boot_image_pair(valid_gspboot_source(bad_descriptor=True))

    def test_unpinned_source_archive_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/mod.SOURCE_FILE
            path.write_bytes(b'not a real source archive')
            with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'):
                mod.extract_source_files(path)

    def test_source_filename_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'some-other-source.tar.xz'
            path.write_bytes(b'ignored')
            with self.assertRaisesRegex(ValueError,'expected pinned'):
                mod.extract_source_files(path)

    def test_output_exists_gate_keeps_original(self):
        with tempfile.TemporaryDirectory() as directory:
            report=Path(directory)/'report.json'
            report.write_text('original')
            with patch('sys.argv',['cmd','--source-archive','missing','--reference-root','missing','--output',str(report)]):
                self.assertEqual(mod.main(),1)
            self.assertEqual(report.read_text(),'original')

if __name__=='__main__':
    unittest.main()
