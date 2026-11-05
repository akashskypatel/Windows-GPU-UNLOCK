#!/usr/bin/env python3
"""Compare stock GA102/AD102 production boot assets across NVIDIA source releases.

Consumes the official, SHA256-pinned 615.78.08 source archive and separately
pinned 610.43.03 reference assets. Produces hashes/metadata only: no firmware
is installed, staged, flashed, emitted, or executed.

615.78.08 is a *nearby Linux source release*, not Windows 617.42/GSP 615.78.05.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import tarfile
import zlib

HERE = Path(__file__).resolve().parent
OLD_VERSION = '610.43.03'
NEW_VERSION = '615.78.08'
SOURCE_FILE = f'NVIDIA-kernel-module-source-{NEW_VERSION}.tar.xz'
SOURCE_SHA256 = '17b4f3d195a5ab1fad9aa1f195c9d3a4ad03aceda18bb9fb68a8bd33d7a000f6'
SOURCE_PREFIX = f'NVIDIA-kernel-module-source-{NEW_VERSION}/src/nvidia/generated/'
MAX_C_FILE = 32 * 1024 * 1024
MAGIC = 0x314C5442
FILENAMES = tuple(
    f'g_bindata_kgspGetBinArchive{family}_{chip}.c'
    for chip in ('AD102', 'GA102')
    for family in ('BooterLoadUcode', 'GspRmBoot')
)
ASSET_NAMES = tuple(
    f'{name}_{chip}.bin'
    for chip in ('ad102', 'ga102')
    for name in ('booter_load', 'gsp_boot', 'gsp_boot_desc')
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as reader:
        for block in iter(lambda: reader.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def array_bytes(source: str, label: str) -> bytes:
    """NVIDIA 615 bindata: little-endian NvU64 words, zero-padded to 8 bytes."""
    marker = f'BINDATA_LABEL_{label}_data[]'
    if source.count(marker) != 1:
        raise ValueError('missing or duplicate bindata label: ' + label)
    start = source.index(marker)
    window = source[max(0, start - 500):start]
    compressed = re.findall(r'COMPRESSION: (YES|NO)', window)
    original_size = re.findall(r'DATA SIZE \(bytes\): (\d+)', window)
    if not compressed or not original_size:
        raise ValueError('missing bindata metadata: ' + label)
    size = int(original_size[-1])
    if not 0 < size <= 16 * 1024 * 1024:
        raise ValueError('bindata decoded size out of range: ' + label)
    match = re.match(re.escape(marker) + r'\s*=\s*\{([^}]*)\};', source[start:], re.S)
    if match is None:
        raise ValueError('malformed bindata declaration: ' + label)
    tokens = [token.strip() for token in match[1].strip().rstrip(',').split(',')]
    if not tokens or any(not re.fullmatch(r'0x[0-9a-fA-F]{1,16}ULL', token) for token in tokens):
        raise ValueError('unexpected NvU64 initializer: ' + label)
    stored_bytes = b''.join(struct.pack('<Q', int(token[2:-3], 16)) for token in tokens)
    if compressed[-1] == 'YES':
        declared = re.findall(r'COMPRESSED SIZE \(bytes\): (\d+)', window)
        if not declared:
            raise ValueError('missing compressed data size: ' + label)
        stored = int(declared[-1])
        if not 0 < stored <= 16 * 1024 * 1024:
            raise ValueError('invalid compressed data size: ' + label)
        if len(stored_bytes) != (stored + 7) // 8 * 8 or any(stored_bytes[stored:]):
            raise ValueError('invalid compressed byte length or U64 alignment padding: ' + label)
        inflater = zlib.decompressobj(-15)
        data = inflater.decompress(stored_bytes[:stored], size + 1)
        if not inflater.eof or inflater.unconsumed_tail or len(inflater.unused_data) != 8:
            raise ValueError('truncated, oversized or malformed compressed bindata: ' + label)
        crc, declared_original = struct.unpack('<II', inflater.unused_data)
        if declared_original != size or crc != zlib.crc32(data):
            raise ValueError('compressed bindata CRC/size mismatch: ' + label)
    else:
        if len(stored_bytes) != (size + 7) // 8 * 8 or any(stored_bytes[size:]):
            raise ValueError('invalid raw byte length or U64 alignment padding: ' + label)
        data = stored_bytes[:size]
    if len(data) != size:
        raise ValueError('decoded bindata size mismatch: ' + label)
    return data


def booter_bundle(source: str) -> bytes:
    image = array_bytes(source, 'IMAGE_PROD')
    header = array_bytes(source, 'HEADER_PROD')
    signatures = array_bytes(source, 'SIG_PROD')
    patch_loc = array_bytes(source, 'PATCH_LOC')
    patch_meta = array_bytes(source, 'PATCH_META')
    num_sigs = array_bytes(source, 'NUM_SIGS')
    if tuple(map(len, (header, patch_loc, patch_meta, num_sigs))) != (36, 4, 12, 4):
        raise ValueError('unexpected Booter metadata geometry')
    fields = struct.unpack('<9I', header)
    loc = struct.unpack('<I', patch_loc)[0]
    _fuse, engine, ucode = struct.unpack('<3I', patch_meta)
    count = struct.unpack('<I', num_sigs)[0]
    if not count or count > 8 or len(signatures) != count * 384 or fields[4] != 1 or not ucode:
        raise ValueError('invalid production Booter signature metadata')
    if loc < fields[2] or loc + 384 > fields[2] + fields[3] or fields[2] + fields[3] > len(image):
        raise ValueError('invalid Booter signature patch location')
    for offset, length in ((fields[0], fields[1]), (fields[2], fields[3]), (fields[5], fields[6])):
        if offset + length > len(image) or offset % 256 or length % 256:
            raise ValueError('invalid Booter Falcon transfer geometry')
    header_bytes = struct.pack('<14I', *fields[:9], loc, ucode, engine, count, len(signatures))
    prefix = struct.pack('<II', MAGIC, 1) + header_bytes + struct.pack('<II', len(image), len(signatures))
    return prefix + image + signatures


def boot_image_pair(source: str) -> tuple[bytes, bytes]:
    image = array_bytes(source, 'UCODE_IMAGE_PROD')
    desc = array_bytes(source, 'UCODE_DESC_PROD')
    if len(desc) != 84:
        raise ValueError('unexpected GSP boot descriptor length')
    fields = struct.unpack('<21I', desc)
    if fields[0] != 5 or fields[14] != 1 or fields[19] != len(image) or fields[20] != 0:
        raise ValueError('unsupported GSP boot descriptor layout')
    for index in (1, 3, 8, 10, 12):
        if not fields[index + 1] or fields[index] + fields[index + 1] > len(image):
            raise ValueError('GSP boot descriptor range exceeds image')
    return image, desc


def extract_source_files(archive: Path) -> dict[str, str]:
    if archive.is_symlink() or not archive.is_file() or archive.name != SOURCE_FILE:
        raise ValueError('not the expected pinned NVIDIA source file')
    if file_digest(archive) != SOURCE_SHA256:
        raise ValueError('official source-archive SHA-256 mismatch')
    expected = {SOURCE_PREFIX + name: name for name in FILENAMES}
    found = {}
    with tarfile.open(archive, 'r:xz') as contents:
        for member in contents:
            if member.name not in expected:
                continue
            if member.name in found or not member.isfile() or not 0 < member.size <= MAX_C_FILE:
                raise ValueError('duplicate or invalid NVIDIA generated source member')
            stream = contents.extractfile(member)
            if stream is None:
                raise ValueError('unreadable NVIDIA generated source member')
            with stream:
                data = stream.read(MAX_C_FILE + 1)
            if len(data) != member.size:
                raise ValueError('NVIDIA source member size mismatch')
            found[member.name] = data.decode('ascii')
    if set(found) != set(expected):
        raise ValueError('missing expected NVIDIA generated source files')
    return {expected[key]: value for key, value in found.items()}


def derive_assets(sources: dict[str, str]) -> dict[str, bytes]:
    result = {}
    for chip in ('ad102', 'ga102'):
        code = chip.upper()
        booter = sources[f'g_bindata_kgspGetBinArchiveBooterLoadUcode_{code}.c']
        boot = sources[f'g_bindata_kgspGetBinArchiveGspRmBoot_{code}.c']
        image, descriptor = boot_image_pair(boot)
        result[f'booter_load_{chip}.bin'] = booter_bundle(booter)
        result[f'gsp_boot_{chip}.bin'] = image
        result[f'gsp_boot_desc_{chip}.bin'] = descriptor
    return result


def compare(archive: Path, reference_root: Path) -> dict:
    # Reuse the original pin table and bounded reader; do not duplicate the
    # reference asset SHA-256 constants or their symlink/race protections.
    verifier_path = HERE.parent / 'profile' / 'verify_secure_assets.py'
    spec = importlib.util.spec_from_file_location('pinned_reference_verifier', verifier_path)
    if spec is None or spec.loader is None:
        raise ValueError('missing pinned reference verifier')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    source = extract_source_files(archive)
    assets = derive_assets(source)
    if set(assets) != set(ASSET_NAMES):
        raise ValueError('unexpected derived asset set')
    records = {}
    for name in ASSET_NAMES:
        reference = reference_root / 'gpu-unlock' / OLD_VERSION / name
        old_sha, old_size = verifier._read_digest(reference)
        if old_sha != verifier.PINS[name]:
            raise ValueError('pinned old reference file differs: ' + name)
        new_sha = sha256(assets[name])
        records[name] = {
            'reference': {'version': OLD_VERSION, 'bytes': old_size, 'sha256': old_sha},
            'candidate': {'version': NEW_VERSION, 'bytes': len(assets[name]), 'sha256': new_sha},
            'byte_identical': new_sha == old_sha and len(assets[name]) == old_size,
        }
    return {
        'schema': 'nvidia-reference-boot-assets-comparison/1',
        'status': 'NEARBY_LINUX_REFERENCE_COMPARISON_COMPLETE',
        'original_reference': OLD_VERSION,
        'comparison_reference': NEW_VERSION,
        'windows_driver_under_investigation': '617.42',
        'windows_gsp_version_observed': '615.78.05',
        'exact_windows_615_78_05_asset_identity_verified': False,
        'source_archive_sha256': SOURCE_SHA256,
        'assets': records,
        'all_six_reference_assets_byte_identical': all(v['byte_identical'] for v in records.values()),
        'firmware_signature_authenticated': False,
        'hardware_tested': False, 'can_detach': False, 'can_unlock': False, 'can_flash': False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-archive', required=True, type=Path)
    parser.add_argument('--reference-root', required=True, type=Path,
                        help='Root containing gpu-unlock/610.43.03/*.bin')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.output.exists() or args.output.is_symlink():
            raise ValueError('refusing to overwrite report')
        report = compare(args.source_archive, args.reference_root)
        with args.output.open('x', encoding='utf-8') as destination:
            destination.write(json.dumps(report, indent=2) + '\n')
        print(f"STATUS=COMPLETE REPORT={args.output} CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false")
        return 0
    except (OSError, ValueError, UnicodeDecodeError, tarfile.TarError, struct.error, zlib.error) as exc:
        print(f'STATUS=ERROR REPORT={args.output} REASON={type(exc).__name__} CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
