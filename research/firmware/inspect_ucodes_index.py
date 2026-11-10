#!/usr/bin/env python3
"""Read-only index inventory for the pinned Windows 617.42 GA10x NVUCODES file.

The 24-byte index entry layout is corroborated by the original Windows GSP
RISC-V reader at 0x01AD1544-0x01AD1572. This tool does not identify Booter
labels, validate signatures, or authorize GPU, driver, or firmware actions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

HEADER = struct.Struct('<8sIIQ')
ENTRY = struct.Struct('<IIQII')  # actualSize, compressedSize, pData, flags, relOffset
WINDOWS_61742_SHA256 = 'eed53d76248582d71c629e8b6230aee48ce673c91d782301c94e98ac6a6db7aa'
WINDOWS_61742_FINGERPRINT = 0x2D38BEFECDB703A6
WINDOWS_61742_COUNT = 1293
MAX_SOURCE_BYTES = 512 * 1024 * 1024
MAX_INDICES = 65536


def inspect_index(data: bytes, *, expected_count: int, expected_fingerprint: int) -> dict:
    """Verify indexed on-disk extents. Never decode or execute record contents."""
    size = len(data)
    if not HEADER.size <= size <= MAX_SOURCE_BYTES:
        raise ValueError('invalid archive length')
    magic, version, count, fingerprint = HEADER.unpack_from(data)
    if (magic != b'NVUCODES' or version != 1 or count != expected_count
            or not 1 <= count <= MAX_INDICES or fingerprint != expected_fingerprint):
        raise ValueError('archive header differs from pinned index contract')
    table_end = HEADER.size + count * ENTRY.size
    if table_end > size:
        raise ValueError('truncated index table')

    records = []
    for index in range(count):
        actual, compressed, pointer, flags, offset = ENTRY.unpack_from(data, HEADER.size + index * ENTRY.size)
        if flags == 0:
            if actual or compressed or pointer or offset:
                raise ValueError(f'index {index}: nonempty fields in empty entry')
            continue
        if flags != 0x04:
            raise ValueError(f'index {index}: unsupported storage flags')
        if (actual == 0 or compressed != 0 or pointer != 0 or offset < table_end
                or offset % 256 != 0 or actual > size - offset):
            raise ValueError(f'index {index}: invalid external extent')
        records.append({'index': index, 'offset': offset, 'bytes': actual,
                        'sha256': hashlib.sha256(data[offset:offset + actual]).hexdigest()})

    if not records:
        raise ValueError('no external records found')
    cursor = table_end
    for record in sorted(records, key=lambda record: record['offset']):
        start = record['offset']
        if start < cursor:
            raise ValueError('overlapping external record ranges')
        if any(data[cursor:start]):
            raise ValueError('nonzero bytes outside indexed record ranges')
        cursor = start + record['bytes']
    if any(data[cursor:]):
        raise ValueError('nonzero trailing bytes outside record ranges')

    return {
        'schema': 'nvidia-windows-61742-nvucodes-index/1',
        'status': 'STATIC_INDEX_EXTENTS_VALID',
        'sha256': hashlib.sha256(data).hexdigest(),
        'bytes': size,
        'header_bytes': HEADER.size,
        'index_entry_bytes': ENTRY.size,
        'index_count': count,
        'index_end_offset': table_end,
        'fingerprint': f'0x{fingerprint:016x}',
        'external_records': len(records),
        'empty_indices': count - len(records),
        'records': records,
        'labels_mapped': False,
        'signed_booter_identified': False,
        'signature_authenticated': False,
        'runtime_accepted': False,
        'can_detach': False,
        'can_unlock': False,
        'can_flash': False,
        'recovery_verified': False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ucodes', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.ucodes.is_symlink() or not args.ucodes.is_file():
            raise ValueError('input is not a regular file')
        if args.output.exists() or args.output.is_symlink():
            raise ValueError('output exists; select a new report path')
        with args.ucodes.open('rb') as src:
            data = src.read(MAX_SOURCE_BYTES + 1)
        if hashlib.sha256(data).hexdigest() != WINDOWS_61742_SHA256:
            raise ValueError('source SHA-256 does not match original Windows 617.42 NVUCODES')
        result = inspect_index(data, expected_count=WINDOWS_61742_COUNT,
                               expected_fingerprint=WINDOWS_61742_FINGERPRINT)
        # Detect changes between source read and report publication.
        if args.ucodes.stat().st_size != len(data):
            raise ValueError('source length changed while inspecting')
        with args.ucodes.open('rb') as src:
            digest = hashlib.sha256()
            for chunk in iter(lambda: src.read(1024 * 1024), b''):
                digest.update(chunk)
        if digest.hexdigest() != result['sha256']:
            raise ValueError('source bytes changed while inspecting')
        with args.output.open('x', encoding='utf-8') as output:
            json.dump(result, output, indent=2)
            output.write('\n')
        print(f"STATUS=COMPLETE REPORT={args.output} EXTERNAL_RECORDS={result['external_records']} "
              'CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false')
        return 0
    except (OSError, ValueError, struct.error) as exc:
        print(f'STATUS=ERROR REPORT={args.output} REASON={exc} '
              'CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
