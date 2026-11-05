#!/usr/bin/env python3
"""Read-only Windows NVIDIA GSP ELF + NVUCODES structural inventory.

Does not extract, modify, execute, load, patch, stage, or validate signatures.
The NVIDIA R615 BINDATA_UCODES_BIN_HEADER is used for only the first 24 bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

UCODES_HEADER = struct.Struct('<8sIIQ')
ELF_HEADER_FIELDS = struct.Struct('<HHIQQQIHHHHHH')
ELF_SECTION = struct.Struct('<IIQQQQIIQQ')
MAX_SECTIONS = 4096
MAX_STRTAB = 16 * 1024 * 1024


def _checked_file(path: Path) -> int:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'not a regular file: {path}')
    size = path.stat().st_size
    if size < 24 or size > 512 * 1024 * 1024:
        raise ValueError(f'invalid file size: {path}')
    return size


def _sha256(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open('rb') as src:
        for block in iter(lambda: src.read(1024 * 1024), b''):
            sha.update(block)
    return sha.hexdigest()


def _range(start: int, length: int, limit: int) -> bool:
    return 0 <= start <= limit and 0 <= length <= limit - start


def _read_at(stream, off: int, size: int) -> bytes:
    stream.seek(off)
    data = stream.read(size)
    if len(data) != size:
        raise ValueError('firmware file changed while reading')
    return data


def inspect_gsp(path: Path) -> dict:
    size = _checked_file(path)
    with path.open('rb') as f:
        header = _read_at(f, 0, 64)
        if header[:4] != b'\x7fELF' or header[4:7] != b'\x02\x01\x01':
            raise ValueError('expected little-endian ELF64 GSP')
        (e_type, e_machine, e_version, _entry, _phoff, shoff, _flags,
         ehsize, _phentsize, _phnum, shentsize, shnum, shstrndx) = ELF_HEADER_FIELDS.unpack_from(header, 16)
        if (e_type != 1 or e_machine != 243 or e_version != 1 or ehsize != 64
                or shentsize != ELF_SECTION.size or not 1 <= shnum <= MAX_SECTIONS
                or not 0 <= shstrndx < shnum or not _range(shoff, shnum * shentsize, size)):
            raise ValueError('invalid or unsupported RISC-V ELF64 section table')
        shdr_data = _read_at(f, shoff, shnum * shentsize)
        sections = [ELF_SECTION.unpack_from(shdr_data, i * shentsize) for i in range(shnum)]
        name_section = sections[shstrndx]
        if (name_section[1] != 3 or name_section[5] > MAX_STRTAB
                or not _range(name_section[4], name_section[5], size)):
            raise ValueError('invalid ELF section name table')
        names = _read_at(f, name_section[4], name_section[5])
        result = []
        for i, (nameoff, typ, _flags, _addr, off, length, _link, _info, _align, _entsize) in enumerate(sections):
            if nameoff >= len(names):
                raise ValueError(f'invalid ELF section name index {i}')
            end = names.find(b'\0', nameoff)
            if end < 0:
                raise ValueError(f'unterminated ELF section name {i}')
            if typ != 8 and not _range(off, length, size):
                raise ValueError(f'ELF section {i} extends beyond firmware')
            result.append({'index': i, 'name': names[nameoff:end].decode('ascii', errors='replace'),
                           'type': typ, 'offset': off, 'size': length})
    return {'format': 'ELF64_LE_RISCV_ET_REL', 'bytes': size, 'sha256': _sha256(path),
            'section_header_offset': shoff, 'section_header_count': shnum,
            'section_name_table_index': shstrndx, 'sections': result}


def inspect_ucodes(path: Path) -> dict:
    size = _checked_file(path)
    with path.open('rb') as f:
        magic, version, count, fingerprint = UCODES_HEADER.unpack(_read_at(f, 0, UCODES_HEADER.size))
    if magic != b'NVUCODES' or version != 1 or count == 0 or count > 65536:
        raise ValueError('invalid or unsupported NVUCODES header')
    return {'format': 'NVUCODES', 'bytes': size, 'sha256': _sha256(path),
            'header_bytes': UCODES_HEADER.size, 'format_version': version,
            'declared_bindata_entries': count, 'filename_index_fingerprint': f'0x{fingerprint:016x}',
            'records_parsed': False}


def inspect_pair(gsp: Path, ucodes: Path, package_dir: Path | None = None) -> dict:
    gsp_info = inspect_gsp(gsp)
    ucodes_info = inspect_ucodes(ucodes)
    output = {'schema': 'nvidia-windows-gsp-container-inventory/1',
              'gsp': gsp_info, 'ucodes': ucodes_info,
              'source': 'user-supplied file paths',
              'firmware_signature_verified': False,
              'gsp_ucodes_pair_accepted_by_driver': False,
              'hardware_tested': False, 'can_unlock': False, 'can_flash': False}
    if package_dir is not None:
        package_files = {'gsp': package_dir / 'gsp_ga10x.bin',
                         'ucodes': package_dir / 'ucodes_ga10x.bin'}
        comparison = {}
        for key, candidate in package_files.items():
            candidate_bytes = _checked_file(candidate)
            ref = output[key]
            comparison[key] = {'same_size': candidate_bytes == ref['bytes'],
                               'same_sha256': _sha256(candidate) == ref['sha256']}
        output['package_comparison'] = comparison
        output['package_files_identical'] = all(x['same_size'] and x['same_sha256'] for x in comparison.values())
    else:
        output['package_files_identical'] = None
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gsp', required=True, type=Path)
    parser.add_argument('--ucodes', required=True, type=Path)
    parser.add_argument('--package-dir', type=Path, help='optional extracted original Display.Driver folder')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.output.exists() or args.output.is_symlink():
            raise ValueError('output already exists; choose a new report path')
        report = inspect_pair(args.gsp, args.ucodes, args.package_dir)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        status = 'PARTIAL' if report['package_files_identical'] is False else 'COMPLETE'
        print(f'STATUS={status} REPORT={args.output} CAN_UNLOCK=false CAN_FLASH=false')
        return 2 if status == 'PARTIAL' else 0
    except (OSError, ValueError, struct.error) as exc:
        print(f'STATUS=ERROR REPORT={args.output} REASON={exc} CAN_UNLOCK=false CAN_FLASH=false')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
