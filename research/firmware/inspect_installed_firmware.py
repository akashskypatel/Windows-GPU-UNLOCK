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
    # The version string and per-architecture signature *bytes* are useful
    # for cross-release comparison. Neither authenticates a signature.
    section_by_name = {entry['name']: entry for entry in result}
    fwversion = None
    fwversion_bytes = None
    version_section = section_by_name.get('.fwversion')
    if version_section is not None and version_section['type'] != 8:
        if version_section['size'] > 256:
            raise ValueError('oversized GSP .fwversion section')
        with path.open('rb') as f:
            raw = _read_at(f, version_section['offset'], version_section['size'])
        fwversion_bytes = raw.hex()
        # Preserve raw bytes when the firmware version is not ASCII.
        fwversion = raw.rstrip(b'\x00').decode('ascii', errors='replace')

    signatures = {}
    with path.open('rb') as f:
        for entry in result:
            if not entry['name'].startswith('.fwsignature_') or entry['type'] == 8:
                continue
            name = entry['name']
            if name in signatures:
                raise ValueError('duplicate GSP firmware signature section')
            if entry['size'] > 64 * 1024:
                raise ValueError('oversized GSP signature section')
            data = _read_at(f, entry['offset'], entry['size'])
            signatures[name] = {'bytes': entry['size'], 'sha256': hashlib.sha256(data).hexdigest()}

    return {'format': 'ELF64_LE_RISCV_ET_REL', 'bytes': size, 'sha256': _sha256(path),
            'section_header_offset': shoff, 'section_header_count': shnum,
            'section_name_table_index': shstrndx, 'sections': result,
            'fwversion': fwversion, 'fwversion_raw_hex': fwversion_bytes,
            'signature_section_digests': signatures,
            'signature_sections_authenticated': False}


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


def _find_fingerprint_in_fwimage(path: Path, gsp_info: dict, fingerprint: bytes) -> dict:
    """Count raw bytes within the ELF .fwimage section, never outside it."""
    images = [section for section in gsp_info['sections'] if section['name'] == '.fwimage']
    if not images:
        return {'search_performed': False, 'reason': 'no .fwimage section',
                'occurrences': None, 'first_file_offset': None,
                'first_fwimage_relative_offset': None, 'unique_occurrence': False}
    if len(images) != 1 or images[0]['type'] == 8:
        raise ValueError('ambiguous or non-file-backed GSP .fwimage section')
    section = images[0]
    first = None
    occurrences = 0
    remaining = section['size']
    absolute = section['offset']
    overlap = b''
    with path.open('rb') as stream:
        stream.seek(absolute)
        while remaining:
            data = stream.read(min(1024 * 1024, remaining))
            if not data:
                raise ValueError('GSP file changed while scanning firmware fingerprint')
            chunk = overlap + data
            start = absolute - len(overlap)
            pos = chunk.find(fingerprint)
            while pos != -1:
                occurrences += 1
                if first is None:
                    first = start + pos
                pos = chunk.find(fingerprint, pos + 1)
            overlap = chunk[-(len(fingerprint) - 1):]
            absolute += len(data)
            remaining -= len(data)
    return {'search_performed': True, 'occurrences': occurrences,
            'first_file_offset': first,
            'first_fwimage_relative_offset': first - section['offset'] if first is not None else None,
            'unique_occurrence': occurrences == 1}


def inspect_pair(gsp: Path, ucodes: Path, package_dir: Path | None = None) -> dict:
    gsp_info = inspect_gsp(gsp)
    ucodes_info = inspect_ucodes(ucodes)
    fingerprint = bytes.fromhex(ucodes_info['filename_index_fingerprint'][2:])[::-1]
    pairing = _find_fingerprint_in_fwimage(gsp, gsp_info, fingerprint)
    pairing['fingerprint_hex'] = ucodes_info['filename_index_fingerprint']
    pairing['runtime_pairing_verified'] = False
    output = {'schema': 'nvidia-windows-gsp-container-inventory/1',
              'gsp': gsp_info, 'ucodes': ucodes_info,
              'static_fingerprint_comparison': pairing,
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
