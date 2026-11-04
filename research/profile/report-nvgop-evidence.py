#!/usr/bin/env python3
"""Verify a passive dual-NVIDIA GOP image capture against its own diagnostic.

This authenticates a capture's internal consistency, not NVIDIA authorship,
firmware Stop() behavior, driver-release safety or unlock eligibility.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path

MAX_DIAG = 8 * 1024 * 1024
MAX_IMAGE = 4 * 1024 * 1024
ROW = re.compile(
    r'nvgop-evidence-v1 bdf-seg=0x([0-9a-f]{4}) bus=0x([0-9a-f]{2}) '
    r'pci-id=0x([0-9a-f]{8}) image-index=0x([0-9a-f]{2}) '
    r'loaded-image-sha256=([0-9a-f]{64})'
)


class Refused(ValueError):
    pass


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise Refused(f'missing source parser: {path.name}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_bounded(path: Path, bound: int):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= bound:
        raise Refused(f'missing, symlinked or oversized evidence: {path.name}')
    with path.open('rb') as stream:
        data = stream.read(bound + 1)
    if not 0 < len(data) <= bound:
        raise Refused(f'evidence changed size or exceeded bound: {path.name}')
    return data


def analyze(diagnostic: bytes, images: Path, profile_dir: Path):
    if len(diagnostic) > MAX_DIAG:
        raise Refused('diagnostic exceeds size limit')
    try:
        source = diagnostic.decode('utf-8-sig').replace('\r\n', '\n')
    except UnicodeDecodeError as exc:
        raise Refused('diagnostic is not UTF-8 text') from exc
    verify = _load(profile_dir / 'verify-console-survivor.py', 'gu_nvgop_survivor')
    graph = _load(profile_dir / 'capture_graph.py', 'gu_nvgop_graph')
    pe = _load(profile_dir / 'make-profile.py', 'gu_nvgop_pe')
    try:
        survivor, _, _, _ = verify.inspect(source, graph.parse_handles)
    except ValueError as exc:
        raise Refused(f'AMD-console observation not accepted: {exc}') from exc
    if survivor['status'] != 'observed_amd_only_console':
        raise Refused('AMD-console observation was not established')

    entries = [line for line in source.splitlines() if line.startswith('nvgop-evidence-v1 ')]
    if len(entries) != 2:
        raise Refused('exactly two NVIDIA image evidence records required')
    seen, indices, rows = set(), set(), []
    if images.is_symlink() or not images.is_dir():
        raise Refused('invalid or symlinked evidence directory')
    for line in entries:
        m = ROW.fullmatch(line)
        if not m:
            raise Refused('malformed NVIDIA image evidence record')
        seg, bus, ident, index, expected_sha = m.groups()
        bdf = f'{int(seg, 16):04x}:{int(bus, 16):02x}:00.0'
        if bdf not in verify.TARGETS or bdf in seen or index in indices:
            raise Refused('duplicate or unrecognized NVIDIA image mapping')
        seen.add(bdf)
        indices.add(index)
        config = verify.EXPECTED[bdf]
        if int(ident, 16) != config[0]:
            raise Refused('evidence record does not match PCI identity')
        path = images / f'IMG{int(index, 16):02d}.BIN'
        data = _read_bounded(path, MAX_IMAGE)
        if len(data) != config[5] or hashlib.sha256(data).hexdigest() != expected_sha:
            raise Refused(f'{path.name} does not match signed diagnostic image bytes')
        try:
            sections, reloc_rva, reloc_len = pe.pe_sections(data)
            matching = [section for section in sections if section[0] == '.text']
            if len(matching) != 1:
                raise Refused('not exactly one .text section in loaded NVIDIA image')
            name, rva, size, flags = matching[0]
            if not size or not flags & 0x20000000 or not rva <= config[6] < rva + size:
                raise Refused('vendor Stop offset is outside executable .text')
            relocations = pe.relocations(data, reloc_rva, reloc_len)
            if any(start < rva + size and rva < start + width for start, width in relocations):
                raise Refused('loaded .text includes relocations; hash would be load-dependent')
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            raise Refused(f'invalid loaded PE image {path.name}: {exc}') from exc
        rows.append({
            'bdf': bdf, 'pci_id': f'{config[0] & 0xffff:04x}:{config[0] >> 16:04x}',
            'nvgop_name': config[4], 'file': path.name,
            'loaded_image_sha256': expected_sha, 'text_rva': f'0x{rva:x}',
            'text_bytes': size, 'text_sha256': hashlib.sha256(data[rva:rva+size]).hexdigest(),
            'stop_rva': f'0x{config[6]:x}', 'text_relocations': 0,
        })
    if seen != set(verify.TARGETS):
        raise Refused('one or more NVIDIA code images are missing')
    return {
        'schema': 'offline-nvgop-text-evidence/1',
        'status': 'captured_loaded_text_fingerprints',
        'diagnostic_sha256': hashlib.sha256(diagnostic).hexdigest(),
        'amd_console_observed': True,
        'images': sorted(rows, key=lambda item: item['bdf']),
        'vendor_code_authenticity_verified': False,
        'vendor_stop_behavior_verified': False,
        'recovery_after_release_verified': False,
        'can_detach': False, 'can_unlock': False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('diagnostic', type=Path)
    p.add_argument('--images', type=Path, help='IMGnn.BIN directory (default: diagnostic directory)')
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    profile_dir = Path(__file__).resolve().parent
    try:
        content = _read_bounded(args.diagnostic, MAX_DIAG)
        result = analyze(content, args.images or args.diagnostic.parent, profile_dir)
    except (Refused, OSError) as exc:
        p.error(f'code evidence refused: {exc}')
    output = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(output, encoding='utf-8')
    else:
        print(output, end='')


if __name__ == '__main__':
    main()
