#!/usr/bin/env python3
"""Offline exact-card GOP evidence gate; NEVER authorizes firmware release/unlock.

Reuses the existing diagnostic, console ownership and PE capture validators.
No GPU/UEFI operations, firmware modification, active profile generation, or ROM writes.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
from pathlib import Path

EXPECTED = {
    '0000:01:00.0': {
        'pci_id': '10de:2684', 'subsystem': '1043:88e6',
        'text_sha256': '77632902f0ceb0ba2848200f396ab61eacd7910e9cce7c535f65d6cdbe2b6c32',
        'text_bytes': 137711, 'stop_rva': '0x6ec', 'nvgop_name': 'nvgop-ad1xx',
        'context_pci_id': '268410de',
    },
    '0000:04:00.0': {
        'pci_id': '10de:220a', 'subsystem': '19da:b612',
        'text_sha256': '615b37a708b1894e18d7fa60cfcdacaa4d8b598863a10b8103d231a595847b2b',
        'text_bytes': 134451, 'stop_rva': '0x678', 'nvgop_name': 'nvgop-ga1xx',
        'context_pci_id': '220a10de',
    },
}
REQUIRED_FIELDS = ('driver_identity_ok', 'image_dump_ok', 'begin', 'text_hash_match',
                   'protocol_status', 'memory_map_status', 'snapshot_complete',
                   'context', 'context_handle', 'context_pci_io', 'device',
                   'adapter', 'embedded', 'device_vtable', 'adapter_vtable',
                   'embedded_vtable', 'reset_flag_98')
FIELD_RE = re.compile(r'^nvgop-context-v1 pci-id=0x([0-9a-f]{8}) ([a-z_0-9]+)=0x([0-9a-f]{16})$')


class Refused(ValueError):
    pass


def load_report(profile_dir: Path):
    path = profile_dir / 'report-nvgop-evidence.py'
    spec = importlib.util.spec_from_file_location('exact_machine_nvgop_report', path)
    if not spec or not spec.loader:
        raise Refused('existing NVIDIA evidence validator unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_snapshot(source: str):
    rows = {}
    for line in source.splitlines():
        if not line.startswith('nvgop-context-v1 '):
            continue
        match = FIELD_RE.fullmatch(line)
        if not match:
            raise Refused('malformed NVIDIA controller snapshot record')
        chip, field, value = match.groups()
        if chip not in {profile['context_pci_id'] for profile in EXPECTED.values()}:
            raise Refused('unexpected NVIDIA context PCI ID')
        if field in rows.setdefault(chip, {}):
            raise Refused('duplicate NVIDIA context snapshot field')
        rows[chip][field] = int(value, 16)
    if len(rows) != len(EXPECTED):
        raise Refused('both NVIDIA controller snapshots required')
    result = {}
    for bdf, expected in EXPECTED.items():
        fields = rows[expected['context_pci_id']]
        if any(name not in fields for name in REQUIRED_FIELDS):
            raise Refused('incomplete NVIDIA controller snapshot')
        if any(fields[name] != 1 for name in ('driver_identity_ok', 'image_dump_ok', 'begin',
                                              'text_hash_match', 'snapshot_complete')):
            raise Refused('NVIDIA controller capture failed identity or completion checks')
        if fields['protocol_status'] or fields['memory_map_status']:
            raise Refused('NVIDIA private-protocol or memory-map read failed')
        if any(fields[name] == 0 for name in ('context', 'context_handle', 'context_pci_io',
                                              'device', 'adapter', 'embedded',
                                              'device_vtable', 'adapter_vtable', 'embedded_vtable')):
            raise Refused('missing required live NVIDIA object')
        result[bdf] = {
            'snapshot_complete': True,
            'reset_flag_98': fields['reset_flag_98'],
            'live_objects_observed': True,
            'address_lifetime': 'THIS_BOOT_ONLY',
        }
    return result


def assemble(source: bytes, evidence: dict) -> dict:
    try:
        decoded = source.decode('utf-8-sig').replace('\r\n', '\n')
    except UnicodeDecodeError as exc:
        raise Refused('diagnostic is not UTF-8') from exc
    lines = decoded.splitlines()
    if lines.count('capture-complete=1') != 1 or \
       len([line for line in lines if line.startswith('capture-complete=')]) != 1 or \
       lines.count('diagnostic-result status=0x0000000000000000') != 1 or \
       len([line for line in lines if line.startswith('diagnostic-result status=')]) != 1:
        raise Refused('diagnostic capture or result incomplete')
    if evidence.get('status') != 'captured_loaded_text_fingerprints' or not evidence.get('amd_console_observed'):
        raise Refused('upstream GOP image and AMD console evidence did not pass')
    captured = evidence.get('images')
    if not isinstance(captured, list) or len(captured) != len(EXPECTED):
        raise Refused('expected exactly two NVIDIA image reports')
    by_bdf = {entry.get('bdf'): entry for entry in captured if isinstance(entry, dict)}
    if len(by_bdf) != len(EXPECTED) or set(by_bdf) != set(EXPECTED):
        raise Refused('NVIDIA code image BDF set mismatch')
    live = check_snapshot(decoded)
    cards = []
    for bdf, expected in EXPECTED.items():
        image = by_bdf[bdf]
        for key in ('pci_id', 'text_sha256', 'text_bytes', 'stop_rva', 'nvgop_name'):
            if image.get(key) != expected[key]:
                raise Refused(f'{bdf} captured {key} differs from this machine\'s pinned value')
        if image.get('text_relocations') != 0 or image.get('text_rva') != '0x280':
            raise Refused(f'{bdf} executable text region not the pinned layout')
        cards.append({
            'bdf': bdf, 'pci_id': expected['pci_id'],
            'subsystem': expected['subsystem'],
            'nvgop_name': expected['nvgop_name'],
            'text_sha256': image['text_sha256'],
            'loaded_image_sha256': image['loaded_image_sha256'],
            'stop_rva': image['stop_rva'], **live[bdf],
        })
    return {
        'schema': 'exact-machine-gop-evidence/1',
        'status': 'MATCHED_PASSIVE_GOP_EVIDENCE',
        'diagnostic_sha256': evidence['diagnostic_sha256'],
        'cards': cards,
        'amd_console_observed': True,
        'missing_active_provenance': [
            'Exact-card complete flashable VBIOS backups: NOT_VERIFIED',
            'Per-card PROM and cold-state hardware admission: NOT_VERIFIED',
            'GA102 signed assets, V67/FWSEC and local board profile: NOT_VERIFIED',
            'AD102 Windows EFI port, signed assets and payload: NOT_IMPLEMENTED',
            'Physical NVIDIA GOP Stop/recovery and stock Windows handoff: NOT_TESTED',
        ],
        'can_detach': False, 'can_unlock': False,
        'hardware_unlock_tested': False,
        'writes_gpu_registers': False,
        'tool_writes_nonvolatile_firmware': False,
        'recovery_verified': False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('diagnostic', type=Path)
    p.add_argument('--images', type=Path, help='IMGnn.BIN directory (default: diagnostic directory)')
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    base = Path(__file__).resolve().parent
    try:
        validate = load_report(base)
        data = validate._read_bounded(args.diagnostic, validate.MAX_DIAG)
        evidence = validate.analyze(data, args.images or args.diagnostic.parent, base)
        report = assemble(data, evidence)
    except (Refused, ValueError, OSError) as exc:
        p.error(f'exact-machine evidence refused: {exc}')
    rendered = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(rendered, encoding='utf-8')
        print(f'STATUS=COMPLETE REPORT={args.output} CAN_UNLOCK=false CAN_DETACH=false')
    else:
        print(rendered, end='')


if __name__ == '__main__':
    main()
