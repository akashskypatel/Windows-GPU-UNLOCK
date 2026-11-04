#!/usr/bin/env python3
"""Redacted, observation-only report from the extended generic UEFI diagnostic.

GPL-2.0-only. No hardware, firmware, profile-generation, or boot operations.
This is deliberately not a hardware unlock eligibility checker.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
from pathlib import Path

MAX_INPUT = 8 * 1024 * 1024
MAX_DEVICES = 64
GOP = '9042a9de-23dc-4a38-96fb-7aded080516a'
PCI = '4cf5b200-68b8-4ca5-9eec-b23e3f50029a'
EDID_DISCOVERED = '1c0c34f6-d380-41fa-a049-8ad06c1a66aa'
EDID_ACTIVE = 'bd8c1056-9f36-44ec-92a8-a6337f817986'
SUCCESS = '0' * 16

FIELDS = [
    'seg', 'bus', 'dev', 'fun', 'id', 'class', 'subsystem', 'command',
    'loc-status', 'config-status', 'repeat-status', 'attrs-status', 'attrs',
    'supported-status', 'supported', 'path-status', 'stable', 'duplicate'
]
HEX = re.compile(r'^0x[0-9a-f]+$')
START = 'probe-inventory-v2 begin'
END_RE = re.compile(r'^probe-inventory-v2 end displays=0x([0-9a-f]+) failures=0x([0-9a-f]+) complete=([01])$')
CONSOLE_RE = re.compile(r'^console out=0x([0-9a-f]+) error=0x([0-9a-f]+) input=0x([0-9a-f]+)$')
BDF_RE = re.compile(r'\bpci location-status=0x([0-9a-f]+) segment=0x([0-9a-f]+) bus=0x([0-9a-f]+) device=0x([0-9a-f]+) function=0x([0-9a-f]+)')


class DiagnosticError(ValueError):
    pass


def match_expected_pair(devices: list[dict], expected_pci_ids: tuple[str, str], complete: bool) -> dict:
    """Evidence of two observed PCI identities, never unlock or detach authorization."""
    if len(expected_pci_ids) != 2 or any(not re.fullmatch(r'10de:[0-9a-f]{4}', pci) for pci in expected_pci_ids):
        raise DiagnosticError('expected exactly two NVIDIA vendor:device identifiers')
    nvidia = [device for device in devices if device['pci_id'].startswith('10de:')]
    matched = (complete and len(nvidia) == 2 and
               all(device['status'] == 'observed_stable' for device in nvidia) and
               len({device['bdf'] for device in nvidia}) == 2 and
               sorted(device['pci_id'] for device in nvidia) == sorted(expected_pci_ids))
    return {
        'status': 'observed_pci_pair' if matched else 'unverified',
        'expected_pci_ids': list(expected_pci_ids),
        'devices': [{'pci_id': device['pci_id'], 'bdf': device['bdf']}
                    for device in sorted(nvidia, key=lambda item: item['bdf'])] if matched else [],
        'can_unlock': False,
        'can_detach': False,
    }


def parse_display(line: str) -> dict:
    if not line.startswith('probe-display-v2 '):
        raise DiagnosticError('not a display observation')
    tokens = line.split()[1:]
    if len(tokens) != len(FIELDS):
        raise DiagnosticError('wrong display field count')
    values = {}
    for token, field in zip(tokens, FIELDS):
        if '=' not in token:
            raise DiagnosticError('malformed display field')
        k, raw = token.split('=', 1)
        if k != field or not HEX.fullmatch(raw) and field not in ('stable', 'duplicate'):
            raise DiagnosticError('malformed display field')
        if field in ('stable', 'duplicate') and raw not in ('0', '1'):
            raise DiagnosticError('invalid display boolean')
        values[field] = int(raw, 16) if field not in ('stable', 'duplicate') else int(raw)
    if not (0 <= values['seg'] <= 0xffff and 0 <= values['bus'] <= 255
            and 0 <= values['dev'] <= 31 and 0 <= values['fun'] <= 7):
        raise DiagnosticError('invalid PCI location')
    if values['id'] > 0xffffffff or values['class'] > 0xffffffff or values['subsystem'] > 0xffffffff:
        raise DiagnosticError('invalid PCI identity')
    if values['class'] >> 24 != 3:
        raise DiagnosticError('non-display in display inventory')
    if any(values[k] > 0xffffffffffffffff for k in FIELDS if k.endswith('status')):
        raise DiagnosticError('oversized EFI status')
    if values['command'] > 0xffff or values['attrs'] > 0xffffffffffffffff or values['supported'] > 0xffffffffffffffff:
        raise DiagnosticError('invalid PCI attributes')
    valid = all(values[k] == 0 for k in ('loc-status', 'config-status', 'repeat-status', 'attrs-status', 'supported-status', 'path-status'))
    valid &= values['stable'] == 1 and values['duplicate'] == 0
    return {
        'bdf': f"{values['seg']:04x}:{values['bus']:02x}:{values['dev']:02x}.{values['fun']}",
        'pci_id': f"{values['id'] & 0xffff:04x}:{(values['id'] >> 16) & 0xffff:04x}",
        'class_revision': f"{values['class']:08x}",
        'subsystem': f"{values['subsystem']:08x}" if values['config-status'] == 0 else None,
        'command': f"{values['command']:04x}" if values['config-status'] == 0 else None,
        'attributes': f"{values['attrs']:016x}" if values['attrs-status'] == 0 else None,
        'supported_attributes': f"{values['supported']:016x}" if values['supported-status'] == 0 else None,
        'status': 'observed_stable' if valid else 'incomplete',
        'failed_stages': [k for k in ('loc-status', 'config-status', 'repeat-status', 'attrs-status', 'supported-status', 'path-status') if values[k] != 0] +
                         (['unstable_config'] if not values['stable'] else []) +
                         (['duplicate_bdf'] if values['duplicate'] else []),
    }


def load_graph_parser(repo: Path):
    path = repo / 'research/profile/capture_graph.py'
    if not path.is_file():
        raise DiagnosticError('upstream capture_graph.py missing')
    spec = importlib.util.spec_from_file_location('dual_capture_graph', path)
    if spec is None or spec.loader is None:
        raise DiagnosticError('upstream capture_graph.py unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.parse_handles


def summarise(source: str, parse_handles, *, boot_origin: str = 'unknown',
              expected_pci_ids: tuple[str, str] | None = None) -> dict:
    if len(source.encode('utf-8')) > MAX_INPUT:
        raise DiagnosticError('diagnostic exceeds size limit')
    lines = source.splitlines()
    starts = [i for i, x in enumerate(lines) if x == START]
    ends = [(i, END_RE.fullmatch(x)) for i, x in enumerate(lines) if x.startswith('probe-inventory-v2 end')]
    if len(starts) != 1 or len(ends) != 1 or ends[0][1] is None or starts[0] >= ends[0][0]:
        raise DiagnosticError('inventory section missing or repeated')
    start, end = starts[0], ends[0][0]
    records = [line for line in lines[start+1:end] if line.startswith('probe-display-v2 ')]
    if any(line.startswith('probe-display-v2 ') for line in lines[:start] + lines[end+1:]):
        raise DiagnosticError('out-of-section display observation')
    if not 0 <= len(records) <= MAX_DEVICES:
        raise DiagnosticError('display inventory exceeds bound')
    declared, failures, complete = (int(ends[0][1][i], 16) if i < 2 else int(ends[0][1][i]) for i in (1, 2, 3))
    if len(records) != declared:
        raise DiagnosticError('display inventory count mismatch')
    devices = [parse_display(row) for row in records]
    bdfs = [d['bdf'] for d in devices]
    if len(bdfs) != len(set(bdfs)):
        raise DiagnosticError('duplicate PCI BDF')
    device_failures = sum(d['status'] != 'observed_stable' for d in devices)
    if failures != device_failures:
        raise DiagnosticError('inconsistent failure summary')
    if complete and (failures or device_failures):
        raise DiagnosticError('false complete inventory')
    if not complete and not failures and not device_failures:
        # A different (non-display) PCI handle may have failed identity discovery.
        pass
    if len([line for line in lines if line.startswith('capture-complete=')]) != 1:
        raise DiagnosticError('capture completion marker not unique')
    if len([line for line in lines if line.startswith('diagnostic-result status=')]) != 1:
        raise DiagnosticError('diagnostic status marker not unique')
    graph = {}
    graph_error = None
    try:
        graph = parse_handles(source)
    except (ValueError, KeyError, TypeError) as exc:
        graph_error = type(exc).__name__  # redact raw diagnostic content
    if not complete or failures or device_failures:
        graph_error = graph_error or 'inventory_incomplete'
    # Prevent cross-record matches by requiring a full line.
    consoles = [CONSOLE_RE.fullmatch(line) for line in lines if line.startswith('console out=')]
    console_handle = int(consoles[0][1], 16) if len(consoles) == 1 and consoles[0] is not None else None
    if console_handle is None:
        graph_error = graph_error or 'console_handle_unavailable'
    gops = []
    direct = []
    for handle, block in graph.items():
        protocols = block['protocols']
        if GOP not in protocols:
            continue
        device_bdf = None
        if PCI in protocols:
            matches = BDF_RE.findall(block['raw'])
            if len(matches) == 1 and int(matches[0][0], 16) == 0:
                _, s, b, d, f = matches[0]
                device_bdf = f'{int(s,16):04x}:{int(b,16):02x}:{int(d,16):02x}.{int(f,16)}'
        is_console = handle == console_handle
        if is_console and device_bdf in bdfs:
            direct.append(device_bdf)
        gops.append({
            'handle_ref': f'gop-{len(gops)}',
            'console_handle_match': is_console,
            'same_handle_pci_bdf': device_bdf if device_bdf in bdfs else None,
            'edid_discovered_protocol': EDID_DISCOVERED in protocols,
            'edid_active_protocol': EDID_ACTIVE in protocols,
        })
    # Parent-baseline observations are explicitly scoped by preceding GPU keys.
    # Missing ancestry is not evidence that a GPU has no PCI parent.
    parent_reports = []
    parent_header = re.compile(r'^probe-parent-v2 seg=0x([0-9a-f]+) bus=0x([0-9a-f]+) id=0x([0-9a-f]+)$')
    parent_status = re.compile(r'^parent-baseline status=0x([0-9a-f]+) available=([01]) parents=0x([0-9a-f]+)$')
    used_parent_bdf = set()
    for i, line in enumerate(lines):
        m = parent_header.fullmatch(line)
        if not m:
            continue
        if i+1 >= len(lines) or not (status := parent_status.fullmatch(lines[i+1])):
            raise DiagnosticError('parent observation missing status')
        seg, bus, pci = (int(v, 16) for v in m.groups())
        bdf = f'{seg:04x}:{bus:02x}:00.0'
        ident = f'{pci & 0xffff:04x}:{pci >> 16:04x}'
        if (bdf, ident) not in {(d['bdf'], d['pci_id']) for d in devices} or bdf in used_parent_bdf:
            raise DiagnosticError('unattributed or duplicate parent observation')
        used_parent_bdf.add(bdf)
        state = 'observed' if int(status[1], 16) == 0 and status[2] == '1' else 'unavailable'
        parent_reports.append({'bdf': bdf, 'status': state, 'declared_parent_count': int(status[3], 16) if state == 'observed' else None})
    gpu_devices = [d for d in devices if d['pci_id'].startswith('10de:')]
    all_complete = complete == 1 and failures == 0 and device_failures == 0 and graph_error is None
    result = {
        'schema': 'dual-nvidia-uefi-diagnostic/1',
        'capture': {
            'status': 'complete_observation' if all_complete else 'incomplete_observation',
            'cold_boot_provenance': boot_origin,
            'unlock_eligible': False,
            'can_detach': False,
            'firmware_modified': None,  # not independently provable from a text log
        },
        'observed_uefi_devices': devices,
        'nvidia_display_count': len(gpu_devices),
        'parent_chains': parent_reports,
        'gop_ownership': {
            'status': 'direct_console_gop_handle_association' if len(set(direct)) == 1 and all_complete else 'ambiguous_or_unavailable',
            'direct_handle_gpu_bdf': direct[0] if len(set(direct)) == 1 and all_complete else None,
            'physical_owner_bdf': None,
            'gop_handles': gops,
        },
        'unresolved': ([f'graph:{graph_error}'] if graph_error else []) +
                      (['PCI inventory incomplete'] if not complete or failures or device_failures else []) +
                      ['Preboot physical monitor/connector ownership is not proven from UEFI graph records'],
        'evidence_quality': 'passive_pci_and_graph' if all_complete else 'partial_or_invalid',
    }
    if expected_pci_ids is not None:
        result['requested_pair'] = match_expected_pair(devices, expected_pci_ids, all_complete)
    return result


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('diagnostic', type=Path)
    p.add_argument('--repository', type=Path, default=Path(__file__).resolve().parents[2])
    p.add_argument('--boot-origin', choices=['cold_off_verified', 'restart', 'unknown'], default='unknown')
    p.add_argument('--output', type=Path)
    p.add_argument('--expect-pci-id', action='append', default=[], metavar='10de:XXXX',
                   help='repeat exactly twice for read-only PCI identity matching; never unlock authorization')
    args = p.parse_args()
    expected_ids = tuple(pci.lower() for pci in args.expect_pci_id)
    if expected_ids and (len(expected_ids) != 2 or any(not re.fullmatch(r'10de:[0-9a-f]{4}', pci) for pci in expected_ids)):
        p.error('--expect-pci-id requires exactly two NVIDIA vendor:device identifiers')
    # Do not follow symlinks or consume unbounded input files.
    if not args.diagnostic.is_file() or args.diagnostic.is_symlink() or args.diagnostic.stat().st_size > MAX_INPUT:
        raise SystemExit('Invalid or oversized diagnostic input')
    try:
        result = summarise(args.diagnostic.read_text(encoding='utf-8'), load_graph_parser(args.repository),
                           boot_origin=args.boot_origin, expected_pci_ids=expected_ids or None)
    except (DiagnosticError, UnicodeDecodeError) as exc:
        raise SystemExit(f'Invalid diagnostic: {exc}') from None
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(text, encoding='utf-8')
    else:
        print(text, end='')


if __name__ == '__main__':
    main()
