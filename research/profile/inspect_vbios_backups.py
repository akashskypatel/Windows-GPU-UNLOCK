#!/usr/bin/env python3
"""Inspect two user-supplied VBIOS backup files, offline and read-only.

The PCI expansion-ROM header and PCIR metadata establish only structural
plausibility and PCI vendor/device identification. They do not authenticate
NVIDIA firmware, prove board/subsystem provenance, certify a complete SPI dump,
or authorize a flash or a GPU unlock. Never writes input files or touches GPUs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MAX_ROM_BYTES = 16 * 1024 * 1024
MAX_IMAGES = 128
PCI_VENDOR_NVIDIA = 0x10DE
EXPECTED = {
    'rtx4090': {'bdf': '0000:01:00.0', 'vendor_id': PCI_VENDOR_NVIDIA,
                'device_id': 0x2684, 'subsystem': '1043:88e6'},
    'rtx3080': {'bdf': '0000:04:00.0', 'vendor_id': PCI_VENDOR_NVIDIA,
                'device_id': 0x220A, 'subsystem': '19da:b612'},
}


class InvalidBackup(ValueError):
    pass


def u16(data: bytes, offset: int) -> int:
    if not 0 <= offset <= len(data) - 2:
        raise InvalidBackup('truncated 16-bit field')
    return int.from_bytes(data[offset:offset + 2], 'little')


def read_backup(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise InvalidBackup('missing, symlinked or non-file VBIOS backup')
    size = path.stat().st_size
    if size < 512 or size > MAX_ROM_BYTES or size % 512:
        raise InvalidBackup('VBIOS backup size is not a bounded multiple of 512 bytes')
    with path.open('rb') as stream:
        data = stream.read(MAX_ROM_BYTES + 1)
    if len(data) != size:
        raise InvalidBackup('VBIOS backup changed length while reading')
    return data


def inspect_backup(data: bytes, *, vendor_id: int, device_id: int) -> dict:
    """Parse standard PCI option-ROM images without executing firmware.

    Some vendor ROM formats may validly deviate from this simple envelope. An
    unrecognized layout is NOT evidence of corruption and must not be flashed
    or patched to satisfy this inspector.
    """
    if not 512 <= len(data) <= MAX_ROM_BYTES or len(data) % 512:
        raise InvalidBackup('size outside bounded 512-byte PCI option-ROM units')
    cursor = 0
    images = []
    for _ in range(MAX_IMAGES):
        if len(data) - cursor < 512 or data[cursor:cursor + 2] != b'\x55\xaa':
            raise InvalidBackup('missing PCI option-ROM signature or truncated image')
        pcir_offset = u16(data, cursor + 0x18)
        if pcir_offset < 0x1A or pcir_offset > len(data) - cursor - 0x16:
            raise InvalidBackup('invalid PCIR pointer')
        pcir = cursor + pcir_offset
        if data[pcir:pcir + 4] != b'PCIR':
            raise InvalidBackup('PCIR structure signature missing')
        pcir_size = u16(data, pcir + 0x0A)
        units = u16(data, pcir + 0x10)
        if pcir_size < 0x16 or units == 0:
            raise InvalidBackup('invalid PCIR structure or zero image size')
        span = units * 512
        end = cursor + span
        if end > len(data) or pcir + pcir_size > end:
            raise InvalidBackup('image or PCIR extends beyond declared ROM bounds')
        vendor, device = u16(data, pcir + 4), u16(data, pcir + 6)
        if (vendor, device) != (vendor_id, device_id):
            raise InvalidBackup('PCIR PCI vendor/device does not match explicit GPU assignment')
        indicator = data[pcir + 0x15]
        images.append({'offset': cursor, 'length': span, 'vendor_id': f'{vendor:04x}',
                       'device_id': f'{device:04x}', 'code_type': data[pcir + 0x14],
                       'pcir_revision': data[pcir + 0x0C],
                       'last_image': bool(indicator & 0x80)})
        cursor = end
        if indicator & 0x80:
            break
    else:
        raise InvalidBackup('no terminal PCIR image within image count bound')
    trailing = data[cursor:]
    if trailing and any(value != trailing[0] for value in trailing):
        raise InvalidBackup('nonuniform trailing data after terminal ROM image')
    if trailing and trailing[0] not in (0x00, 0xFF):
        raise InvalidBackup('unexpected trailing bytes beyond declared ROM image')
    return {'sha256': hashlib.sha256(data).hexdigest(), 'file_bytes': len(data),
            'declared_image_bytes': cursor, 'trailing_padding_bytes': len(trailing),
            'images': images, 'pci_rom_structure': 'STRUCTURALLY_PLAUSIBLE',
            'subsystem_id_in_rom_verified': False,
            'full_spi_flash_contents_verified': False,
            'nvidia_signature_verified': False}


def build_report(rom_4090: bytes, rom_3080: bytes) -> dict:
    cards = []
    for label, contents in (('rtx4090', rom_4090), ('rtx3080', rom_3080)):
        expected = EXPECTED[label]
        details = inspect_backup(contents, vendor_id=expected['vendor_id'], device_id=expected['device_id'])
        cards.append({'gpu': label, 'claimed_bdf': expected['bdf'],
                      'claimed_subsystem': expected['subsystem'],
                      'pci_vendor_device_matched': True,
                      'capture_bdf_provenance': 'USER_FILE_ASSIGNMENT_ONLY',
                      **details})
    return {
        'schema': 'dual-gpu-vbios-backup-inspection/1',
        'status': 'PCI_ROM_HEADERS_MATCH_ASSIGNED_GPU_IDS',
        'cards': cards,
        'limits': [
            'PCI ROM header and PCIR are structural checks; vendor authenticity unverified',
            'PCIR contains vendor/device identifiers but cannot attest the claimed subsystem or BDF',
            'A GPU utility saved file may differ from a complete SPI flash dump',
            'A valid-looking ROM is not a validated safe flash/recovery image',
            'No ROM or cold-state evidence authorizes active GPU unlock or driver release',
        ],
        'can_unlock': False, 'can_detach': False, 'can_flash': False,
        'backup_proven_flashable': False, 'writes_firmware': False, 'hardware_tested': False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--rtx4090', type=Path, required=True, help='explicitly assigned 4090 option-ROM backup file')
    parser.add_argument('--rtx3080', type=Path, required=True, help='explicitly assigned 3080 option-ROM backup file')
    parser.add_argument('--output', type=Path, help='JSON report path; defaults to stdout')
    args = parser.parse_args()
    try:
        if args.rtx4090.resolve() == args.rtx3080.resolve():
            raise InvalidBackup('two distinct card backup paths are required')
        report = build_report(read_backup(args.rtx4090), read_backup(args.rtx3080))
    except (OSError, InvalidBackup) as exc:
        parser.error(f'backup evidence rejected: {exc}')
    output = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(output, encoding='utf-8')
        print(f'STATUS={report["status"]} CAN_FLASH=false CAN_UNLOCK=false')
    else:
        print(output, end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
