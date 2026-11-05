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


def u32(data: bytes, offset: int) -> int:
    if not 0 <= offset <= len(data) - 4:
        raise InvalidBackup('truncated 32-bit field')
    return int.from_bytes(data[offset:offset + 4], 'little')


def pci_rom_start(data: bytes) -> tuple[int, dict]:
    """Locate PCI images via a verified NVGI v3 ROM directory, never byte scanning.

    Source: Linux nova-core VBIOS IFR documentation. Unknown IFR versions and
    directories are deliberately refused rather than treated as invalid flash.
    """
    if data[:2] == b'\x55\xaa':
        return 0, {'container_format': 'PCI_OPTION_ROM'}
    if data[:4] != b'NVGI':
        first = data[:16].hex(' ')
        raise InvalidBackup(f'missing PCI option-ROM signature at byte offset 0x0; first 16 bytes: {first}')
    fixed1, fixed2 = u32(data, 4), u32(data, 8)
    version = (fixed1 >> 8) & 0xff
    if version != 3:
        raise InvalidBackup(f'unsupported NVGI IFR software version {version}; no offset guessed')
    # As specified by nova-core: FIXED2[19:0] indexes a u32 flash-status
    # offset; the RFRD directory is 4 KiB after the pointed-to offset.
    if fixed2 & ~0xfffff:
        raise InvalidBackup('unexpected IFR v3 FIXED2 reserved bits')
    total_data_size = fixed2 & 0xfffff
    flash_status_offset = u32(data, total_data_size)
    directory = flash_status_offset + 4096
    if directory > len(data) - 12 or data[directory:directory + 4] != b'RFRD':
        raise InvalidBackup('IFR v3 RFRD directory missing or out of bounds')
    rom_start = u32(data, directory + 8)
    if rom_start % 4 or rom_start <= directory + 12 or rom_start > len(data) - 512:
        raise InvalidBackup('IFR v3 PCI image offset is unaligned, overlaps directory or exceeds file')
    return rom_start, {'container_format': 'NVIDIA_IFR_V3', 'ifrv3_flash_status_offset': flash_status_offset,
                       'ifrv3_rom_directory_offset': directory, 'pci_rom_start_offset': rom_start,
                       'ifrv3_header_dword_0c': f'{u32(data, 12):08x}',
                       'ifrv3_header_dword_0c_semantics_verified': False}


def inspect_backup(data: bytes, *, vendor_id: int, device_id: int) -> dict:
    """Parse standard PCI images or a documented NVIDIA IFR v3 wrapper.

    Some vendor ROM formats may validly deviate from this simple envelope. An
    unrecognized layout is NOT evidence of corruption and must not be flashed
    or patched to satisfy this inspector.
    """
    if not 512 <= len(data) <= MAX_ROM_BYTES or len(data) % 512:
        raise InvalidBackup('size outside bounded 512-byte PCI option-ROM units')
    cursor, envelope = pci_rom_start(data)
    start = cursor
    images = []
    for _ in range(MAX_IMAGES):
        if len(data) - cursor < 512:
            raise InvalidBackup(f'truncated PCI option-ROM image at byte offset 0x{cursor:x}')
        if data[cursor:cursor + 2] != b'\x55\xaa':
            first = data[cursor:cursor + 16].hex(' ')
            raise InvalidBackup(f'missing PCI option-ROM signature at byte offset 0x{cursor:x}; first 16 bytes: {first}')
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
        code_type = data[pcir + 0x14]
        identity = (vendor, device)
        # One captured GA102 NVGI v3 GOP image declares 0000:0000 in its
        # secondary EFI PCIR. Do not use that entry to establish card identity.
        # Only an already-matched first image permits this narrow exception.
        missing_efi_identity = (bool(images) and envelope['container_format'] == 'NVIDIA_IFR_V3'
                                and code_type == 3 and identity == (0, 0))
        if identity != (vendor_id, device_id) and not missing_efi_identity:
            raise InvalidBackup('PCIR PCI vendor/device does not match explicit GPU assignment')
        if not images and envelope['container_format'] == 'NVIDIA_IFR_V3' and code_type != 0:
            raise InvalidBackup('IFR first PCI image is not legacy PC-AT code type')
        indicator = data[pcir + 0x15]
        images.append({'offset': cursor, 'length': span, 'vendor_id': f'{vendor:04x}',
                       'device_id': f'{device:04x}', 'code_type': code_type,
                       'identity_status': 'UNSPECIFIED_EFI_PCIR' if missing_efi_identity else 'MATCHED',
                       'pcir_revision': data[pcir + 0x0C],
                       'last_image': bool(indicator & 0x80)})
        cursor = end
        if indicator & 0x80:
            break
    else:
        raise InvalidBackup('no terminal PCIR image within image count bound')
    trailing = data[cursor:]
    if envelope['container_format'] == 'PCI_OPTION_ROM':
        if trailing and any(value != trailing[0] for value in trailing):
            raise InvalidBackup('nonuniform trailing data after terminal ROM image')
        if trailing and trailing[0] not in (0x00, 0xFF):
            raise InvalidBackup('unexpected trailing bytes beyond declared ROM image')
    # NVIDIA IFR includes vendor-managed regions and potentially redundant
    # copies after the PCI option-ROM chain. Never call that region padding.
    return {'sha256': hashlib.sha256(data).hexdigest(), 'file_bytes': len(data),
            **envelope, 'declared_image_bytes': cursor - start,
            'pci_rom_end_offset': cursor,
            'trailing_padding_bytes': len(trailing) if start == 0 else None,
            'unparsed_container_bytes_after_pci_chain': len(trailing) if start else 0,
            'images': images, 'pci_rom_structure': 'STRUCTURALLY_PLAUSIBLE',
            'subsystem_id_in_rom_verified': False,
            'full_spi_flash_contents_verified': False,
            'nvidia_signature_verified': False}


def build_report(rom_4090: bytes, rom_3080: bytes) -> dict:
    cards = []
    for label, contents in (('rtx4090', rom_4090), ('rtx3080', rom_3080)):
        expected = EXPECTED[label]
        try:
            details = inspect_backup(contents, vendor_id=expected['vendor_id'], device_id=expected['device_id'])
        except InvalidBackup as exc:
            raise InvalidBackup(f'{label}: {exc}') from exc
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
            'PCI ROM/IFR directory structures are checks only; vendor authenticity unverified',
            'PCIR contains vendor/device identifiers but cannot attest the claimed subsystem or BDF',
            'IFR data outside the first PCI image chain is not fully parsed or authenticated',
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
        inputs = {}
        for label, path in (('rtx4090', args.rtx4090), ('rtx3080', args.rtx3080)):
            try:
                inputs[label] = read_backup(path)
            except (OSError, InvalidBackup) as exc:
                raise InvalidBackup(f'{label} ({path}): {exc}') from exc
        report = build_report(inputs['rtx4090'], inputs['rtx3080'])
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
