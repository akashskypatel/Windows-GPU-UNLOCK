#!/usr/bin/env python3
"""Build the pinned GA102 and AD102 research assets on a Windows host.

Firmware source is NVIDIA 610.43.03. Windows 617.42 is an independently
checked *target driver*, not an interchangeable firmware archive/version.
Never loads firmware, accesses GPU registers, stages EFI or modifies drivers.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
VENDOR = HERE / 'ada_610'
REFERENCE_VERSION = '610.43.03'
TARGET_DRIVER = '617.42'
EXPECTED_CARDS = {'01:00.0': 'NVIDIA GeForce RTX 4090', '04:00.0': 'NVIDIA GeForce RTX 3080'}
SOURCE_ROOT = f'NVIDIA-kernel-module-source-{REFERENCE_VERSION}'
SOURCE_C_FILES = (
    'g_bindata_kgspGetBinArchiveBooterLoadUcode_GA102.c',
    'g_bindata_kgspGetBinArchiveGspRmBoot_GA102.c',
    'g_bindata_kgspGetBinArchiveBooterLoadUcode_AD102.c',
    'g_bindata_kgspGetBinArchiveGspRmBoot_AD102.c',
)
SOURCE_PREFIX = SOURCE_ROOT + '/src/nvidia/generated/'
MAX_SOURCE_C_BYTES = 32 * 1024 * 1024


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def parse_driver_inventory(output: str) -> dict:
    """Require exactly the two observed adapters and driver version."""
    devices = {}
    for row in csv.reader(output.splitlines()):
        if len(row) != 3:
            raise ValueError('unexpected nvidia-smi CSV shape')
        address, name, version = (field.strip() for field in row)
        match = re.fullmatch(r'[0-9a-fA-F]{4,8}:([0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7])', address)
        if not match:
            raise ValueError('unexpected NVIDIA PCI address')
        bdf = match.group(1).lower()
        if bdf not in EXPECTED_CARDS or EXPECTED_CARDS[bdf] != name or bdf in devices:
            raise ValueError('unexpected GPU set or duplicate BDF')
        if version != TARGET_DRIVER:
            raise ValueError('installed NVIDIA driver is not the target version')
        devices[bdf] = {'name': name, 'reported_driver': version, 'pci_bus_id': address}
    if set(devices) != set(EXPECTED_CARDS):
        raise ValueError('missing expected GPU')
    return devices


def installed_driver_inventory() -> dict:
    result = subprocess.run(
        ['nvidia-smi', '--query-gpu=pci.bus_id,name,driver_version', '--format=csv,noheader'],
        capture_output=True, text=True, check=True, timeout=20,
    )
    return parse_driver_inventory(result.stdout)


def unpack_exact_source(archive_file: Path, destination: Path) -> Path:
    """Extract ONLY four exact pinned generated C files, never tar paths."""
    expected = {SOURCE_PREFIX + name: name for name in SOURCE_C_FILES}
    found = set()
    root = destination / SOURCE_ROOT / 'src/nvidia/generated'
    root.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive_file, 'r:xz') as archive:
        for member in archive:
            if member.name not in expected:
                continue
            if member.name in found or not member.isfile() or not 0 < member.size <= MAX_SOURCE_C_BYTES:
                raise ValueError('duplicate, invalid or oversized generated source')
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError('unreadable generated source')
            with stream:
                data = stream.read(MAX_SOURCE_C_BYTES + 1)
            if len(data) != member.size:
                raise ValueError('generated source length mismatch')
            (root / expected[member.name]).write_bytes(data)
            found.add(member.name)
    if found != set(expected):
        raise ValueError('incomplete pinned NVIDIA source archive')
    return destination / SOURCE_ROOT


def run_vendor(script: str, *args: object) -> None:
    subprocess.run([sys.executable, '-I', str(VENDOR / script), *(str(x) for x in args)],
                   check=True)


def verify_reference_assets(root: Path) -> dict:
    script = HERE.parent / 'profile' / 'verify_secure_assets.py'
    spec = importlib.util.spec_from_file_location('reference_asset_verification', script)
    if spec is None or spec.loader is None:
        raise ValueError('reference asset verifier unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report = module.inspect(root)
    if report['status'] != 'ALL_REFERENCE_ASSETS_MATCH' or len(report['assets']) != 9:
        raise ValueError('reference assets failed pinned SHA-256 verification')
    if any(report[key] for key in ('can_detach', 'can_unlock', 'can_flash', 'nvidia_signature_verified')):
        raise ValueError('unexpected authorization in reference verifier')
    return report


def prepare(cache: Path, output: Path, *, offline: bool = False,
            verify_installed_driver: bool = False) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError('output must not exist; never overwrite existing assets')
    if not output.parent.is_dir():
        raise ValueError('output parent must already exist')
    if shutil.which('zstd') is None:
        raise ValueError('zstd executable required on PATH to unpack NVIDIA package')
    installed = installed_driver_inventory() if verify_installed_driver else None
    manifest = json.loads((VENDOR / f'artifacts-{REFERENCE_VERSION}.json').read_text(encoding='utf-8'))
    source_entry, _, package_entry = manifest['source_artifacts']
    if (source_entry['filename'] != f'{SOURCE_ROOT}.tar.xz' or
            package_entry['filename'] != f'nvidia-utils-{REFERENCE_VERSION}-1-x86_64_v3.pkg.tar.zst'):
        raise ValueError('unexpected upstream source manifest')
    run_vendor('fetch_artifacts.py', cache, *(['--offline'] if offline else []))
    source_file, package_file = (cache / source_entry['filename'], cache / package_entry['filename'])
    for entry, path in ((source_entry, source_file), (package_entry, package_file)):
        if not path.is_file() or path.is_symlink() or digest(path) != entry['sha256']:
            raise ValueError('pinned NVIDIA input has changed')

    with tempfile.TemporaryDirectory(prefix='.nvidia-reference-', dir=output.parent) as temporary:
        work = Path(temporary)
        source_root = unpack_exact_source(source_file, work / 'source')
        result = work / 'result'
        asset_dir = result / 'gpu-unlock' / REFERENCE_VERSION
        asset_dir.mkdir(parents=True)
        run_vendor('generate_v67.py', package_file, asset_dir)
        run_vendor('extract_boot_assets.py', source_root, asset_dir)
        run_vendor('extract_boot_assets.py', source_root, asset_dir, '--chip', 'ad102')
        inspection = verify_reference_assets(result)
        (result / 'reference-asset-verification.json').write_text(json.dumps(inspection, indent=2) + '\n', encoding='utf-8')
        provenance = {
            'schema': 'windows-dual-gpu-reference-firmware/1',
            'status': 'REFERENCE_BYTES_MATCH_COMPATIBILITY_UNPROVEN',
            'reference_firmware_version': REFERENCE_VERSION,
            'target_windows_driver_version': TARGET_DRIVER,
            'installed_driver_check': 'MATCHED' if installed is not None else 'NOT_REQUESTED',
            'observed_gpus': installed,
            'source_revision': 'JustAResearcher/gpu-unlock-ada@d28c485418c3d9d034cd4bac19200bc33dd3453b',
            'source_archive_sha256': digest(source_file),
            'nvidia_package_sha256': digest(package_file),
            'assets': {name: {'sha256': info['sha256'], 'size': info['size']}
                       for name, info in inspection['assets'].items()},
            'driver_firmware_compatibility_verified': False,
            'nvidia_signature_verified': False,
            'exact_card_fwsec_compatibility_verified': False,
            'hardware_tested': False,
            'can_detach': False,
            'can_unlock': False,
            'can_flash': False,
        }
        (result / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n', encoding='utf-8')
        shutil.copyfile(VENDOR / 'NOTICE.md', result / 'NOTICE.md')
        # Atomic publication, only after every hash gate passes. No existing
        # output is touched; temporary working files are removed on failure.
        if output.exists() or output.is_symlink():
            raise ValueError('output appeared during generation')
        result.rename(output)
    return provenance


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', required=True, type=Path,
                        help='local directory for hash-pinned downloaded source inputs')
    parser.add_argument('--output', required=True, type=Path,
                        help='new directory for reference assets (must not exist)')
    parser.add_argument('--offline', action='store_true', help='use only already verified cached inputs')
    parser.add_argument('--verify-installed-driver', action='store_true',
                        help='require installed driver 617.42 and expected 4090/3080 PCI BDFs')
    args = parser.parse_args()
    try:
        result = prepare(args.cache.absolute(), args.output.absolute(),
                         offline=args.offline, verify_installed_driver=args.verify_installed_driver)
        print(f"STATUS={result['status']} CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false REPORT={args.output.absolute() / 'provenance.json'}")
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
            tarfile.TarError) as error:
        print(f'STATUS=ERROR CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false REASON={type(error).__name__}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
