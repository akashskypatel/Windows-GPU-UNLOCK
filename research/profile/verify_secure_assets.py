#!/usr/bin/env python3
"""Read-only host verification of separate GA102/AD102 reference firmware assets.

Matching hashes identifies bytes in a pinned *public reference*, not NVIDIA
signatures, compatibility with this motherboard, or unlock eligibility.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

SOURCE = 'JustAResearcher/gpu-unlock-ada@d28c485418c3d9d034cd4bac19200bc33dd3453b/kernel/gpu_unlock/firmware_pins_610.h'
PREFIX = 'gpu-unlock/610.43.03/'
PINS = {
    'booter_load_ad102.bin': '6ee05b20e1dc244c08c052f36ef28469b8d09f4955d1fe33e48a179e11a7fd49',
    'booter_load_ga102.bin': '056cbc064a888f80717726c54d7f64fcd68044d123870c95a74f37f4975dcaa4',
    'gsp_boot_ad102.bin': '45d6335a8185d6ff13e8d1484cea73f68d3d13aa1c19dc080ed1c3482dd5bac0',
    'gsp_boot_desc_ad102.bin': '83f8f3f1f5f9496e0ea8fc7103c2beb64d0b6de2f5ffe725f13514de5a95fa42',
    'gsp_boot_desc_ga102.bin': 'cc5a3fc1f4c47f2fe107b1b68f0176d8a448e6dec84b575e5560ccef5262bf15',
    'gsp_boot_ga102.bin': '3df651acb174fd5f5561a1996965b192f50c5d763168446ed0d4ead19d895768',
    'gsp_ga10x.bin': '572373620a37418f24dc16b5031c39338778c3257e48e8408de9a57291b24f3a',
    'v67-ad102-610.43.03-four-plm.bin': '44c36b2d6b3424e53e18f3e55db85c833655de071ce66ce42749588a4a7dc8cb',
    'v67-ga102-610.43.03.bin': '2a0aa1f86d0b6afff5214d641d87d46dc98ef06ed908ff05d0ddbad5ffb7e197',
}
GROUPS = {
    'rtx4090_ad102': ('booter_load_ad102.bin', 'gsp_boot_ad102.bin',
                     'gsp_boot_desc_ad102.bin', 'gsp_ga10x.bin',
                     'v67-ad102-610.43.03-four-plm.bin'),
    'rtx3080_ga102': ('booter_load_ga102.bin', 'gsp_boot_ga102.bin',
                     'gsp_boot_desc_ga102.bin', 'gsp_ga10x.bin',
                     'v67-ga102-610.43.03.bin'),
}
# The pinned gsp_ga10x.bin is 84,277,400 bytes (firmware/artifacts-610.43.03.json).
# Allow that stock image without admitting unbounded files.
MAX_ASSET_BYTES = 96 * 1024 * 1024


def _read_digest(path: Path) -> tuple[str, int]:
    # Refuse symlinked path components, not just the final file.
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError('symlinked path')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_ASSET_BYTES:
            raise ValueError('not a bounded regular file')
        h = hashlib.sha256()
        size = 0
        while (block := stream.read(1024 * 1024)):
            size += len(block)
            if size > MAX_ASSET_BYTES:
                raise ValueError('asset size exceeded limit')
            h.update(block)
        after = os.fstat(stream.fileno())
        if size != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('asset changed during read')
    return h.hexdigest(), size


def inspect(root: Path, pins: dict[str, str] = PINS) -> dict:
    results = {}
    for name, expected in pins.items():
        path = root / 'gpu-unlock' / '610.43.03' / name
        entry = {'path': PREFIX + name, 'expected_sha256': expected, 'matched': False}
        try:
            sha, size = _read_digest(path)
            entry.update(sha256=sha, size=size, matched=(sha == expected),
                         status='MATCHED' if sha == expected else 'HASH_MISMATCH')
        except (OSError, ValueError) as exc:
            # Never emit private paths or exception data into a shared report.
            entry['status'] = 'MISSING_OR_UNREADABLE' if isinstance(exc, OSError) else 'REFUSED_INVALID_FILE'
        results[name] = entry
    groups = {gpu: {'asset_names': list(names), 'reference_hashes_matched': all(results[name]['matched'] for name in names)}
              for gpu, names in GROUPS.items()}
    all_match = all(entry['matched'] for entry in results.values())
    return {
        'schema': 'dual-gpu-secure-asset-reference-check/1',
        'source_pin_table': SOURCE,
        'status': 'ALL_REFERENCE_ASSETS_MATCH' if all_match else 'REFERENCE_ASSET_EVIDENCE_INCOMPLETE',
        'assets': results, 'groups': groups,
        'nvidia_signature_verified': False,
        'board_compatibility_verified': False,
        'firmware_execution_tested': False,
        'can_detach': False, 'can_unlock': False, 'can_flash': False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets-root', type=Path, required=True,
                        help='Directory containing gpu-unlock/610.43.03/*.bin')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = inspect(args.assets_root)
        if args.output.resolve(strict=False) in { (args.assets_root / 'gpu-unlock' / '610.43.03' / name).resolve(strict=False) for name in PINS }:
            raise ValueError('report would overwrite an input')
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(f"STATUS={report['status']} CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false REPORT={args.output}")
        return 0 if report['status'] == 'ALL_REFERENCE_ASSETS_MATCH' else 2
    except (OSError, ValueError) as exc:
        print(f'STATUS=ERROR CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false REASON={type(exc).__name__}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
