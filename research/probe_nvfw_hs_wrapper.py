#!/usr/bin/env python3
"""Read-only, pinned-input scan for NVIDIA Linux-reference HS wrapper *candidates*.

This tests a specific wrapper layout constructed by NVIDIA's 615.78.08
nouveau/extract-firmware-nouveau.py (booter(), GA102/AD102 production).
It does not parse arbitrary Windows 617.42 bindata, establish the image
producer, authenticate signatures, or prove runtime use. Zero matches do NOT
establish that Windows Booter data is absent.

Only explicitly named DriverStore files are read. The sole output is JSON.
"""

import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

EXPECTED_SHA256 = {
    "nvlddmkm.sys": "db407b964c11441642a1642a0922c35990de974c267a08537c3432765365f84b",
    "gsp_ga10x.bin": "f89d8f615e6146ed2808df974b7af7f1aabda876596391b0aabcc32ba293c34f",
    "ucodes_ga10x.bin": "eed53d76248582d71c629e8b6230aee48ce673c91d782301c94e98ac6a6db7aa",
}
MAGIC_VERSION = struct.pack("<II", 0x10DE, 1)
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_IMAGE_BYTES = 256 * 1024
MAX_MATCHES = 32
SIGNATURE_STRIDE = 384  # NVIDIA 615.78.08 GA102/AD102 extractor, NOT Windows-verified


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def parse_reference_wrapper(data, at):
    """Check the *canonical assembled Linux reference* layout at file offset at.

    Uses bounded positions, no pointers, and checks all nine wrapper offsets.
    A match identifies format similarity, not a specific producer or valid sig.
    """
    available = len(data) - at
    if at < 0 or available < 120 + SIGNATURE_STRIDE:
        return None
    if data[at:at + 8] != MAGIC_VERSION:
        return None
    magic, version, total, hdr_off, fw_off, fw_len = struct.unpack_from("<6I", data, at)
    if hdr_off != 24 or fw_len == 0 or fw_len > MAX_IMAGE_BYTES:
        return None
    if fw_off < 120 + SIGNATURE_STRIDE or fw_off > available or fw_len > available - fw_off:
        return None
    if total != ((fw_off + fw_len + 255) // 256) * 256:
        return None
    fields = struct.unpack_from("<9I", data, at + hdr_off)
    sig_off, sig_len, loc_off, patch_sig_off, meta_off, meta_len, count_off, load_off, load_len = fields
    if sig_off != 60 or not 0 < sig_len <= 15 * SIGNATURE_STRIDE:
        return None
    if sig_len % SIGNATURE_STRIDE or fw_off != 120 + sig_len:
        return None
    if fields != (60, sig_len, 60 + sig_len, 64 + sig_len, 68 + sig_len,
                  12, 80 + sig_len, 84 + sig_len, 36):
        return None
    # File bounds above guarantee the following fields can be read safely.
    patch_loc, patch_sig, fuse_ver, engine_id, ucode_id, count = struct.unpack_from(
        "<6I", data, at + loc_off)
    if not 1 <= count <= 15 or sig_len != count * SIGNATURE_STRIDE:
        return None
    if patch_sig != 0:  # reference exporter inserts a zero placeholder
        return None
    load = struct.unpack_from("<9I", data, at + load_off)
    os_code_off, os_code_len, os_data_off, os_data_len, apps, app_code_off, app_code_len, app_data_off, app_data_len = load
    if apps != 1 or os_code_len != app_code_off:
        return None
    if (os_code_off > fw_len or os_data_off > fw_len or app_code_off > fw_len or
            app_data_off > fw_len):
        return None
    return {
        "file_offset": at,
        "payload_end_file_offset_exclusive": at + fw_off + fw_len,
        "declared_total_size": total,
        "image_size": fw_len,
        "image_file_offset": at + fw_off,
        "image_sha256": _sha256(data[at + fw_off:at + fw_off + fw_len]),
        "signature_count": count,
        "signature_size": sig_len,
        "signature_file_offset": at + sig_off,
        "signature_sha256": _sha256(data[at + sig_off:at + sig_off + sig_len]),
        "load_header_file_offset": at + load_off,
        "load_header_sha256": _sha256(data[at + load_off:at + load_off + load_len]),
        "patch_location": patch_loc,
        "fuse_version": fuse_ver,
        "engine_id": engine_id,
        "ucode_id": ucode_id,
        "source_contract": "Linux 615.78.08 canonical assembled GA102/AD102 wrapper",
        "windows_producer_proven": False,
        "signature_verified": False,
        "runtime_invocation_proven": False,
    }


def scan_bytes(data, max_matches=MAX_MATCHES):
    """Locate canonical candidates. A capacity overrun is explicitly PARTIAL."""
    if not 1 <= max_matches <= 128:
        raise ValueError("invalid match cap")
    matches, examined, capped = [], 0, False
    pos = 0
    while True:
        pos = data.find(MAGIC_VERSION, pos)
        if pos < 0:
            break
        examined += 1
        match = parse_reference_wrapper(data, pos)
        if match is not None:
            if len(matches) >= max_matches:
                capped = True
                break
            matches.append(match)
        pos += 1
    return {"status": "PARTIAL" if capped else "COMPLETE",
            "magic_version_occurrences_examined": examined,
            "candidate_count": len(matches),
            "candidates": matches,
            "truncated": capped,
            "no_match_does_not_prove_absence": True,
            "provenance_or_cryptographic_acceptance_proven": False}


def scan_file(path, max_matches=MAX_MATCHES):
    path = Path(path)
    name = path.name.casefold()
    if name not in EXPECTED_SHA256:
        raise ValueError("input filename is not one of the three pinned DriverStore files: " + path.name)
    if path.is_symlink() or not path.is_file():
        raise ValueError("input must be a non-symlink regular file")
    before = path.stat()
    if not 0 < before.st_size <= MAX_FILE_BYTES:
        raise ValueError("input exceeds bounded file size or is empty")
    sha = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha.update(chunk)
    digest = sha.hexdigest()
    if digest != EXPECTED_SHA256[name]:
        raise ValueError("input SHA-256 does not match the pinned Windows 617.42 DriverStore asset: " + name)
    with path.open("rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            result = scan_bytes(mapped, max_matches)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("input changed during analysis")
    return {"name": name, "path": str(path), "size": before.st_size,
            "sha256": digest, "pinned_input": True, **result}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append", required=True,
                        help="Exact installed driver/firmware path (repeatable)")
    parser.add_argument("--output", type=Path, required=True, help="new JSON report path only")
    parser.add_argument("--max-matches", type=int, default=MAX_MATCHES)
    args = parser.parse_args(argv)
    if not 1 <= args.max_matches <= 128:
        parser.error("--max-matches must be between 1 and 128")
    if args.output.suffix.casefold() != ".json":
        parser.error("--output must end in .json")
    try:
        output = args.output.resolve()
        inputs = [p.resolve() for p in args.input]
        if len(set(inputs)) != len(inputs):
            raise ValueError("duplicate input")
        if output in inputs:
            raise ValueError("output must not overwrite any input")
        files = [scan_file(p, args.max_matches) for p in args.input]
        status = "COMPLETE" if all(f["status"] == "COMPLETE" for f in files) else "PARTIAL"
        result = {
            "status": status, "mode": "read_only_pinned_linux_reference_wrapper_candidate_scan",
            "source": "NVIDIA open-gpu-kernel-modules 615.78.08 nouveau/extract-firmware-nouveau.py",
            "files": files,
            "total_candidates": sum(f["candidate_count"] for f in files),
            "windows_signed_booter_producer_proven": False,
            "falcon_argument_three_or_receiver_proven": False,
            "signature_authenticated": False,
            "hardware_action": "NONE",
            "no_match_does_not_prove_absence": True,
        }
        rc = 2 if status == "PARTIAL" else 0
    except (OSError, ValueError) as exc:
        status, rc = "ERROR", 1
        result = {"status": status, "error": str(exc), "hardware_action": "NONE"}
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        print("REPORT_WRITE_ERROR=%s" % exc, file=sys.stderr)
        print("STATUS=ERROR REPORT=%s" % args.output)
        return 1
    print("STATUS=%s REPORT=%s" % (status, args.output))
    return rc


if __name__ == "__main__":
    sys.exit(main())
