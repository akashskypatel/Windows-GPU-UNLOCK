#!/usr/bin/env python3
"""Read-only inventory of installed NVIDIA GSP/UCODES inputs.

The inventory cannot prove Booter presence, signed-image selection, acceptance,
anything about kernel runtime dispatch, or which GPU uses a candidate file.
It reads only explicitly named firmware/driver files under supplied roots.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

DRIVER_MD5_61742 = "3fb9afac9d0e394723e830aa14e60512"
TARGET_NAMES = frozenset((
    "nvlddmkm.sys", "gsp_ga10x.bin", "ucodes_ga10x.bin",
    "gsp_tu10x.bin", "ucodes_tu10x.bin",
))
CHUNK = 1024 * 1024
MAX_ELF_SECTIONS = 4096
MAX_ELF_STRING_TABLE = 8 * CHUNK


def _hash_file(path):
    sha256, md5 = hashlib.sha256(), hashlib.md5()
    before = path.stat()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("File changed while hashing")
    return {"size": after.st_size, "sha256": sha256.hexdigest(), "md5": md5.hexdigest()}


def _hash_region(handle, start, length):
    handle.seek(start)
    digest = hashlib.sha256()
    remaining = length
    while remaining:
        block = handle.read(min(CHUNK, remaining))
        if not block:
            raise ValueError("Unexpected EOF while hashing ELF section")
        digest.update(block)
        remaining -= len(block)
    return digest.hexdigest()



def _ucodes_header(path, file_size):
    """Read only the 24-byte NVUCODES container header, never its payload.

    Layout is NVIDIA 615.78.08 bin_data_pvt.h BINDATA_UCODES_BIN_HEADER.
    numEntries is a build-time capacity, NOT a verified number of records in
    this particular Windows file, and fingerprint is NOT compared with GSP.
    """
    with path.open("rb") as handle:
        header = handle.read(24)
    if file_size < 24 or len(header) != 24:
        return {"format": "too_short_for_nvucodes_header",
                "note": "No assumption about archive contents"}
    magic, version, entry_capacity, fingerprint = struct.unpack("<QIIQ", header)
    if magic != 0x5345444F4355564E:  # b"NVUCODES" on disk
        return {"format": "unrecognized_ucodes_header",
                "first_8_bytes_hex": header[:8].hex(),
                "note": "No unsupported format is parsed as NVUCODES"}
    result = {"format": "nvucodes_v1" if version == 1 else "nvucodes_unsupported_version",
              "magic": "NVUCODES", "version": version,
              "declared_possible_entry_count": entry_capacity,
              "fingerprint_hex": "0x%016x" % fingerprint,
              "note": "Header only; possible-entry count is not a record listing; "
                      "fingerprint pairing with GSP and signed Booter presence NOT proven"}
    return result


def _elf_sections(path, file_size):
    """Record only signature/fwimage *section metadata*, not image contents.

    Handles ELF64 little-endian non-extended section tables. Other formats are
    explicitly reported as unsupported, never interpreted as lacking signatures.
    """
    with path.open("rb") as handle:
        ident = handle.read(64)
        if len(ident) < 64 or ident[:4] != b"\x7fELF":
            return {"format": "not_plain_elf", "selected_sections": [],
                    "note": "Container or opaque firmware: no signature absence inferred"}
        if ident[4] != 2 or ident[5] != 1:
            return {"format": "unsupported_elf_class_or_endian", "selected_sections": []}
        shoff = struct.unpack_from("<Q", ident, 40)[0]
        entsize, count, names_index = struct.unpack_from("<HHH", ident, 58)
        if (not count or count > MAX_ELF_SECTIONS or entsize < 64 or
                names_index >= count or shoff > file_size or
                count * entsize > file_size - shoff):
            return {"format": "elf64_le_unhandled_section_table", "selected_sections": [],
                    "note": "Extended/invalid section table; not evidence of missing signatures"}
        def entry(i):
            handle.seek(shoff + i * entsize)
            values = struct.unpack("<IIQQQQIIQQ", handle.read(64))
            # sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, ...
            if values[4] > file_size or values[5] > file_size - values[4]:
                raise ValueError("Out-of-range ELF section")
            return values
        name_info = entry(names_index)
        if name_info[5] > MAX_ELF_STRING_TABLE:
            return {"format": "elf64_le_oversized_names", "selected_sections": []}
        handle.seek(name_info[4])
        names = handle.read(name_info[5])
        selected = []
        for i in range(count):
            sh = entry(i)
            off = sh[0]
            if off >= len(names):
                continue
            end = names.find(b"\0", off)
            if end < 0:
                continue
            name = names[off:end].decode("ascii", "replace")
            if name.startswith(".fwsignature") or name == ".fwimage":
                selected.append({"name": name, "offset": sh[4], "size": sh[5],
                                 "sha256": _hash_region(handle, sh[4], sh[5])})
        return {"format": "elf64_le", "section_count": count,
                "selected_sections": selected,
                "note": "Section names/hashes are not a signature verification or Booter proof"}


def _paths_under(root, max_depth=3):
    if root.is_file():
        if root.name.casefold() in TARGET_NAMES:
            yield root
        return
    if not root.is_dir():
        raise FileNotFoundError(str(root))
    is_driver_store = root.name.casefold() == "filerepository"
    for here, dirs, files in os.walk(root, followlinks=False):
        here_path = Path(here)
        depth = len(here_path.relative_to(root).parts)
        if is_driver_store and depth == 0:
            dirs[:] = [d for d in dirs if d.casefold().startswith("nv") and
                       ".inf_" in d.casefold() and not (here_path / d).is_symlink()]
        elif depth >= max_depth:
            dirs[:] = []
        else:
            dirs[:] = [d for d in dirs if not (here_path / d).is_symlink()]
        for filename in files:
            candidate = here_path / filename
            if filename.casefold() in TARGET_NAMES and not candidate.is_symlink():
                yield candidate


def inventory(roots, expected_md5, max_files):
    findings, problems = [], []
    found = set()
    capped = False
    for raw_root in roots:
        root = Path(raw_root).expanduser()
        try:
            for path in _paths_under(root):
                unique = os.path.normcase(str(path.resolve()))
                if unique in found:
                    continue
                found.add(unique)
                if len(findings) >= max_files:
                    capped = True
                    break
                item = {"path": str(path), "name": path.name}
                try:
                    item.update(_hash_file(path))
                    if path.name.casefold() == "nvlddmkm.sys":
                        item["matches_expected_driver_md5"] = item["md5"] == expected_md5
                    if path.name.casefold().startswith("gsp_") and path.name.lower().endswith(".bin"):
                        item["gsp_elf_sections"] = _elf_sections(path, item["size"])
                        if path.stat().st_size != item["size"]:
                            raise ValueError("GSP file size changed while parsing ELF metadata")
                    if path.name.casefold().startswith("ucodes_") and path.name.lower().endswith(".bin"):
                        item["ucodes_header"] = _ucodes_header(path, item["size"])
                        if path.stat().st_size != item["size"]:
                            raise ValueError("UCODES file size changed while reading header")
                except (OSError, ValueError, struct.error) as exc:
                    item["error"] = str(exc)
                    problems.append({"path": str(path), "error": str(exc)})
                findings.append(item)
        except OSError as exc:
            problems.append({"root": str(root), "error": str(exc)})
        if capped:
            break
    matched = any(f.get("matches_expected_driver_md5") for f in findings)
    have_gsp = any(f["name"].casefold() == "gsp_ga10x.bin" and "error" not in f for f in findings)
    have_ucodes = any(f["name"].casefold() == "ucodes_ga10x.bin" and "error" not in f for f in findings)
    # COMPLETE covers a fully successful *inventory*, not the firmware question.
    complete = bool(findings) and not (problems or capped)
    return {"schema_version": 1,
            "status": "COMPLETE" if complete else "PARTIAL",
            "mode": "read_only_firmware_file_inventory",
            "roots": [str(Path(r)) for r in roots],
            "expected_driver_md5": expected_md5,
            "findings": findings,
            "warnings": problems,
            "files_truncated": capped,
            "facts": {"pinned_nvlddmkm_sys_found": matched,
                      "gsp_ga10x_file_found": have_gsp,
                      "ucodes_ga10x_file_found": have_ucodes,
                      "windows_production_booter_record_proven": False,
                      "falcon_loader_descriptor_proven": False,
                      "gpu_architecture_selection_proven": False,
                      "signature_cryptographically_verified": False,
                      "hardware_modified": False},
            "scope": "Hashes, plain-ELF section metadata and 24-byte NVUCODES headers only; no archive record parser or runtime trace"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", help="Input file/directory (repeatable); default: installed NVIDIA DriverStore and system driver")
    parser.add_argument("--output", type=Path, required=True, help="JSON output path; only written file")
    parser.add_argument("--expected-driver-md5", default=DRIVER_MD5_61742)
    parser.add_argument("--max-files", type=int, default=128)
    args = parser.parse_args(argv)
    if args.output.suffix.casefold() != ".json" or args.output.name.casefold() in TARGET_NAMES:
        parser.error("--output must name a JSON report, never a firmware or driver input")
    if args.max_files < 1 or args.max_files > 1024:
        parser.error("--max-files must be between 1 and 1024")
    roots = args.root
    if roots is None:
        system_root = os.environ.get("SystemRoot")
        if not system_root:
            parser.error("--root is required outside Windows")
        roots = [str(Path(system_root) / "System32" / "DriverStore" / "FileRepository"),
                 str(Path(system_root) / "System32" / "drivers" / "nvlddmkm.sys")]
    report = args.output
    try:
        result = inventory(roots, args.expected_driver_md5.lower(), args.max_files)
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        returncode = 0 if result["status"] == "COMPLETE" else 2
    except Exception as exc:
        # Failure must remain visible even if the report cannot be written.
        returncode = 1
        try:
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(json.dumps({"status": "ERROR", "error": str(exc)}, indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass
        result = {"status": "ERROR"}
    print("STATUS=%s REPORT=%s" % (result["status"], report))
    return returncode


if __name__ == "__main__":
    sys.exit(main())
