#!/usr/bin/env python3
"""Read-only, hash-pinned source context for two Windows 617.42 slot readers.

This extracts original PE machine bytes and exception-table code ranges; it
cannot establish a physical GPU mapping, a signed record or a secure-loader call.
No driver or GPU code is executed. The only subprocess is optional GNU objdump.
"""

import argparse
import hashlib
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import zipfile

EXPECTED_SHA256 = "db407b964c11441642a1642a0922c35990de974c267a08537c3432765365f84b"
EXPECTED_BASE = 0x140000000
SITES = (0x1405A989F, 0x1405A9C94)
SITE_BYTES = bytes.fromhex("0fb681b0010000")  # Original MOVZX EAX, byte ptr [RCX+0x1b0].
MAX_DRIVER_BYTES = 256 * 1024 * 1024
MAX_FUNCTION_BYTES = 64 * 1024
MAX_CALL_CANDIDATES = 32


def u16(data, at):
    return struct.unpack_from("<H", data, at)[0]


def u32(data, at):
    return struct.unpack_from("<I", data, at)[0]


class PE:
    def __init__(self, raw):
        self.raw = raw
        if len(raw) < 0x100 or raw[:2] != b"MZ":
            raise ValueError("not an MZ executable")
        off = u32(raw, 0x3C)
        if off + 24 > len(raw) or raw[off:off+4] != b"PE\x00\x00":
            raise ValueError("missing PE signature")
        if u16(raw, off+4) != 0x8664:
            raise ValueError("not an x86-64 PE")
        count, opt_size = u16(raw, off+6), u16(raw, off+20)
        opt = off + 24
        if opt + opt_size > len(raw) or opt_size < 0x88 or u16(raw, opt) != 0x20B:
            raise ValueError("invalid PE32+ optional header")
        self.base = struct.unpack_from("<Q", raw, opt+24)[0]
        if self.base != EXPECTED_BASE:
            raise ValueError("unexpected PE image base")
        if u32(raw, opt+108) < 4:
            raise ValueError("missing exception directory")
        self.exception_rva = u32(raw, opt+112+3*8)
        self.exception_size = u32(raw, opt+112+3*8+4)
        self.sections = []
        for i in range(count):
            p = opt + opt_size + 40*i
            if p+40 > len(raw):
                raise ValueError("truncated PE section table")
            name = raw[p:p+8].split(b"\x00")[0].decode("ascii", "replace")
            virtual_size, rva, raw_size, file_offset = struct.unpack_from("<IIII", raw, p+8)
            flags = u32(raw, p+36)
            if file_offset + raw_size > len(raw):
                raise ValueError("section exceeds file")
            self.sections.append((name, rva, virtual_size, raw_size, file_offset, flags))

    def section(self, rva, size=1):
        for name, base, vs, rs, file_off, flags in self.sections:
            if base <= rva and rva + size <= base + rs:
                return name, file_off + rva-base, flags
        raise ValueError("RVA 0x%x + %d does not map to file-backed section" % (rva, size))

    def read(self, va, size, executable=False):
        rva = va-self.base
        name, off, flags = self.section(rva, size)
        if executable and not flags & 0x20000000:
            raise ValueError("VA 0x%x not in executable PE section %s" % (va, name))
        return self.raw[off:off+size]

    def unwind_ranges(self):
        if self.exception_size == 0 or self.exception_size % 12:
            raise ValueError("invalid PE exception table length")
        name, off, _ = self.section(self.exception_rva, self.exception_size)
        ranges = []
        for p in range(off, off+self.exception_size, 12):
            begin, end, unwind = struct.unpack_from("<III", self.raw, p)
            if begin and begin < end:
                ranges.append((self.base+begin, self.base+end, self.base+unwind))
        return ranges


def original_bytes(path):
    path = Path(path)
    if path.suffix.lower() == ".zip":
        if path.stat().st_size > MAX_DRIVER_BYTES:
            raise ValueError("ZIP size exceeds inspection cap")
        with zipfile.ZipFile(path) as archive:
            members = [m for m in archive.infolist()
                       if m.filename.replace("\\", "/").split("/")[-1].lower() == "nvlddmkm.sys"]
            if len(members) != 1 or members[0].file_size > MAX_DRIVER_BYTES:
                raise ValueError("ZIP must contain exactly one bounded nvlddmkm.sys member")
            # ZipFile.read verifies the member CRC; SHA-256 below pins full bytes.
            raw = archive.read(members[0])
    else:
        if path.stat().st_size > MAX_DRIVER_BYTES:
            raise ValueError("driver size exceeds inspection cap")
        raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError("ORIGINAL_SHA256_MISMATCH expected=%s actual=%s" %
                         (EXPECTED_SHA256, digest))
    return raw, digest


def raw_direct_call_candidates(pe, ranges):
    """Raw E8 candidates only; these are NOT verified instruction boundaries."""
    found = []
    for name, rva, vs, rs, file_off, flags in pe.sections:
        if not flags & 0x20000000:
            continue
        data = pe.raw[file_off:file_off+rs]
        pos = 0
        while True:
            pos = data.find(b"\xE8", pos)
            if pos < 0 or pos+5 > len(data):
                break
            va = pe.base+rva+pos
            target = va+5+struct.unpack_from("<i", data, pos+1)[0]
            if any(start <= target < end for start, end in ranges):
                found.append((va, target, name, data[max(0, pos-8):pos+13].hex()))
            pos += 1
    return found


def disassemble_original(data, va):
    tool = shutil.which("objdump")
    if tool is None:
        return "DISASSEMBLY_UNAVAILABLE GNU objdump not on PATH; hex bytes are preserved"
    with tempfile.TemporaryDirectory(prefix="nv-slot-reader-") as directory:
        sample = Path(directory)/"original-code-window.bin"
        sample.write_bytes(data)
        command = [tool, "-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel",
                   "--adjust-vma=0x%x" % va, str(sample)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=20,
                                errors="replace", check=False)
        if result.returncode:
            return "DISASSEMBLY_FAILED exit=%d stderr=%s" % (result.returncode, result.stderr[:500])
        # Print only disassembly, not the temporary file path or redundant headers.
        lines = result.stdout.splitlines()
        lines = [line for line in lines if line.lstrip().startswith(tuple("0123456789abcdef"))
                 and ":" in line]
        return "\n".join(lines)


def report_for_original(raw, digest):
    pe = PE(raw)
    unwind = pe.unwind_ranges()
    lines = ["STATUS=READ_ONLY_ORIGINAL_PE", "DRIVER_SHA256=" + digest,
             "IMAGE_BASE=0x%x" % pe.base,
             "PROOF_LIMIT=Static machine bytes only; no physical GPU assignment, signed Booter record or loader invocation proof",
             "EXCEPTION_TABLE_ENTRIES=%d" % len(unwind)]
    selected = {}
    for site in SITES:
        actual = pe.read(site, len(SITE_BYTES), executable=True)
        if actual != SITE_BYTES:
            raise ValueError("original instruction mismatch at 0x%x expected=%s actual=%s" %
                             (site, SITE_BYTES.hex(), actual.hex()))
        ranges = [(start,end) for start,end,_ in unwind if start <= site < end]
        lines.append("SELECTOR_SITE=0x%x OPCODE=%s UNWIND_RANGES=%d" %
                     (site, actual.hex(), len(ranges)))
        if not ranges:
            lines.append("FUNCTION_BOUNDARY_UNAVAILABLE=0x%x cannot infer from nearby bytes" % site)
            window_start = site-64
            lines.append("SITE_HEX_CONTEXT=0x%x %s" %
                         (window_start, pe.read(window_start, 160, executable=True).hex()))
            continue
        for start, end in ranges:
            if end-start > MAX_FUNCTION_BYTES:
                lines.append("UNWIND_RANGE_TOO_LARGE start=0x%x end=0x%x" % (start,end))
                continue
            selected[(start,end)] = True
            lines.append("UNWIND_RANGE begin=0x%x end=0x%x byte_count=%d" %
                         (start,end,end-start))
    for start,end in selected:
        data = pe.read(start, end-start, executable=True)
        lines.append("FUNCTION_CODE_BEGIN start=0x%x end=0x%x full_sha256=%s" %
                     (start,end,hashlib.sha256(data).hexdigest()))
        # Preserve exact original bytes so the result is useful even if GNU objdump
        # is absent on the owner's Windows host. Avoid any loss through C decompilation.
        for offset in range(0, len(data), 64):
            lines.append("FUNCTION_HEX va=0x%x bytes=%s" %
                         (start+offset, data[offset:offset+64].hex()))
        lines.append(disassemble_original(data, start))
        lines.append("FUNCTION_CODE_END start=0x%x" % start)
    candidates = raw_direct_call_candidates(pe, selected.keys())
    lines.append("RAW_E8_CANDIDATES=%d displayed_max=%d" %
                 (len(candidates),MAX_CALL_CANDIDATES))
    for source,target,section,near in candidates[:MAX_CALL_CANDIDATES]:
        lines.append("POTENTIAL_DIRECT_CALL_RAW site=0x%x target=0x%x section=%s bytes=%s" %
                     (source,target,section,near))
        # Context may cover code across a function boundary: byte evidence only.
        try:
            context_start = source - 128
            lines.append("POTENTIAL_CALL_CONTEXT_HEX va=0x%x bytes=%s" %
                         (context_start, pe.read(context_start, 160, executable=True).hex()))
        except ValueError:
            lines.append("POTENTIAL_CALL_CONTEXT_UNAVAILABLE site=0x%x" % source)
    lines.append("LIMIT=E8 byte patterns are not instruction-boundary-verified; indirect calls and aliases are not found")
    lines.append("LIMIT=Unwind ranges can be funclets rather than whole functions")
    lines.append("HARDWARE_ACTION=NONE DRIVER_EXECUTION=NONE GHIDRA_MUTATION=NONE")
    return "\n".join(lines)+"\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input",required=True,help="Original nvlddmkm.sys or ZIP containing it")
    parser.add_argument("--report",required=True,help="New output text file")
    args = parser.parse_args()
    raw, digest = original_bytes(args.input)
    output = report_for_original(raw,digest)
    report = Path(args.report)
    if report.exists():
        raise ValueError("refusing to overwrite existing report: %s" % report)
    with report.open("x",encoding="utf-8",newline="\n") as stream:
        stream.write(output)
    print("STATUS=COMPLETE REPORT=%s SHA256=%s" %
          (report,hashlib.sha256(output.encode("utf-8")).hexdigest()))


if __name__ == "__main__":
    main()
