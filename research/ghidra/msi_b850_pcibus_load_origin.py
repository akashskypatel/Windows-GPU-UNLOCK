# @runtime PyGhidra
"""Read-only, bounded original MSI B850 1A70 PciBus LoadImage caller trace.

Run against the unmodified, SHA-256-pinned extracted PciBus EFI image in an
existing Ghidra Python 3 session. The report covers the *incoming* callers of
the already documented original image loader, its actual machine-level
LoadImage/StartImage arguments, and the surrounding original source. It does
not infer first-bind timing, signed firmware authenticity, or a safe release.
No Ghidra database, GPU hardware, UEFI variable, or driver is modified.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
import traceback

EXPECTED_SHA256 = "d341ffee887f7bb9e51e70d87c1fd16edf92d4360bf835829eb9aac1cda7615f"
EXPECTED_BASE = 0
LOADER = 0x9C38
LOAD_IMAGE_CALL = 0x9DC1
START_IMAGE_CALL = 0x9DF2
MODE_CHECK = 0x9DDD
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_INCOMING = 48
MAX_INSTRUCTIONS = 6000
MAX_FUNCTIONS = 16
MAX_C_CHARS = 90000
DECOMPILE_SECONDS = 18
BEFORE_CALL = 32
AFTER_CALL = 12


def program_address(program, value):
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(value)


def source_hash(path):
    item = Path(path)
    if not item.is_file():
        raise ValueError("Original extracted PciBus EFI file is not readable: %s" % item)
    if item.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError("Original PE exceeds bounded file size")
    data = item.read_bytes()
    return hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest()


def instruction_window(program, function, call_addr, emit):
    listing = program.getListing()
    it = listing.getInstructions(function.getBody(), True)
    insns = []
    while it.hasNext():
        if len(insns) >= MAX_INSTRUCTIONS:
            emit("INSTRUCTION_LIMIT function=%s max=%d" % (function.getName(), MAX_INSTRUCTIONS))
            return False
        insns.append(it.next())
    offset = int(call_addr)
    idx = next((i for i, ins in enumerate(insns)
                if int(ins.getAddress().getOffset()) == offset), None)
    if idx is None:
        emit("SITE_ABSENT function=%s address=0x%x" % (function.getName(), offset))
        return False
    for ins in insns[max(idx - BEFORE_CALL, 0):min(idx + AFTER_CALL + 1, len(insns))]:
        addr = int(ins.getAddress().getOffset())
        emit("INSN at=0x%x mnemonic=%s asm=%s" %
             (addr, str(ins.getMnemonicString()), str(ins)))
    return True


def decompile(function, interface, monitor, emit):
    res = interface.decompileFunction(function, DECOMPILE_SECONDS, monitor)
    if not res.decompileCompleted() or res.getDecompiledFunction() is None:
        emit("DECOMP_FAIL function=%s error=%s" %
             (function.getName(), str(res.getErrorMessage())))
        return False
    value = str(res.getDecompiledFunction().getC())
    if len(value) > MAX_C_CHARS:
        emit("DECOMP_TOO_LARGE function=%s chars=%d cap=%d" %
             (function.getName(), len(value), MAX_C_CHARS))
        return False
    emit("DECOMP_BEGIN function=%s clipped=False chars=%d" %
         (function.getName(), len(value)))
    emit(value)
    emit("DECOMP_END function=%s" % function.getName())
    return True


def direct_callers(program, target):
    seen = set()
    edges = []
    for ref in program.getReferenceManager().getReferencesTo(target):
        kind = ref.getReferenceType()
        if not kind.isCall():
            continue
        from_addr = ref.getFromAddress()
        key = int(from_addr.getOffset())
        if key in seen:
            continue
        seen.add(key)
        edges.append(from_addr)
    return sorted(edges, key=lambda a: int(a.getOffset()))


def run():
    program = globals().get("currentProgram")
    if program is None:
        raise RuntimeError("Open original extracted PciBus in Ghidra Python 3 first")
    if "pcibus" not in str(program.getName()).lower():
        raise ValueError("Current Ghidra program is not the original PciBus image")
    path = globals().get("PCIBUS_ORIGINAL_PE") or str(program.getExecutablePath())
    if not path:
        raise ValueError("Provide PCIBUS_ORIGINAL_PE pointing to the extracted original PE")
    digest, original_md5 = source_hash(path)
    program_md5 = str(program.getExecutableMD5() or "").lower()
    if program_md5 != original_md5:
        raise ValueError("Imported Ghidra program MD5 does not match pinned original PE bytes")
    if digest.lower() != EXPECTED_SHA256:
        raise ValueError("Original PciBus PE SHA-256 mismatch: %s" % digest)
    base = int(program.getImageBase().getOffset())
    if base != EXPECTED_BASE:
        raise ValueError("Original Ghidra program image base must be 0, got 0x%x" % base)

    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import TaskMonitor

    report_dir = Path(globals().get("PCIBUS_REPORT_DIR",
                          r"D:\Projects\gpu-unlock\ghidra"))
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / ("msi-b850-pcibus-loader-parents-%s.txt" %
                datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    status = "COMPLETE"
    decomp = None
    with report_path.open("x", encoding="utf-8") as fd:
        def say(value):
            line = str(value)
            fd.write(line + "\n")
            print(line)

        try:
            say("ORIGINAL_MSIB850_PCIBUS=1 READ_ONLY=1")
            say("PE_PATH=%s" % path)
            say("PE_SHA256=%s VERIFIED=1" % digest)
            say("IMAGE_BASE=0x%x EXPECTED=0x%x" % (base, EXPECTED_BASE))
            say("SOURCE_NOTE=STATIC_ONLY_NOT_A_HARDWARE_TEST")
            funcs = program.getFunctionManager()
            loader_addr = program_address(program, LOADER)
            loader = funcs.getFunctionAt(loader_addr)
            if loader is None:
                raise ValueError("Expected function at 0x%x not present" % LOADER)
            say("LOADER_ENTRY=0x%x NAME=%s" % (LOADER, loader.getName()))
            for label, address in (("LOAD_IMAGE", LOAD_IMAGE_CALL),
                                   ("MODE_CHECK", MODE_CHECK),
                                   ("START_IMAGE", START_IMAGE_CALL)):
                ins = program.getListing().getInstructionAt(program_address(program, address))
                if ins is None or not loader.getBody().contains(ins.getAddress()):
                    raise ValueError("%s is not in expected original loader" % label)
                say("%s_SITE=0x%x MNEMONIC=%s ASM=%s" %
                    (label, address, ins.getMnemonicString(), ins))
                if label != "MODE_CHECK" and str(ins.getMnemonicString()).upper() != "CALL":
                    raise ValueError("Original %s address is not a CALL" % label)

            decomp = DecompInterface()
            decomp.openProgram(program)
            say("LOADER_CALL_CONTEXT_BEGIN")
            for address in (LOAD_IMAGE_CALL, MODE_CHECK, START_IMAGE_CALL):
                if not instruction_window(program, loader, address, say):
                    status = "PARTIAL"
            say("LOADER_CALL_CONTEXT_END")
            if not decompile(loader, decomp, TaskMonitor.DUMMY, say):
                status = "PARTIAL"

            refs = direct_callers(program, loader_addr)
            say("DIRECT_INCOMING_CALLS=%d CAP=%d INDIRECT_CALLS_NOT_COVERED=1" %
                (len(refs), MAX_INCOMING))
            if len(refs) > MAX_INCOMING:
                status = "PARTIAL"
            seen_funcs = {LOADER}
            for call in refs[:MAX_INCOMING]:
                fn = funcs.getFunctionContaining(call)
                if fn is None:
                    say("CALLER_UNRESOLVED at=0x%x" % call.getOffset())
                    status = "PARTIAL"
                    continue
                entry = int(fn.getEntryPoint().getOffset())
                say("CALLER_SITE at=0x%x function=0x%x name=%s" %
                    (call.getOffset(), entry, fn.getName()))
                if not instruction_window(program, fn, call.getOffset(), say):
                    status = "PARTIAL"
                if entry not in seen_funcs:
                    if len(seen_funcs) >= MAX_FUNCTIONS:
                        say("CALLER_FUNCTION_LIMIT cap=%d" % MAX_FUNCTIONS)
                        status = "PARTIAL"
                    else:
                        seen_funcs.add(entry)
                        if not decompile(fn, decomp, TaskMonitor.DUMMY, say):
                            status = "PARTIAL"
            say("PROVEN_SPECIFIC_LOADIMAGE_MACHINE_INPUTS=ORIGINAL_LISTING_ONLY")
            say("PROVEN_GA102_EXCLUSIVE_POLICY=FALSE")
            say("PROVEN_HARDWARE_BIND_ORDER=FALSE")
            say("GPU_MUTATION=NONE GHIDRA_MUTATION=NONE")
        except Exception:
            status = "ERROR"
            say("ERROR=" + traceback.format_exc())
        finally:
            if decomp is not None:
                decomp.dispose()
            say("STATUS=%s REPORT=%s" % (status, report_path))
    return status


if __name__ == "__main__":
    run()
