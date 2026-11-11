# @runtime PyGhidra
"""Read-only bounded data-flow evidence for the unresolved Windows 617.42 Falcon receiver.

Run in the ORIGINAL MD5-pinned nvlddmkm.sys PyGhidra project, not Linux GSP.
No disassembly, analysis, renaming, database writes, driver calls, or GPU I/O.
Existing high-level p-code can suggest data flow; it does NOT prove runtime
callback identity, signed Booter acceptance or firmware selection.
"""
from __future__ import annotations
from datetime import datetime
from pathlib import Path
import time
import traceback

EXPECTED_MD5 = "3fb9afac9d0e394723e830aa14e60512"
EXPECTED_BASE = 0x140000000
REPORT_DIR = Path(r"D:\Projects\gpu-unlock\ghidra")
FUNCTION_RECORD = 0x140e19a0c        # Consecutive 32-bit RVAs; not a 64-bit loader pointer.
FOCUSED_FIELD_SITES = (0x1417e8b32, 0x1417e8e45, 0x1417e8ef9,
                       0x1417e983c, 0x1417e985a)
MAX_FOCUSED_OPS_PER_SITE = 16
LOADER = 0x140bf3880                  # Original flcnLoadAndExecuteHsBinaryViaDma_GA10X.
REGISTRATION_SITES = (0x1417e8e3e, 0x1417e8e45)  # Existing nested +0x170 callback stores.
FIELD_OFFSETS = frozenset((0x108, 0x170, 0x250, 0x3e8))
MAX_FUNCTIONS = 6
MAX_INBOUND = 32
MAX_CALLIND_PER_FUNCTION = 20
MAX_FIELD_OPS_PER_FUNCTION = 18
MAX_PCODE_OPS = 25000
DECOMP_TIMEOUT_SECONDS = 12
WALL_SECONDS = 85


def va(program, number):
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(int(number))


def decode_runtime_function_record(words, base, loader):
    """Interpret possible Windows x64 exception metadata, not callback use."""
    if len(words) != 3 or any(type(w) is not int or w < 0 or w > 0xffffffff
                              for w in words):
        raise ValueError("exactly three unsigned 32-bit relative virtual addresses required")
    begin, end, unwind = words
    return {"begin_rva": begin, "end_rva": end, "unwind_rva": unwind,
            "begin": base + begin, "end": base + end, "unwind": base + unwind,
            "candidate": begin != 0 and begin < end and unwind != 0 and
                         base + begin == loader}


def inspect_function_record(program, say):
    """Report all three fields and memory sections; do not label it a pointer."""
    address = va(program, FUNCTION_RECORD)
    memory = program.getMemory()
    block = memory.getBlock(address)
    if block is None or not block.isInitialized():
        say("FUNCTION_RECORD_UNAVAILABLE address=%s" % address)
        return False
    try:
        fields = tuple(int(memory.getInt(va(program, FUNCTION_RECORD + offset))) &
                       0xffffffff for offset in (0, 4, 8))
        record = decode_runtime_function_record(fields, EXPECTED_BASE, LOADER)
        start_block = memory.getBlock(va(program, record["begin"]))
        unwind_block = memory.getBlock(va(program, record["unwind"]))
        say("FUNCTION_RECORD_CANDIDATE address=%s section=%s begin_rva=0x%x "
            "end_rva=0x%x unwind_rva=0x%x begin_va=0x%x end_exclusive_va=0x%x "
            "unwind_va=0x%x beginning_matches_loader=%s start_executable=%s "
            "unwind_mapped=%s pointer_slot=FALSE type_not_proven=TRUE" %
            (address, block.getName(), record["begin_rva"], record["end_rva"],
             record["unwind_rva"], record["begin"], record["end"],
             record["unwind"], record["candidate"],
             bool(start_block is not None and start_block.isExecute()),
             unwind_block is not None))
        return True
    except Exception as exc:
        say("FUNCTION_RECORD_READ_ERROR address=%s error=%s" %
            (address, type(exc).__name__))
        return False


def format_focused_op(fn, op, address):
    """Describe an exact-site p-code read/write without claiming a receiver."""
    inputs = ";".join(fmt_node(op.getInput(i), 2) for i in
                      range(min(int(op.getNumInputs()), 5)))
    return ("FOCUSED_PCODE function=%s address=%s op=%s output=%s inputs=%s "
            "callback_invoke_not_proven=TRUE" %
            (fn.getEntryPoint(), address, op.getMnemonic(),
             fmt_node(op.getOutput(), 1), inputs))


def fmt_node(node, depth=2):
    if node is None:
        return "NULL"
    value = str(node)
    try:
        if node.isConstant():
            value += "[const=0x%x]" % int(node.getOffset())
        definition = node.getDef()
        if depth and definition is not None:
            count = min(int(definition.getNumInputs()), 3)
            inputs = ",".join(fmt_node(definition.getInput(i), depth - 1)
                              for i in range(count))
            value += "<%s(%s)>" % (definition.getMnemonic(), inputs)
    except Exception as exc:
        value += "[definition_error=%s]" % type(exc).__name__
    return value[:600]


def existing_instruction_window(program, location, say):
    listing = program.getListing()
    address = va(program, location)
    instruction = listing.getInstructionContaining(address)
    if instruction is None:
        say("SITE_UNAVAILABLE address=%s no_existing_instruction" % address)
        return False
    func = program.getFunctionManager().getFunctionContaining(address)
    say("SITE address=%s instruction_start=%s function=%s text=%s" %
        (address, instruction.getAddress(),
         func.getEntryPoint() if func is not None else "UNKNOWN", instruction))
    previous = instruction
    before = []
    for unused in range(5):
        earlier = listing.getInstructionBefore(previous.getAddress())
        if earlier is None or (func is not None and not func.getBody().contains(earlier.getAddress())):
            break
        before.insert(0, earlier)
        previous = earlier
    for ins in before:
        say("  PREVIOUS address=%s asm=%s" % (ins.getAddress(), ins))
    later = instruction
    for unused in range(5):
        later = listing.getInstructionAfter(later.getAddress())
        if later is None or (func is not None and not func.getBody().contains(later.getAddress())):
            break
        say("  FOLLOWING address=%s asm=%s" % (later.getAddress(), later))
    return True


def candidate_functions(program, say):
    manager = program.getFunctionManager()
    refs = program.getReferenceManager()
    found = {}
    complete = True
    loader = manager.getFunctionAt(va(program, LOADER))
    if loader is None:
        say("LOADER_UNAVAILABLE address=0x%x no_existing_function" % LOADER)
        return None, False
    found[int(loader.getEntryPoint().getOffset())] = loader

    for number in REGISTRATION_SITES:
        fn = manager.getFunctionContaining(va(program, number))
        if fn is None:
            say("REGISTRATION_OWNER_UNAVAILABLE site=0x%x" % number)
            return None, False
        found[int(fn.getEntryPoint().getOffset())] = fn

    # Possible exception metadata is not a callback pointer slot.
    # No metadata reference or address-taken reference is an actual call.
    for target, name in ((FUNCTION_RECORD, "FUNCTION_RECORD_CANDIDATE"),
                         (LOADER, "LOADER_ENTRY")):
        count = 0
        for reference in refs.getReferencesTo(va(program, target)):
            if count >= MAX_INBOUND:
                say("XREF_TRUNCATED target=%s cap=%d" % (name, MAX_INBOUND))
                complete = False
                break
            origin = reference.getFromAddress()
            fn = manager.getFunctionContaining(origin)
            say("XREF target=%s source=%s kind=%s function=%s" %
                (name, origin, reference.getReferenceType(),
                 fn.getEntryPoint() if fn is not None else "NONE"))
            if fn is not None:
                key = int(fn.getEntryPoint().getOffset())
                if key not in found and len(found) >= MAX_FUNCTIONS:
                    say("FUNCTION_LIMIT_OMISSION entry=%s cap=%d" %
                        (fn.getEntryPoint(), MAX_FUNCTIONS))
                    complete = False
                else:
                    found[key] = fn
            count += 1
        say("XREF_OBSERVED target=%s count=%d (bounded)" % (name, count))
    return [found[k] for k in sorted(found)], complete


def dump_high_pcode(decompiler, fn, say):
    from ghidra.util.task import TaskMonitor
    from ghidra.program.model.pcode import PcodeOp

    result = decompiler.decompileFunction(fn, DECOMP_TIMEOUT_SECONDS, TaskMonitor.DUMMY)
    if result is None or not result.decompileCompleted() or result.getHighFunction() is None:
        say("DECOMP_FAIL function=%s reason=%s" %
            (fn.getEntryPoint(), result.getErrorMessage() if result else "NULL"))
        return False
    high = result.getHighFunction()
    calls, fields, total = 0, 0, 0
    focus_counts = {site: 0 for site in FOCUSED_FIELD_SITES}
    excess_fields = False
    truncated = False
    for op in high.getPcodeOps():
        total += 1
        if total > MAX_PCODE_OPS:
            say("PCODE_TRUNCATED function=%s cap=%d" % (fn.getEntryPoint(), MAX_PCODE_OPS))
            truncated = True
            break
        location = op.getSeqnum().getTarget()
        site = int(location.getOffset())
        if int(fn.getEntryPoint().getOffset()) == 0x1417e8550 and site in focus_counts:
            focus_counts[site] += 1
            if focus_counts[site] <= MAX_FOCUSED_OPS_PER_SITE:
                say(format_focused_op(fn, op, location))
            else:
                truncated = True
        if op.getOpcode() == PcodeOp.CALLIND:
            if calls >= MAX_CALLIND_PER_FUNCTION:
                truncated = True
                continue
            calls += 1
            inputs = min(int(op.getNumInputs()), 5)
            say("CALLIND function=%s address=%s inputs=%d target_and_args_pcode_not_runtime_proof=1" %
                (fn.getEntryPoint(), location, int(op.getNumInputs())))
            for n in range(inputs):
                say("  CALLIND_INPUT index=%d evidence=%s" % (n, fmt_node(op.getInput(n))))
        else:
            for index in range(int(op.getNumInputs())):
                node = op.getInput(index)
                if node is not None and node.isConstant() and int(node.getOffset()) in FIELD_OFFSETS:
                    fields += 1
                    if fields > MAX_FIELD_OPS_PER_FUNCTION:
                        excess_fields = True
                        break
                    say("FIELD_PCODE function=%s address=%s op=%s operand=%d offset=0x%x other_inputs=%s" %
                        (fn.getEntryPoint(), location, op.getMnemonic(), index,
                         int(node.getOffset()), ";".join(fmt_node(op.getInput(k), 1)
                         for k in range(min(int(op.getNumInputs()), 3)))))
                    break
    if int(fn.getEntryPoint().getOffset()) == 0x1417e8550:
        for site, count in sorted(focus_counts.items()):
            say("FOCUSED_SITE_SUMMARY address=0x%x pcode_ops=%d capped=%s" %
                (site, count, count > MAX_FOCUSED_OPS_PER_SITE))
            if count == 0:
                truncated = True
    truncated = truncated or excess_fields
    say("PCODE_SUMMARY function=%s inspected=%d callind_recorded=%d offset_ops_recorded=%d truncated=%s" %
        (fn.getEntryPoint(), total, calls, min(fields, MAX_FIELD_OPS_PER_FUNCTION), str(truncated)))
    return not truncated


def main():
    started = time.monotonic()
    status = "ERROR"
    report = None
    stream = None
    def say(line):
        message = str(line)
        if stream is not None:
            stream.write(message + "\n")
            stream.flush()
        print(message)
    decompiler = None
    try:
        program = globals().get("currentProgram")
        if program is None:
            raise RuntimeError("Pass currentProgram=state.getCurrentProgram(); no program is selected")
        md5 = str(program.getExecutableMD5()).lower()
        image_base = int(program.getImageBase().getOffset())
        if md5 != EXPECTED_MD5 or image_base != EXPECTED_BASE:
            raise ValueError("Original Windows 617.42 driver mismatch: MD5=%s BASE=0x%x" % (md5, image_base))
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        report = REPORT_DIR / ("nvlddmkm-61742-callback-pcode-%s.txt" %
                               datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
        stream = report.open("w", encoding="utf-8")
        say("IDENTITY=nvlddmkm.sys MD5=%s BASE=0x%x" % (md5, image_base))
        say("MODE=PASSIVE READ_ONLY EXISTING_GHIDRA_ANALYSIS NO_DATABASE_WRITES NO_DEVICE_ACTION")
        say("METHOD=Exact prior registration and five source-grounded field sites, bounded p-code operations and 12-byte function-record candidate")
        say("LIMIT=Not a complete indirect call graph; no asserted same-instance target or signed firmware acceptance")
        complete = inspect_function_record(program, say)
        for site in REGISTRATION_SITES + FOCUSED_FIELD_SITES:
            complete = existing_instruction_window(program, site, say) and complete
        functions, candidates_complete = candidate_functions(program, say)
        complete = candidates_complete and complete
        if not functions:
            complete = False
        else:
            from ghidra.app.decompiler import DecompInterface
            decompiler = DecompInterface()
            if not decompiler.openProgram(program):
                raise RuntimeError("Ghidra decompiler openProgram failed")
            for fn in functions[:MAX_FUNCTIONS]:
                if time.monotonic() - started > WALL_SECONDS:
                    say("TIME_LIMIT_REACHED before_function=%s" % fn.getEntryPoint())
                    complete = False
                    break
                say("PCODE_FUNCTION_BEGIN entry=%s name=%s" %
                    (fn.getEntryPoint(), fn.getName()))
                if not dump_high_pcode(decompiler, fn, say):
                    complete = False
        status = "COMPLETE" if complete else "PARTIAL"
        say("STOCK_WINDOWS_BOOTER_ORIGIN_PROVEN=FALSE")
        say("ACTUAL_NESTED_LOADER_INVOCATION_PROVEN=FALSE")
        say("ARGUMENT_THREE_DESCRIPTOR_PROVEN=FALSE")
        say("HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE")
    except KeyboardInterrupt:
        status = "PARTIAL"
        say("INTERRUPTED=KeyboardInterrupt")
    except Exception:
        status = "ERROR"
        say("ERROR=" + traceback.format_exc())
    finally:
        if decompiler is not None:
            decompiler.dispose()
        say("ELAPSED_SECONDS=%.3f" % (time.monotonic() - started))
        say("STATUS=%s REPORT=%s" % (status, report if report else "<not-created>"))
        if stream is not None:
            stream.close()
    return status


if __name__ == "__main__":
    main()
