# @runtime PyGhidra
"""Bounded, read-only Windows 617.42 Falcon loader-call data-flow candidates.

Use with the previously analyzed, MD5-pinned original nvlddmkm.sys. This is a
new call-input def-use check, not the completed +0x108 linear register scan.
It NEVER establishes runtime receiver identity, signature acceptance or GPU use.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
import re
import time
import traceback

DRIVER_MD5 = '3fb9afac9d0e394723e830aa14e60512'
DRIVER_BASE = 0x140000000
REPORT_DIR = Path(r'D:\Projects\gpu-unlock\ghidra')
MAX_SCAN_BYTES = 64 * 1024 * 1024
MAX_SECONDS = 85
CHUNK_SIZE = 256 * 1024
MAX_FUNCTIONS = 48
MAX_SEEDS = 240
MAX_CALLS_PER_FUNCTION = 40
MAX_PCODE_PER_FUNCTION = 30000
MAX_RECURSION = 14
DECOMP_SECONDS = 12
SLOT = 0x170
OWNER_LINK = 0x108
NEEDLE = SLOT.to_bytes(4, 'little')
# Only a qword read or indirect transfer may be a consumer; exclude stores and
# arithmetic constants. The old scan already classified registration writes.
READ_RE = re.compile(r'^(?:MOV|MOVZX|MOVSXD)\s+[^,]+,\s*(?:(?:qword|dword|word|byte) ptr\s+)?\[[^\]\n]*\+\s*0x170\b[^\]\n]*\]$', re.I)
TRANSFER_RE = re.compile(r'^(?:CALL|JMP)\s+(?:qword ptr\s+)?\[[^\]\n]*\+\s*0x170\b[^\]\n]*\]$', re.I)
TRANSPARENT = frozenset(('COPY', 'CAST', 'INT_ZEXT', 'INT_SEXT', 'SUBPIECE', 'INDIRECT', 'MULTIEQUAL'))


def read_candidate(asm):
    """An operand-shaped read, not a literal constant or callback writer."""
    return bool(READ_RE.match(asm) or TRANSFER_RE.match(asm))


def _inputs(op):
    return [op.getInput(i) for i in range(min(int(op.getNumInputs()), 20))]


def _definition(node):
    return node.getDef() if node is not None else None


def _const(node):
    if node is None or not node.isConstant():
        return None
    return int(node.getOffset())


def _base_for_offset(address_node, offset, depth=MAX_RECURSION, seen=None):
    """Yield explicit pointer bases at address +offset, without alias guesses."""
    if address_node is None or depth <= 0:
        return
    seen = set() if seen is None else seen
    key = id(address_node)
    if key in seen:
        return
    seen.add(key)
    op = _definition(address_node)
    if op is None:
        return
    name = str(op.getMnemonic())
    args = _inputs(op)
    if name in ('INT_ADD', 'PTRSUB') and len(args) >= 2:
        if _const(args[1]) == offset:
            yield args[0]
        if name == 'INT_ADD' and _const(args[0]) == offset:
            yield args[1]
    elif name == 'PTRADD' and len(args) >= 3:
        # p-code PTRADD(base,index,element_size): accept only exact constants.
        index, scale = _const(args[1]), _const(args[2])
        if index is not None and scale is not None and index * scale == offset:
            yield args[0]
    elif name in ('COPY', 'CAST', 'INT_ZEXT', 'INT_SEXT', 'INDIRECT') and args:
        yield from _base_for_offset(args[0], offset, depth - 1, seen)
    elif name == 'MULTIEQUAL':
        for arg in args:
            yield from _base_for_offset(arg, offset, depth - 1, seen)


def _load_bases(value, offset, depth=MAX_RECURSION, seen=None):
    """Return only explicit LOAD(value=*[base+offset]) provenance branches."""
    if value is None or depth <= 0:
        return []
    seen = set() if seen is None else seen
    key = id(value)
    if key in seen:
        return []
    seen.add(key)
    op = _definition(value)
    if op is None:
        return []
    name = str(op.getMnemonic())
    args = _inputs(op)
    if name == 'LOAD' and len(args) >= 2:
        return list(_base_for_offset(args[1], offset, depth - 1))
    if name in TRANSPARENT and args:
        # INDIRECT's second input is an internal operation reference, not value
        # provenance; MULTIEQUAL alternatives remain separate candidates.
        flow = args if name == 'MULTIEQUAL' else args[:1]
        results = []
        for item in flow:
            results.extend(_load_bases(item, offset, depth - 1, seen.copy()))
        return results
    return []


def classify_call_input(node):
    """Return (loads method at +0x170, nested pointer from +0x108).

    Does not establish call target identity or same allocation across functions.
    """
    bases = _load_bases(node, SLOT)
    return bool(bases), any(_load_bases(base, OWNER_LINK) for base in bases)


def _memory_bytes(memory, addr, size):
    from jpype import JArray, JByte
    buf = JArray(JByte)(size)
    if int(memory.getBytes(addr, buf)) != size:
        raise ValueError('short memory read')
    return bytes(int(item) & 0xff for item in buf)


def _address(program, number):
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(int(number))


def discover_function_seeds(program, say, deadline):
    """Bounded existing-instruction consumer seeds, no new disassembly."""
    memory = program.getMemory()
    listing = program.getListing()
    manager = program.getFunctionManager()
    blocks = sorted((b for b in memory.getBlocks() if b.isExecute() and b.isInitialized()),
                    key=lambda b: int(b.getStart().getOffset()))
    found, instructions = {}, set()
    scanned = raw_hits = verified = 0
    complete = True
    for block in blocks:
        size = int(block.getSize())
        base = int(block.getStart().getOffset())
        pos, previous = 0, b''
        while pos < size:
            if time.monotonic() >= deadline or scanned >= MAX_SCAN_BYTES:
                complete = False
                say('SEED_SCAN_TRUNCATED reason=time_or_bytes block=%s remaining=%d' % (block.getName(), size-pos))
                break
            take = min(CHUNK_SIZE, size-pos, MAX_SCAN_BYTES-scanned)
            payload = _memory_bytes(memory, _address(program, base+pos), take)
            combined = previous + payload
            offset = 0
            while True:
                index = combined.find(NEEDLE, offset)
                if index < 0:
                    break
                offset = index + 1
                if index + len(NEEDLE) <= len(previous):
                    continue
                raw_hits += 1
                insn = listing.getInstructionContaining(_address(program, base+pos+index-len(previous)))
                if insn is None or not read_candidate(str(insn)):
                    continue
                va = int(insn.getAddress().getOffset())
                if va in instructions:
                    continue
                instructions.add(va)
                fn = manager.getFunctionContaining(insn.getAddress())
                if fn is None:
                    continue
                verified += 1
                entry = int(fn.getEntryPoint().getOffset())
                if entry not in found and len(found) >= MAX_FUNCTIONS:
                    complete = False
                    continue
                sites = found.setdefault(entry, [])
                if len(sites) >= MAX_SEEDS:
                    complete = False
                    continue
                sites.append((va, str(insn)))
            previous = combined[-(len(NEEDLE)-1):]
            scanned += take
            pos += take
        if not complete and (time.monotonic() >= deadline or scanned >= MAX_SCAN_BYTES):
            break
    say('SEED_SCAN_SUMMARY bytes=%d raw_matches=%d existing_consumers=%d function_candidates=%d complete=%s' %
        (scanned, raw_hits, verified, len(found), complete))
    return found, complete


def inspect_function(program, decompiler, entry, seeds, say, deadline):
    from ghidra.program.model.pcode import PcodeOp
    from ghidra.util.task import TaskMonitor
    fn = program.getFunctionManager().getFunctionAt(_address(program, entry))
    if fn is None:
        say('FUNCTION_MISSING entry=0x%x' % entry)
        return False
    say('FUNCTION_BEGIN entry=0x%x consumer_seeds=%d' % (entry, len(seeds)))
    for addr, asm in seeds:
        say('  EXISTING_READ va=0x%x asm=%s' % (addr, asm))
    if time.monotonic() >= deadline:
        say('FUNCTION_TIMEOUT entry=0x%x' % entry)
        return False
    result = decompiler.decompileFunction(fn, DECOMP_SECONDS, TaskMonitor.DUMMY)
    if result is None or not result.decompileCompleted():
        say('DECOMPILER_UNAVAILABLE entry=0x%x' % entry)
        return False
    high = result.getHighFunction()
    if high is None:
        return False
    ops = high.getPcodeOps()
    seen_ops = calls = flow_candidates = 0
    complete = True
    while ops.hasNext():
        op = ops.next()
        seen_ops += 1
        if seen_ops > MAX_PCODE_PER_FUNCTION or time.monotonic() >= deadline:
            say('PCODE_TRUNCATED entry=0x%x limit_or_deadline=TRUE' % entry)
            complete = False
            break
        if op.getOpcode() != PcodeOp.CALLIND:
            continue
        calls += 1
        if calls > MAX_CALLS_PER_FUNCTION:
            say('CALLIND_TRUNCATED entry=0x%x cap=%d' % (entry, MAX_CALLS_PER_FUNCTION))
            complete = False
            break
        args = _inputs(op)
        flowing = [(i, *classify_call_input(arg)) for i, arg in enumerate(args)]
        active = [row for row in flowing if row[1]]
        if active:
            flow_candidates += 1
            evidence = ','.join('%d:slot170=%s:outer108=%s' % x for x in active)
            say('  CALL_INPUT_FLOW va=%s inputs=%d traces=%s same_instance_unproven=TRUE' %
                (op.getSeqnum().getTarget(), len(args), evidence))
    say('FUNCTION_END entry=0x%x callind=%d traced=%d pcode=%d complete=%s' %
        (entry, min(calls, MAX_CALLS_PER_FUNCTION), flow_candidates, seen_ops, complete))
    return complete


def main():
    start = time.monotonic()
    report = None
    stream = None
    decompiler = None
    status = 'ERROR'
    def say(line):
        print(line)
        if stream is not None:
            stream.write(line+'\n')
    try:
        program = globals().get('currentProgram')
        if program is None:
            raise ValueError('currentProgram is required')
        name = str(program.getName())
        md5 = str(program.getExecutableMD5() or '').lower()
        base = int(program.getImageBase().getOffset())
        if not name.lower().endswith('nvlddmkm.sys') or md5 != DRIVER_MD5 or base != DRIVER_BASE:
            raise ValueError('WRONG_BINARY name=%s md5=%s base=0x%x' % (name, md5, base))
        directory = Path(globals().get('REPORT_DIR', REPORT_DIR))
        directory.mkdir(parents=True, exist_ok=True)
        report = directory / ('nvlddmkm-61742-loader-call-flow-%s.txt' % datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
        stream = report.open('x', encoding='utf-8', buffering=1)
        say('STATUS=RUNNING')
        say('IDENTITY=nvlddmkm.sys MD5=%s BASE=0x%x' % (md5, base))
        say('MODE=READ_ONLY EXISTING_INSTRUCTIONS_AND_HIGH_PCODE NO_GHIDRA_OR_GPU_WRITES')
        say('METHOD=+0x170 existing-read seeds; CALLIND input LOAD def-use; optional same-chain +0x108')
        say('LIMIT=CFG guarded dispatch may hide real target as implicit register; missing result is not negative proof')
        seeds, complete = discover_function_seeds(program, say, start+MAX_SECONDS)
        from ghidra.app.decompiler import DecompInterface
        decompiler = DecompInterface()
        if not decompiler.openProgram(program):
            raise RuntimeError('Ghidra decompiler initialization failed')
        for entry, sites in sorted(seeds.items()):
            if time.monotonic() >= start+MAX_SECONDS:
                complete = False
                say('TIME_LIMIT before_function=0x%x' % entry)
                break
            if not inspect_function(program, decompiler, entry, sites, say, start+MAX_SECONDS):
                complete = False
        say('PROVEN_SAME_PUBLISHED_RECEIVER=FALSE')
        say('ORIGINAL_WINDOWS_SIGNED_BOOTER_SOURCE_PROVEN=FALSE')
        say('FIRMWARE_ACCEPTANCE_OR_HARDWARE_TEST=FALSE')
        say('HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE')
        status = 'COMPLETE' if complete else 'PARTIAL'
    except KeyboardInterrupt:
        status = 'PARTIAL'
        say('INTERRUPTED')
    except Exception:
        status = 'ERROR'
        say('ERROR='+traceback.format_exc())
    finally:
        if decompiler is not None:
            decompiler.dispose()
        say('ELAPSED_SECONDS=%.3f' % (time.monotonic()-start))
        say('STATUS=%s REPORT=%s' % (status, report if report is not None else '<not-created>'))
        if stream is not None:
            stream.close()
    return status


if __name__ == '__main__':
    main()