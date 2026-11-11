# @runtime PyGhidra
"""Bounded, read-only Windows 617.42 Falcon loader-call data-flow candidates.

Use with the previously analyzed, MD5-pinned original nvlddmkm.sys. This is a
new call-input def-use check, not the completed +0x108 linear register scan.
It NEVER establishes runtime receiver identity, signature acceptance or GPU use.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import time
import traceback

DRIVER_MD5 = '3fb9afac9d0e394723e830aa14e60512'
DRIVER_BASE = 0x140000000
REPORT_DIR = Path(r'D:\Projects\gpu-unlock\ghidra')
GRAPH_FILE = REPORT_DIR / 'nvlddmkm-61742-booter-discovery-20261110-134621-824423-reference-graph.json'
GRAPH_SCHEMA = 'ghidra-static-function-references-v3'
GRAPH_ROOTS = frozenset(('0x140bf3880', '0x14179e530', '0x140aece90'))
MAX_GRAPH_BYTES = 8 * 1024 * 1024
MAX_GRAPH_NODES = 2048
MAX_GRAPH_EDGES = 16384
MAX_GRAPH_CALL_SITES = 256
MAX_GRAPH_FUNCTIONS = 128
MAX_SCAN_BYTES = 64 * 1024 * 1024
MAX_SECONDS = 120
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
    # Bulk buffer conversion is essential: per-byte JPype access exhausted the
    # entire 85-second budget after only 1 MiB in the owner's first report.
    try:
        return memoryview(buf).tobytes()
    except (TypeError, BufferError):
        # Correctness fallback for an incompatible bridge; not fast-path proof.
        return bytes(int(item) & 0xff for item in buf)


def _address(program, number):
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(int(number))


def validate_graph(graph):
    """Extract bounded unresolved call sites from the completed original graph.

    A graph is static reference evidence, NOT proof of a real loader callback.
    Reject partial, foreign-schema, or inconsistent snapshots rather than scan
    unrelated driver code to compensate.
    """
    if not isinstance(graph, dict) or graph.get('schema') != GRAPH_SCHEMA:
        raise ValueError('unsupported existing-reference graph schema')
    if graph.get('status') != 'COMPLETE' or graph.get('omissions') != []:
        raise ValueError('graph contains unresolved scan omissions')
    roots = graph.get('roots')
    if not isinstance(roots, list) or not GRAPH_ROOTS.issubset(set(roots)):
        raise ValueError('graph does not contain the three previously reviewed source roots')
    nodes, edges = graph.get('nodes'), graph.get('edges')
    if (not isinstance(nodes, list) or not isinstance(edges, list) or
            len(nodes) > MAX_GRAPH_NODES or len(edges) > MAX_GRAPH_EDGES):
        raise ValueError('graph nodes/edges absent or exceed bounded source limits')
    lookup = {}
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get('id'), str):
            raise ValueError('malformed graph node')
        if node['id'] in lookup:
            raise ValueError('duplicate graph node id')
        lookup[node['id']] = node
    sites = set()
    for edge in edges:
        if not isinstance(edge, dict) or edge.get('kind') != 'INDIRECT_UNKNOWN':
            continue
        source = lookup.get(edge.get('source'))
        target = lookup.get(edge.get('target'))
        if (source is None or target is None or source.get('kind') != 'FUNCTION' or
                target.get('kind') != 'INDIRECT'):
            raise ValueError('unresolved graph edge has invalid owner or target')
        raw = edge.get('site')
        if not isinstance(raw, str) or not re.fullmatch(r'0x[0-9a-fA-F]{9,16}', raw):
            raise ValueError('invalid indirect-call virtual address')
        address = int(raw, 16)
        if not DRIVER_BASE <= address < DRIVER_BASE + (1 << 32):
            raise ValueError('graph site outside original driver image range')
        if source.get('entry') is None or int(source['entry'], 16) > address:
            raise ValueError('bad source entry for graph site')
        sites.add(address)
        if len(sites) > MAX_GRAPH_CALL_SITES:
            raise ValueError('too many graph unresolved call sites')
    if not sites:
        raise ValueError('graph has no original unresolved call sites')
    return sorted(sites)


def graph_function_candidates(program, graph_path, say):
    """Validate a completed source graph against existing Ghidra call sites."""
    path = Path(graph_path)
    if not path.is_file():
        raise FileNotFoundError('previous source graph missing: %s' % path)
    if path.stat().st_size > MAX_GRAPH_BYTES:
        raise ValueError('source graph file too large')
    data = path.read_bytes()
    graph = json.loads(data.decode('utf-8'))
    sites = validate_graph(graph)
    say('GRAPH_INPUT path=%s bytes=%d sha256=%s schema=%s' %
        (path, len(data), hashlib.sha256(data).hexdigest(), GRAPH_SCHEMA))
    listing, manager = program.getListing(), program.getFunctionManager()
    found = {}
    invalid = 0
    for site in sites:
        addr = _address(program, site)
        instruction = listing.getInstructionAt(addr)
        fn = manager.getFunctionContaining(addr)
        if (instruction is None or fn is None or
                str(instruction.getMnemonicString()).upper() not in ('CALL', 'JMP')):
            invalid += 1
            say('GRAPH_SITE_UNAVAILABLE va=0x%x original_instruction_missing_or_not_transfer=TRUE' % site)
            continue
        entry = int(fn.getEntryPoint().getOffset())
        if entry not in found and len(found) >= MAX_GRAPH_FUNCTIONS:
            raise ValueError('graph call-site owner count exceeds limit')
        found.setdefault(entry, []).append((site, str(instruction)))
    say('GRAPH_SITE_SUMMARY recorded_sites=%d validated_sites=%d unavailable_sites=%d owning_functions=%d' %
        (len(sites), len(sites)-invalid, invalid, len(found)))
    if invalid:
        raise ValueError('source graph references missing or changed original instructions')
    return found


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


def inspect_function(program, decompiler, entry, seeds, say, deadline, graph_mode=False):
    from ghidra.program.model.pcode import PcodeOp
    from ghidra.util.task import TaskMonitor
    fn = program.getFunctionManager().getFunctionAt(_address(program, entry))
    if fn is None:
        say('FUNCTION_MISSING entry=0x%x' % entry)
        return False
    say('FUNCTION_BEGIN entry=0x%x %s=%d' %
        (entry, 'graph_call_sites' if graph_mode else 'consumer_seeds', len(seeds)))
    for addr, asm in seeds:
        say('  EXISTING_GRAPH_CALL va=0x%x asm=%s' % (addr, asm) if graph_mode
            else '  EXISTING_READ va=0x%x asm=%s' % (addr, asm))
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
    graph_sites = {addr for addr, _ in seeds} if graph_mode else set()
    pcode_graph_sites = set()
    complete = True
    while ops.hasNext():
        op = ops.next()
        seen_ops += 1
        if seen_ops > MAX_PCODE_PER_FUNCTION or time.monotonic() >= deadline:
            say('PCODE_TRUNCATED entry=0x%x limit_or_deadline=TRUE' % entry)
            complete = False
            break
        try:
            op_site = int(op.getSeqnum().getTarget().getOffset())
        except (AttributeError, TypeError):
            op_site = -1
        in_graph = graph_mode and op_site in graph_sites
        if in_graph and op.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND):
            pcode_graph_sites.add(op_site)
            say('  GRAPH_SITE_PCODE va=0x%x opcode=%s inputs=%d call_target_unresolved=TRUE' %
                (op_site, op.getMnemonic(), op.getNumInputs()))
        if in_graph and op.getOpcode() == PcodeOp.CALL:
            # A direct guarded-dispatch call is NOT an indirect-loader call.
            # Record only explicit input provenance, not an inferred target.
            guard_args = _inputs(op)
            guarded = [(i, *classify_call_input(arg)) for i, arg in enumerate(guard_args)]
            found = [row for row in guarded if row[1]]
            if found:
                say('  GRAPH_GUARDED_ARGUMENT_FLOW va=0x%x inputs=%d traces=%s method_target_unproven=TRUE' %
                    (op_site, len(guard_args), ','.join('%d:slot170=%s:outer108=%s' % row for row in found)))
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
            label = ('GRAPH_CALL_INPUT_FLOW' if in_graph else
                     'OTHER_FUNCTION_CALL_INPUT_FLOW' if graph_mode else 'CALL_INPUT_FLOW')
            say('  %s va=%s inputs=%d traces=%s same_instance_unproven=TRUE' %
                (label, op.getSeqnum().getTarget(), len(args), evidence))
    if graph_mode:
        for site in sorted(graph_sites - pcode_graph_sites):
            say('  GRAPH_SITE_NO_CALL_PCODE va=0x%x decompiler_mapping_unavailable=TRUE' % site)
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
        say('METHOD=Original completed 410-node reference graph, its unresolved call sites; CALLIND input LOAD def-use')
        say('LIMIT=CFG guarded dispatch may hide real target as implicit register; missing result is not negative proof')
        use_raw_scan = bool(globals().get('SCAN_EXECUTABLE', False))
        if use_raw_scan:
            say('MODE_DETAIL=OPT_IN_RAW_EXISTING_INSTRUCTION_SCAN not_original_graph')
            seeds, complete = discover_function_seeds(program, say, start+MAX_SECONDS)
        else:
            graph_path = globals().get('GRAPH_JSON', GRAPH_FILE)
            seeds = graph_function_candidates(program, graph_path, say)
            complete = True
        from ghidra.app.decompiler import DecompInterface
        decompiler = DecompInterface()
        if not decompiler.openProgram(program):
            raise RuntimeError('Ghidra decompiler initialization failed')
        processed = 0
        for entry, sites in sorted(seeds.items()):
            if time.monotonic() >= start+MAX_SECONDS:
                complete = False
                say('TIME_LIMIT before_function=0x%x' % entry)
                break
            if not inspect_function(program, decompiler, entry, sites, say, start+MAX_SECONDS, graph_mode=not use_raw_scan):
                complete = False
            processed += 1
        say('INSPECTION_SUMMARY candidates=%d processed=%d omitted=%d' %
            (len(seeds), processed, len(seeds)-processed))
        if processed != len(seeds):
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
