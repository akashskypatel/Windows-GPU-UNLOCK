# @runtime PyGhidra
"""Read-only, bounded discovery for the Windows 617.42 GSP Booter loader.

Run in the Ghidra Python 3 / PyGhidra console with the *original* 617.42
nvlddmkm.sys imported. Does not analyze, disassemble, rename, patch, or save
anything in Ghidra. This script inspects loaded virtual memory (not raw PE
file offsets). Strings and static references alone cannot prove runtime
architecture selection or signed firmware acceptance.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
import re
import time
import traceback

EXPECTED_MD5 = '3fb9afac9d0e394723e830aa14e60512'
EXPECTED_IMAGE_BASE = 0x140000000
DEFAULT_REPORT_DIR = Path(r'D:\Projects\gpu-unlock\ghidra')
MAX_SCAN_BYTES = 192 * 1024 * 1024
MAX_SCAN_SECONDS = 90
CHUNK_BYTES = 512 * 1024
MAX_RECORDED_PER_TERM = 12
MAX_TOTAL_RECORDED = 220
MAX_REFS_PER_HIT = 10
MAX_TARGETS = 4
MAX_INCOMING_REFS = 24
MAX_DATA_SITES = 8
MAX_INSTRUCTION_SITES = 4
MAX_FUNCTION_LISTING_INSTRUCTIONS = 1024
MAX_CALL_TRACE_FUNCTIONS = 2
MAX_CALL_TRACE_SITES = 32
MAX_SLOT_CANDIDATES = 80
DECOMP_TIMEOUT_SECONDS = 12
MAX_DECOMP_CHARS = 20000
MAX_FULL_DECOMP_CHARS = 131072  # Opt-in upper limit for full target C report output.

# Exact ASCII string virtual addresses from the user's Ghidra 617.42 CSV.
# These are data anchors, not established function addresses or runtime selectors.
FIRMWARE_STRING_LEADS = (
    ('flcnLoadAndExecuteHsBinaryViaDma_GA10X', 0x140d2eae0),
    ('GSP_LOAD_EXEC_GENERIC_BOOTLOADER', 0x140d09070),
    ('GSP_LOAD_EXEC_HS_BINARY', 0x140d090a0),
    ('.fwsignature_', 0x140d150b0),
    ('.fwsignature_cc_', 0x140d1d760),
    ('.fwsignature_spdm_lite_', 0x140d1d780),
    ('RmBootGspRmWithBoostClocks', 0x140d1d740),
    ('RMAcrExecuteOnSec2', 0x140d2c4c0),
    ('RMExecuteFwsecOnSec2', 0x140d06b60),
    ('RmBootFromHs', 0x140d0ce10),
    ('RMEnableAcrRiscv', 0x140d2c520),
    ('RmDisableGspLoad', 0x140d12550),
    ('RmDisableSec2Load', 0x140d0cd10),
    ('Invalid Bindata Access', 0x140e557f8),
    ('flcnLoadUcode_GM107', 0x140d17030),
    ('RmGspBootRetryAttempts', 0x140d09bb0),
    ('gsp_ga10x.bin', 0x140d04330),
    ('ucodes_ga10x.bin', 0x140d04360),
)

# Linux source names are search hypotheses, not assumed Windows symbols.
# Keep these mostly specific to avoid false positives from unrelated strings.
SEARCH_TERMS = (
    'kgspAllocateBooterLoadUcodeImage',
    'kgspGetBinArchiveBooterLoadUcode',
    'kgspGetBinArchiveGspRmBoot',
    'BooterLoadUcode', 'BooterUnloadUcode', 'GspRmBoot',
    'BINDATA_LABEL_IMAGE_PROD', 'BINDATA_LABEL_SIG_PROD',
    'bindataArchiveGetStorage', 'bindata',
    'gsp_ga10x.bin', 'ucodes_ga10x.bin',
    'gsp_tu10x.bin', 'ucodes_tu10x.bin',
    'NVUCODES', 'FWSEC', 'SEC2', 'FALCON',
    'AD102', 'GA102', 'GSP-RM', 'booter',
)


def _compile_markers():
    # Longer terms first. Byte-regex also discovers still-undefined strings.
    terms = sorted(set(SEARCH_TERMS), key=len, reverse=True)
    ascii_terms = b'|'.join(re.escape(t.encode('ascii')) for t in terms)
    wide_terms = b'|'.join(re.escape(t.encode('utf-16le')) for t in terms)
    return re.compile(b'(?P<ascii>' + ascii_terms + b')|(?P<wide>' + wide_terms + b')', re.I), max(len(t) * 2 for t in terms)


MARKERS, MAX_MARKER_BYTES = _compile_markers()


def marker_hits(window: bytes):
    """Yield (start, end, canonical-search-term, encoding) for raw byte windows."""
    for match in MARKERS.finditer(window):
        raw = match.group(0)
        if match.group('wide') is not None:
            value, encoding = raw.decode('utf-16le', errors='replace').lower(), 'UTF16LE'
        else:
            value, encoding = raw.decode('ascii', errors='replace').lower(), 'ASCII'
        yield match.start(), match.end(), value, encoding


def combine_chunk_hits(previous: bytes, current: bytes):
    """Count cross-boundary matches once, never those wholly in the previous tail."""
    combined = previous + current
    for start, end, term, encoding in marker_hits(combined):
        if end > len(previous):
            yield start - len(previous), term, encoding


def _memory_bytes(memory, address, size):
    # PyGhidra/JPype requires a Java byte[] for output parameters. A Python
    # bytearray may be silently copied and left unchanged by Memory.getBytes.
    from jpype import JArray, JByte
    buffer = JArray(JByte)(size)
    count = int(memory.getBytes(address, buffer))
    if count != size:
        raise ValueError('short Ghidra memory read at %s (%d/%d)' % (address, count, size))
    try:
        return memoryview(buffer).tobytes()
    except (TypeError, BufferError):
        return bytes(int(byte) & 255 for byte in buffer)


def _address(program, integer):
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(int(integer))


def _bounded_references(program, address, maximum):
    refs = []
    manager = program.getReferenceManager()
    function_manager = program.getFunctionManager()
    for target in (address,):
        for reference in manager.getReferencesTo(target):
            if len(refs) == maximum:
                return refs, True
            origin = reference.getFromAddress()
            fn = function_manager.getFunctionContaining(origin)
            refs.append({
                'source': str(origin),
                'kind': str(reference.getReferenceType()),
                'function_entry': str(fn.getEntryPoint()) if fn is not None else 'UNKNOWN',
                'function_name': str(fn.getName()) if fn is not None else 'UNKNOWN',
            })
    return refs, False


def _source_block(memory, address):
    block = memory.getBlock(address)
    return str(block.getName()) if block is not None else '<unmapped>'


MAX_SYMBOL_PATTERNS = 4
MAX_SYMBOLS_PER_PATTERN = 12
MAX_SYMBOL_REFS_PER_SYMBOL = 20


def inspect_named_symbol_references(program, patterns, log):
    """Read bounded existing name-index and xref evidence; never create symbols."""
    if (not isinstance(patterns, (list, tuple)) or
            not 1 <= len(patterns) <= MAX_SYMBOL_PATTERNS or
            any(not isinstance(p, str) or len(p) > 64 or len(p) < 3 or
                not re.fullmatch(r'[A-Za-z0-9_*?]+', p) or
                not re.search(r'[A-Za-z]', p) for p in patterns)):
        raise ValueError('TRACE_SYMBOL_PATTERNS requires 1-4 bounded name patterns')
    symbols = program.getSymbolTable()
    references = program.getReferenceManager()
    functions = program.getFunctionManager()
    listing = program.getListing()
    complete = True
    for pattern in patterns:
        count = 0
        truncated = False
        for sym in symbols.getSymbolIterator(pattern, False):
            if count >= MAX_SYMBOLS_PER_PATTERN:
                truncated = True
                break
            count += 1
            target = sym.getAddress()
            log('SYMBOL_MATCH pattern=%s name=%s namespace=%s address=%s type=%s' % (
                pattern, sym.getName(), sym.getParentNamespace(), target,
                sym.getSymbolType()))
            ref_count = 0
            for ref in references.getReferencesTo(target):
                if ref_count >= MAX_SYMBOL_REFS_PER_SYMBOL:
                    truncated = True
                    break
                ref_count += 1
                site = ref.getFromAddress()
                function = functions.getFunctionContaining(site)
                instruction = listing.getInstructionAt(site)
                log('SYMBOL_XREF pattern=%s target=%s site=%s kind=%s owner=%s asm=%s' % (
                    pattern, target, site, ref.getReferenceType(),
                    function.getEntryPoint() if function is not None else 'UNKNOWN',
                    str(instruction) if instruction is not None else 'NONE'))
            log('SYMBOL_XREF_COUNT pattern=%s target=%s recorded=%d' % (
                pattern, target, ref_count))
        if not count:
            log('SYMBOL_MATCH_NONE pattern=%s EXISTING_SYMBOL_MAP_ONLY=TRUE' % pattern)
        if truncated:
            complete = False
            log('SYMBOL_REFERENCES_TRUNCATED pattern=%s symbols_limit=%d references_limit=%d' % (
                pattern, MAX_SYMBOLS_PER_PATTERN, MAX_SYMBOL_REFS_PER_SYMBOL))
        log('SYMBOL_PATTERN_COMPLETE pattern=%s matched=%d truncated=%s' % (
            pattern, count, truncated))
    log('SYMBOL_LOOKUP_SCOPE=EXISTING_SYMBOL_INDEX_AND_XREFS_ONLY NO_IMPORT_OR_RUNTIME_PROOF')
    return complete


def scan_memory(program, log, deadline):
    memory = program.getMemory()
    initialized = [b for b in memory.getBlocks() if b.isInitialized()]
    # Search non-executable data first; executable blocks are not silently skipped.
    initialized.sort(key=lambda b: (bool(b.isExecute()), int(b.getStart().getOffset())))
    counters = Counter()
    recorded = []
    skipped_blocks = []
    scanned = 0
    complete = True
    log('BLOCKS total=%d initialized=%d' % (len(memory.getBlocks()), len(initialized)))
    for b in memory.getBlocks():
        log('BLOCK name=%s start=%s end=%s size=%d initialized=%s R=%s W=%s X=%s' % (
            b.getName(), b.getStart(), b.getEnd(), int(b.getSize()),
            b.isInitialized(), b.isRead(), b.isWrite(), b.isExecute()))
    for block in initialized:
        start = int(block.getStart().getOffset())
        length = int(block.getSize())
        log('SCAN_BLOCK name=%s va=0x%x size=%d' % (block.getName(), start, length))
        offset = 0
        overlap = b''
        while offset < length:
            if scanned >= MAX_SCAN_BYTES or time.monotonic() > deadline:
                complete = False
                skipped_blocks.append('%s remaining=%d' % (block.getName(), length-offset))
                break
            take = min(CHUNK_BYTES, length-offset, MAX_SCAN_BYTES-scanned)
            try:
                raw = _memory_bytes(memory, _address(program, start + offset), take)
            except Exception as err:
                complete = False
                log('SCAN_READ_ERROR block=%s va=0x%x type=%s' % (
                    block.getName(), start + offset, type(err).__name__))
                skipped_blocks.append('%s read-failure=0x%x' % (block.getName(), start+offset))
                break
            for relative, term, encoding in combine_chunk_hits(overlap, raw):
                location = start + offset + relative
                counters[term] += 1
                per_term = sum(1 for entry in recorded if entry['term'] == term)
                if per_term < MAX_RECORDED_PER_TERM and len(recorded) < MAX_TOTAL_RECORDED:
                    recorded.append({'term': term, 'encoding': encoding,
                                     'va': location, 'block': str(block.getName())})
            overlap = (overlap + raw)[-(MAX_MARKER_BYTES - 1):]
            offset += take
            scanned += take
            if scanned and scanned % (16 * 1024 * 1024) < CHUNK_BYTES:
                log('PROGRESS scanned_bytes=%d recorded=%d elapsed_seconds=%.1f' % (
                    scanned, len(recorded), MAX_SCAN_SECONDS - max(0.0, deadline-time.monotonic())))
        if not complete and (scanned >= MAX_SCAN_BYTES or time.monotonic() > deadline):
            break
    log('SCAN_BYTES=%d SCAN_COMPLETE=%s RECORDED=%d' % (scanned, complete, len(recorded)))
    for term, count in counters.most_common():
        log('TERM_COUNT term=%r total=%d' % (term, count))
    for miss in skipped_blocks:
        log('SCAN_INCOMPLETE_REASON=%s' % miss)
    return recorded, counters, complete


def describe_references(program, hits, log):
    listing = program.getListing()
    fn_entries = {}
    log('REFERENCE_SCAN=Ghidra-existing-references-only no-new-disassembly')
    for hit in hits:
        addr = _address(program, hit['va'])
        target_addrs = [addr]
        data = listing.getDataContaining(addr)
        if data is not None and data.isDefined():
            data_start = data.getMinAddress()
            if data_start != addr:
                target_addrs.append(data_start)
        combined = []
        truncated = False
        for target in target_addrs:
            refs, cut = _bounded_references(program, target, MAX_REFS_PER_HIT-len(combined))
            combined.extend(refs)
            truncated = truncated or cut
            if len(combined) >= MAX_REFS_PER_HIT:
                break
        log('STRING_MATCH term=%r encoding=%s VA=0x%x BLOCK=%s XREFS=%d capped=%s' % (
            hit['term'], hit['encoding'], hit['va'], hit['block'], len(combined), truncated))
        for r in combined:
            log('  XREF from=%s type=%s function=%s(%s)' % (
                r['source'], r['kind'], r['function_name'], r['function_entry']))
            if r['function_entry'] != 'UNKNOWN':
                fn_entries.setdefault(r['function_entry'], set()).add(hit['term'])
    for addr, terms in sorted(fn_entries.items()):
        log('CANDIDATE_FUNCTION entry=%s referenced_terms=%s' % (addr, ','.join(sorted(terms))))
    log('CANDIDATE_FUNCTION_COUNT=%d STRING_XREF_ABSENCE_PROVES_NO_EMBEDDED_BOOTER=FALSE' % len(fn_entries))



def scan_known_string_references(program, log, leads=FIRMWARE_STRING_LEADS):
    """Examine only verified literal VAs, reusing the existing bounded XREF path.

    Do not assume that a CSV string VA denotes a function or that a named
    firmware operation is a runtime operation. Match literal bytes before XREFs.
    """
    if len(leads) > 24:
        raise ValueError('too many explicit CSV leads')
    memory = program.getMemory()
    hits = []
    for label, va in leads:
        address = _address(program, va)
        block = memory.getBlock(address)
        if block is None or not block.isInitialized():
            raise ValueError('CSV lead is not in initialized Ghidra memory: 0x%x' % va)
        expected = label.encode('ascii')
        if _memory_bytes(memory, address, len(expected)) != expected:
            raise ValueError('CSV lead bytes differ from expected literal at 0x%x: %s' % (va, label))
        hits.append({'term': label, 'encoding': 'CSV_EXACT_ASCII',
                     'va': va, 'block': str(block.getName())})
        log('CSV_LEAD_VERIFIED label=%r VA=0x%x' % (label, va))
    log('CSV_LEAD_COUNT=%d SOURCE=nvlddmkm-strings.csv; selected anchors only' % len(hits))
    describe_references(program, hits, log)




def inspect_data_reference_sites(program, sites, log):
    """Read existing outgoing/incoming Ghidra references at explicit data VAs.

    This examines referenced pointers and their containing defined data objects.
    It does not scan memory, create functions or mutate the Ghidra database.
    """
    if isinstance(sites, (str, bytes)) or not isinstance(sites, (list, tuple)) or len(sites) > MAX_DATA_SITES:
        raise ValueError('TRACE_DATA_SITES requires at most %d explicit addresses' % MAX_DATA_SITES)
    memory = program.getMemory()
    complete = True
    for value in sites:
        address = _address(program, int(str(value), 0))
        block = memory.getBlock(address)
        if block is None or not block.isInitialized():
            log('DATA_SITE_UNAVAILABLE VA=%s; no initialized backing memory' % address)
            complete = False
            continue
        listing = program.getListing()
        manager = program.getReferenceManager()
        functions = program.getFunctionManager()
        data = listing.getDataContaining(address)
        data_defined = data is not None and data.isDefined()
        root = data.getMinAddress() if data_defined else address
        log('DATA_SITE VA=%s block=%s defined=%s containing_start=%s' % (
            address, block.getName(), data_defined, root))
        n = 0
        for ref in manager.getReferencesFrom(address):
            if n >= MAX_REFS_PER_HIT:
                log('DATA_SITE_OUTBOUND_TRUNCATED VA=%s' % address)
                complete = False
                break
            destination = ref.getToAddress()
            fn = functions.getFunctionContaining(destination)
            log('  OUTBOUND target=%s kind=%s function=%s(%s)' % (
                destination, ref.getReferenceType(),
                fn.getName() if fn is not None else 'UNKNOWN',
                fn.getEntryPoint() if fn is not None else 'UNKNOWN'))
            n += 1
        for candidate in (address, root) if root != address else (address,):
            refs, capped = _bounded_references(program, candidate, MAX_REFS_PER_HIT)
            log('  INBOUND_ROOT VA=%s count=%d capped=%s' % (candidate, len(refs), capped))
            for ref in refs:
                log('    INBOUND from=%s kind=%s function=%s(%s)' % (
                    ref['source'], ref['kind'], ref['function_name'], ref['function_entry']))
            if capped:
                complete = False
    return complete



def inspect_instruction_sites(program, sites, log):
    """Print bounded existing instruction listings around explicit call sites.

    Read-only: no disassembly, analysis, database writes, or implied ABI interpretation.
    """
    if (isinstance(sites, (str, bytes)) or not isinstance(sites, (list, tuple)) or
            len(sites) > MAX_INSTRUCTION_SITES):
        raise ValueError('TRACE_INSTRUCTION_SITES requires at most %d explicit addresses' % MAX_INSTRUCTION_SITES)
    memory = program.getMemory()
    complete = True
    for raw in sites:
        address = _address(program, int(str(raw), 0))
        block = memory.getBlock(address)
        if block is None or not block.isExecute():
            log('INSTRUCTION_SITE_UNAVAILABLE VA=%s not in executable block' % address)
            complete = False
            continue
        listing = program.getListing()
        functions = program.getFunctionManager()
        insn = listing.getInstructionContaining(address)
        fn = functions.getFunctionContaining(address)
        if insn is None or fn is None:
            log('INSTRUCTION_SITE_UNAVAILABLE VA=%s existing instruction/function missing' % address)
            complete = False
            continue
        log('INSTRUCTION_SITE VA=%s actual=%s function=%s(%s)' % (
            address, insn.getAddress(), fn.getName(), fn.getEntryPoint()))
        preceding = []
        cursor = insn
        for _ in range(12):
            older = listing.getInstructionBefore(cursor.getAddress())
            if older is None or not fn.getBody().contains(older.getAddress()):
                break
            preceding.append(older)
            cursor = older
        following = []
        cursor = insn
        for _ in range(4):
            newer = listing.getInstructionAfter(cursor.getAddress())
            if newer is None or not fn.getBody().contains(newer.getAddress()):
                break
            following.append(newer)
            cursor = newer
        for current in reversed(preceding):
            log('  BEFORE VA=%s asm=%s' % (current.getAddress(), current))
        log('  AT VA=%s asm=%s' % (insn.getAddress(), insn))
        for current in following:
            log('  AFTER VA=%s asm=%s' % (current.getAddress(), current))
        log('  INSTRUCTION_CONTEXT_ONLY=TRUE ABI_OR_RUNTIME_NOT_PROVEN')
    return complete




def inspect_function_calls(program, targets, log):
    """Report bounded instruction windows around existing CALLs in named functions.

    Includes CFG-guard dispatch setup when adjacent; no decompilation,
    instruction creation, indirect target inference, or Ghidra database writes.
    """
    if (isinstance(targets, (str, bytes)) or not isinstance(targets, (list, tuple)) or
            len(targets) > MAX_CALL_TRACE_FUNCTIONS):
        raise ValueError('TRACE_FUNCTION_CALLS requires at most %d addresses' % MAX_CALL_TRACE_FUNCTIONS)
    listing = program.getListing()
    functions = program.getFunctionManager()
    complete = True
    for raw in targets:
        address = _address(program, int(str(raw), 0))
        fn = functions.getFunctionContaining(address)
        if fn is None:
            log('FUNCTION_CALLS_UNAVAILABLE VA=%s no existing function' % address)
            complete = False
            continue
        entry = fn.getEntryPoint()
        body = fn.getBody()
        logged = 0
        capped = False
        log('FUNCTION_CALLS_BEGIN entry=%s name=%s max_calls=%d' % (
            entry, fn.getName(), MAX_CALL_TRACE_SITES))
        for insn in listing.getInstructions(body, True):
            if str(insn.getMnemonicString()).upper() != 'CALL':
                continue
            if logged >= MAX_CALL_TRACE_SITES:
                complete = False
                capped = True
                log('FUNCTION_CALLS_TRUNCATED entry=%s limit=%d' % (entry, MAX_CALL_TRACE_SITES))
                break
            log('  FUNCTION_CALL VA=%s asm=%s' % (insn.getAddress(), insn))
            preceding = []
            cursor = insn
            for _ in range(12):
                older = listing.getInstructionBefore(cursor.getAddress())
                if older is None or not body.contains(older.getAddress()):
                    break
                preceding.append(older)
                cursor = older
            for previous in reversed(preceding):
                log('    BEFORE VA=%s asm=%s' % (previous.getAddress(), previous))
            cursor = insn
            for _ in range(4):
                newer = listing.getInstructionAfter(cursor.getAddress())
                if newer is None or not body.contains(newer.getAddress()):
                    break
                log('    AFTER VA=%s asm=%s' % (newer.getAddress(), newer))
                cursor = newer
            logged += 1
        log('FUNCTION_CALLS_END entry=%s recorded=%d capped=%s' % (entry, logged, capped))
    log('FUNCTION_CALLS_SCOPE=Existing CALL instructions only, including indirect guard sites; excludes JMP aliases and runtime target identity')
    return complete


def _slot_displacement_hits(previous, current, needle):
    """Return raw offsets relative to current chunk, including boundary hits."""
    if len(needle) != 4:
        raise ValueError('expected x64 disp32 bytes')
    combined = previous + current
    pos = 0
    while True:
        at = combined.find(needle, pos)
        if at < 0:
            return
        if at + len(needle) > len(previous):
            yield at - len(previous)
        pos = at + 1


def _slot_transfer_evidence(instruction, listing, functions, slot, lookahead=8):
    """Return a bounded *candidate* transfer near a slot read, never proof of a callback.

    Only explicit CALL/JMP [base+slot] or register loads followed by indirect
    transfer/guard dispatch are retained. Other ways of forwarding the pointer
    will not be found by this conservative filter.
    """
    assembly = str(instruction)
    slot_operand = r'\[[^\]\n]*\+\s*0x%x\b[^\]\n]*\]' % slot
    if re.match(r'^(?:CALL|JMP)\s+', assembly, re.I) and re.search(slot_operand, assembly, re.I):
        return ('DIRECT_MEMORY_TRANSFER', 'AT ' + assembly)
    match = re.match(
        r'^MOV\s+(R[A-Z0-9]+)\s*,\s*qword ptr\s*' + slot_operand + r'\s*$',
        assembly, re.I)
    if match is None:
        return None
    target_register = match.group(1)
    fn = functions.getFunctionContaining(instruction.getAddress())
    if fn is None:
        return None
    current = instruction
    for distance in range(1, lookahead + 1):
        following = listing.getInstructionAfter(current.getAddress())
        if following is None or not fn.getBody().contains(following.getAddress()):
            return None
        next_assembly = str(following)
        if re.match(r'^(?:CALL|JMP)\s+' + re.escape(target_register) + r'\s*$',
                    next_assembly, re.I):
            return ('REGISTER_TRANSFER_NEARBY', '%d instructions later: %s' % (distance, next_assembly))
        if (re.match(r'^(?:CALL|JMP)\s+', next_assembly, re.I) and
                ('guard_dispatch_icall' in next_assembly.lower() or
                 '0x140e02aa8' in next_assembly.lower())):
            return ('GUARD_TRANSFER_NEARBY', '%d instructions later: %s' % (distance, next_assembly))
        current = following
    return None


def _slot_write_evidence(instruction, slot):
    """Identify explicit writes to a field at the requested literal displacement.

    Textual candidate filter only: does not resolve the object type, aliases,
    memcopy destinations, or stores via nonliteral/computed addresses.
    """
    assembly = str(instruction)
    operand = r'\[[^\]\n]*\+\s*0x%x\b[^\]\n]*\]' % slot
    # Memory as first operand: ordinary stores, SIMD stores and RMW operations.
    match = re.match(
        r'^(?:LOCK\s+)?(MOV|MOVABS|MOVAPS|MOVUPS|MOVDQA|MOVDQU|MOVQ|MOVD|'
        r'XCHG|XADD|CMPXCHG|AND|OR|XOR|ADD|SUB|INC|DEC)\s+'
        r'(byte|word|dword|qword|xmmword|ymmword)\s+ptr\s*' + operand + r'\s*(?:,|$)',
        assembly, re.I)
    if match is not None:
        return ('FIELD_WRITE_' + match.group(2).upper(), assembly)
    # XCHG writes both operands. This form has memory second.
    if re.match(r'^XCHG\s+[A-Z][A-Z0-9]*\s*,\s*'
                r'(?:byte|word|dword|qword)\s+ptr\s*' + operand + r'\s*$',
                assembly, re.I):
        return ('FIELD_EXCHANGE', assembly)
    return None


def scan_existing_slot_displacements(program, slot, log, deadline, focus="all", max_recorded=MAX_SLOT_CANDIDATES):
    """Find candidate x64 [register+disp32] uses in existing executable code.

    Bytes are never disassembled; raw matches are accepted only when already
    defined Ghidra instructions contain the exact displacement in brackets.
    Matches are *candidates*, not validated indirect calls or object aliases.
    """
    slot = int(str(slot), 0) if isinstance(slot, str) else int(slot)
    if not 0x80 <= slot <= 0x7fffffff:
        raise ValueError('SLOT_DISPLACEMENT must be a positive x64 disp32 >= 0x80')
    if focus not in ('all', 'transfer', 'write'):
        raise ValueError('SLOT_SCAN_FOCUS must be all, transfer or write')
    if type(max_recorded) is not int or not 1 <= max_recorded <= 5000:
        raise ValueError('SLOT_SCAN_MAX_RECORDED must be an integer from 1 to 5000')
    memory = program.getMemory()
    listing = program.getListing()
    functions = program.getFunctionManager()
    blocks = [b for b in memory.getBlocks() if b.isInitialized() and b.isExecute()]
    blocks.sort(key=lambda b: int(b.getStart().getOffset()))
    raw_needle = slot.to_bytes(4, 'little')
    operand_re = re.compile(r'\[[^\]\n]*\+\s*0x%x\b[^\]\n]*\]' % slot, re.I)
    scanned = 0
    raw_matches = 0
    verified = 0
    relevant = 0
    recorded = 0
    seen_instructions = set()
    complete = True
    log('SLOT_SCAN_BEGIN slot=0x%x focus=%s block_count=%d max_bytes=%d max_recorded=%d deadline_bounded=True' % (
        slot, focus, len(blocks), MAX_SCAN_BYTES, max_recorded))
    for block_index, block in enumerate(blocks):
        base = int(block.getStart().getOffset())
        length = int(block.getSize())
        log('SLOT_SCAN_BLOCK name=%s va=0x%x bytes=%d' % (block.getName(), base, length))
        offset = 0
        previous = b''
        while offset < length:
            if scanned >= MAX_SCAN_BYTES or time.monotonic() > deadline:
                complete = False
                log('SLOT_SCAN_TRUNCATED block=%s remaining=%d reason=budget_or_deadline' % (
                    block.getName(), length-offset))
                break
            take = min(CHUNK_BYTES, length-offset, MAX_SCAN_BYTES-scanned)
            try:
                current = _memory_bytes(memory, _address(program, base+offset), take)
            except Exception as exc:
                complete = False
                log('SLOT_SCAN_READ_ERROR block=%s va=0x%x error_type=%s' % (
                    block.getName(), base+offset, type(exc).__name__))
                break
            for relative in _slot_displacement_hits(previous, current, raw_needle):
                raw_matches += 1
                where = _address(program, base+offset+relative)
                instruction = listing.getInstructionContaining(where)
                if instruction is None or not operand_re.search(str(instruction)):
                    continue
                entry = str(instruction.getAddress())
                if entry in seen_instructions:
                    continue
                seen_instructions.add(entry)
                verified += 1
                evidence = None
                if focus == 'transfer':
                    evidence = _slot_transfer_evidence(instruction, listing, functions, slot)
                    if evidence is None:
                        continue
                elif focus == 'write':
                    evidence = _slot_write_evidence(instruction, slot)
                    if evidence is None:
                        continue
                relevant += 1
                if recorded >= max_recorded:
                    complete = False
                    continue
                recorded += 1
                fn = functions.getFunctionContaining(instruction.getAddress())
                log('SLOT_CANDIDATE VA=%s block=%s asm=%s function=%s(%s) evidence=%s' % (
                    instruction.getAddress(), block.getName(), instruction,
                    fn.getName() if fn is not None else 'UNKNOWN',
                    fn.getEntryPoint() if fn is not None else 'UNKNOWN',
                    ('%s; %s' % evidence) if evidence is not None else 'offset_only'))
            previous = (previous + current)[-3:]
            offset += take
            scanned += take
        if scanned >= MAX_SCAN_BYTES or time.monotonic() > deadline:
            if offset < length or block_index < len(blocks)-1:
                complete = False
                log('SLOT_SCAN_UNVISITED_BLOCKS count=%d' % (len(blocks)-block_index-1))
            break
    log('SLOT_SCAN_END scanned_bytes=%d raw_hits=%d distinct_instruction_candidates=%d recorded=%d capped=%s scan_complete=%s selected_candidates=%d focus=%s' % (
        scanned, raw_matches, verified, recorded, relevant>recorded, complete, relevant, focus))
    log('SLOT_SCAN_LIMIT=Filtered uses are candidate code sites only: no alias/object identity, indirect-call identity, runtime branch, or firmware acceptance proven')
    return complete


# Pair existing nested-pointer load and callback-field instructions; only a heuristic.
RECEIVER_LOAD_RE = re.compile(r'^MOV\s+(R[A-Z0-9]+),qword ptr \[(R[A-Z0-9]+)\s*\+\s*0x108\]$', re.I)
RECEIVER_FIELD_RE = re.compile(r'\[\s*(R[A-Z0-9]+)\s*\+\s*0x(170|250)\]', re.I)
RECEIVER_COPY_RE = re.compile(r'^MOV\s+(R[A-Z0-9]+),\s*(R[A-Z0-9]+)$', re.I)
RECEIVER_REGISTER_DEST_RE = re.compile(r'^(?:MOV|LEA|XOR|ADD|SUB|AND|OR|SHL|SHR|SAR|IMUL|POP)\s+(R[A-Z0-9]+)\s*[, ]', re.I)
MAX_RECEIVER_SECONDS = 40
MAX_RECEIVER_LOOKAHEAD = 36
MAX_RECEIVER_RECORDED = 48


def _receiver_field_step(asm, aliases):
    """Track simple MOV aliases; neither alias nor branch reachability is proven."""
    if asm.upper().startswith('CALL '):
        aliases.difference_update(('RAX', 'RCX', 'RDX', 'R8', 'R9', 'R10', 'R11'))
        return None
    matched = RECEIVER_FIELD_RE.search(asm)
    field = int(matched.group(2), 16) if matched and matched.group(1).upper() in aliases else None
    copy = RECEIVER_COPY_RE.match(asm)
    if copy:
        dst, src = copy.group(1).upper(), copy.group(2).upper()
        if src in aliases:
            aliases.add(dst)
        else:
            aliases.discard(dst)
    else:
        destination = RECEIVER_REGISTER_DEST_RE.match(asm)
        if destination:
            aliases.discard(destination.group(1).upper())
    return field


def scan_nested_receiver_candidates(program, log, deadline):
    """Find source-grounded receiver candidates without a full instruction walk.

    Scan executable bytes only for the 32-bit +0x108 field displacement. For
    each byte hit, use an EXISTING Ghidra instruction and require an exact
    MOV register,[register+0x108] operand before bounded same-function alias
    tracking. This is static, branch-insensitive and not a runtime call proof.
    """
    listing = program.getListing()
    functions = program.getFunctionManager()
    memory = program.getMemory()
    blocks = [b for b in memory.getBlocks() if b.isInitialized() and b.isExecute()]
    blocks.sort(key=lambda b: int(b.getStart().getOffset()))
    needle = (0x108).to_bytes(4, 'little')
    raw_hits = 0
    inspected = 0
    seeds = 0
    matches = 0
    recorded = 0
    scanned_bytes = 0
    seen_instructions = set()
    complete = True
    timed_out = False
    stopped = False
    log('SCAN_NESTED_RECEIVER_BEGIN seed=read_qword_at_0x108 slots=0x170,0x250 '
        'method=existing_instruction_byte_seeded lookahead=%d max_bytes=%d '
        'max_recorded=%d deadline_bounded=True block_count=%d' %
        (MAX_RECEIVER_LOOKAHEAD, MAX_SCAN_BYTES, MAX_RECEIVER_RECORDED, len(blocks)))

    for block_index, block in enumerate(blocks):
        base = int(block.getStart().getOffset())
        length = int(block.getSize())
        offset = 0
        previous = b''
        while offset < length:
            if scanned_bytes >= MAX_SCAN_BYTES or time.monotonic() >= deadline:
                complete = False
                timed_out = time.monotonic() >= deadline
                stopped = True
                log('SCAN_NESTED_RECEIVER_TRUNCATED block=%s remaining_bytes=%d reason=%s' %
                    (block.getName(), length - offset,
                     'TIME_BUDGET' if timed_out else 'BYTE_BUDGET'))
                break
            take = min(CHUNK_BYTES, length - offset, MAX_SCAN_BYTES - scanned_bytes)
            try:
                current = _memory_bytes(memory, _address(program, base + offset), take)
                if len(current) != take:
                    raise ValueError('short read')
            except Exception as exc:
                complete = False
                stopped = True
                log('SCAN_NESTED_RECEIVER_READ_ERROR block=%s va=0x%x error_type=%s' %
                    (block.getName(), base + offset, type(exc).__name__))
                break
            for relative in _slot_displacement_hits(previous, current, needle):
                raw_hits += 1
                if time.monotonic() >= deadline:
                    timed_out = True
                    complete = False
                    stopped = True
                    break
                site = _address(program, base + offset + relative)
                instruction = listing.getInstructionContaining(site)
                if instruction is None:
                    continue
                instruction_addr = instruction.getAddress()
                key = int(instruction_addr.getOffset())
                if key in seen_instructions:
                    continue
                seen_instructions.add(key)
                inspected += 1
                if str(instruction.getMnemonicString()).upper() != 'MOV':
                    continue
                seed_asm = str(instruction)
                start = RECEIVER_LOAD_RE.match(seed_asm)
                if start is None:
                    continue
                fn = functions.getFunctionContaining(instruction_addr)
                if fn is None:
                    continue
                seeds += 1
                aliases = {start.group(1).upper()}
                cursor = instruction
                for distance in range(1, MAX_RECEIVER_LOOKAHEAD + 1):
                    cursor = listing.getInstructionAfter(cursor.getAddress())
                    if cursor is None or not fn.getBody().contains(cursor.getAddress()):
                        break
                    field_asm = str(cursor)
                    slot = _receiver_field_step(field_asm, aliases)
                    if slot is None:
                        continue
                    matches += 1
                    nearby_transfer = False
                    follower = cursor
                    for _ in range(8):
                        follower = listing.getInstructionAfter(follower.getAddress())
                        if follower is None or not fn.getBody().contains(follower.getAddress()):
                            break
                        if str(follower.getMnemonicString()).upper() in ('CALL', 'JMP'):
                            nearby_transfer = True
                            break
                    if recorded < MAX_RECEIVER_RECORDED:
                        recorded += 1
                        log('RECEIVER_CANDIDATE seed_va=%s seed_asm=%s field_va=%s '
                            'field_asm=%s slot=0x%x distance=%d nearby_transfer=%s '
                            'function=%s(%s) potential_alias_only=True' %
                            (instruction_addr, seed_asm, cursor.getAddress(), field_asm,
                             slot, distance, nearby_transfer, fn.getName(), fn.getEntryPoint()))
            previous = (previous + current)[-3:]
            offset += take
            scanned_bytes += take
            if stopped:
                break
        if stopped:
            remaining_blocks = len(blocks) - block_index - 1
            if remaining_blocks:
                log('SCAN_NESTED_RECEIVER_UNVISITED_BLOCKS count=%d' % remaining_blocks)
            break
    capped = matches > recorded
    if capped:
        complete = False
    log('SCAN_NESTED_RECEIVER_END scanned_bytes=%d raw_hits=%d '
        'defined_candidate_instructions=%d seeds=%d matched_fields=%d '
        'recorded=%d capped=%s timed_out=%s scan_complete=%s' %
        (scanned_bytes, raw_hits, inspected, seeds, matches, recorded,
         capped, timed_out, complete))
    log('SCAN_NESTED_RECEIVER_LIMIT=Byte-seeded *existing* instructions only; '
        'linear same-function register-copy heuristic; no alias/branch or actual '
        'loader invocation proof; misses computed offsets, interprocedural aliases '
        'and outer+0xf0->+0x18 patterns')
    return complete


def inspect_static_bytes(program, sites, log):
    """Read at most four 64-byte initialized nonexecutable regions, without mutation."""
    if (isinstance(sites, (str, bytes)) or not isinstance(sites, (list, tuple)) or
            len(sites) > 4):
        raise ValueError('TRACE_STATIC_BYTES requires at most four explicit addresses')
    memory = program.getMemory()
    complete = True
    for raw in sites:
        address = _address(program, int(str(raw), 0))
        block = memory.getBlock(address)
        if (block is None or not block.isInitialized() or block.isExecute() or
                int(block.getEnd().getOffset()) - int(address.getOffset()) < 63):
            log('STATIC_BYTES_UNAVAILABLE VA=%s reason=uninitialized_executable_or_short_block' % address)
            complete = False
            continue
        try:
            data = _memory_bytes(memory, address, 64)
            if len(data) != 64:
                raise ValueError('short static-byte read')
        except Exception as exc:
            log('STATIC_BYTES_UNAVAILABLE VA=%s error_type=%s' %
                (address, type(exc).__name__))
            complete = False
            continue
        log('STATIC_BYTES VA=%s length=64 interpretation=unknown' % address)
        for offset in range(0, 64, 16):
            chunk = data[offset:offset+16]
            log('  STATIC_HEX offset=0x%02x data=%s' % (offset, chunk.hex()))
        log('  STATIC_QWORD0_LE=0x%016x' % int.from_bytes(data[:8], 'little'))
    return complete


def decompilation_excerpt(code, terms, limit=MAX_DECOMP_CHARS):
    """Extract bounded line-numbered evidence around requested C identifiers.

    Returns (text, term_counts, truncated); no Ghidra DB interaction.
    An excerpt is not complete control-flow or a complete decompilation.
    """
    if (isinstance(terms, str) or not isinstance(terms, (tuple, list)) or
            not 0 < len(terms) <= 8 or
            any(not isinstance(t, str) or not 3 <= len(t) <= 96 or
                any(c in t for c in '\r\n') for t in terms)):
        raise ValueError('DECOMP_FOCUS_TERMS requires 1..8 single-line strings of length 3..96')
    if not 256 <= limit <= 65536:
        raise ValueError('invalid excerpt size limit')
    lines = code.splitlines()
    indices = set()
    counts = {}
    capped_matches = False
    for term in terms:
        matches = [i for i, line in enumerate(lines) if term.casefold() in line.casefold()]
        counts[term] = len(matches)
        if len(matches) > 8:
            capped_matches = True
        for i in matches[:8]:
            indices.update(range(max(0, i-5), min(len(lines), i+8)))
    output = []
    size = 0
    prior = -2
    clipped = capped_matches
    for i in sorted(indices):
        segment = ('... omitted lines ...\n' if i > prior + 1 else '') + ('L%d: %s\n' % (i+1, lines[i]))
        if size + len(segment) > limit:
            clipped = True
            break
        output.append(segment)
        size += len(segment)
        prior = i
    return ''.join(output), counts, clipped



def inspect_function_listing(program, targets, log):
    """Record one exact existing function's machine listing without modifying Ghidra.

    This is a bounded static record. Sequential instructions can belong to
    different control-flow paths. Assembly alone does not prove register
    provenance, object identity, indirect target or runtime acceptance.
    """
    if isinstance(targets, (str, bytes)) or not isinstance(targets, (list, tuple)) or len(targets) > 1:
        raise ValueError('TRACE_FUNCTION_LISTING requires at most one explicit function entry')
    complete = True
    for raw in targets:
        addr = _address(program, int(str(raw), 0))
        block = program.getMemory().getBlock(addr)
        fn = program.getFunctionManager().getFunctionContaining(addr)
        if block is None or not block.isExecute() or fn is None or fn.getEntryPoint() != addr:
            log('FUNCTION_LISTING_UNAVAILABLE VA=%s exact executable function entry required' % addr)
            complete = False
            continue
        count = 0
        covered = 0
        capped = False
        log('FUNCTION_LISTING_BEGIN entry=%s name=%s max_instructions=%d' % (
            addr, fn.getName(), MAX_FUNCTION_LISTING_INSTRUCTIONS))
        for instruction in program.getListing().getInstructions(fn.getBody(), True):
            if count >= MAX_FUNCTION_LISTING_INSTRUCTIONS:
                log('FUNCTION_LISTING_TRUNCATED entry=%s limit=%d' % (
                    addr, MAX_FUNCTION_LISTING_INSTRUCTIONS))
                capped = True
                complete = False
                break
            log('  LISTING VA=%s asm=%s' % (instruction.getAddress(), instruction))
            count += 1
            covered += int(instruction.getLength())
        body_size = int(fn.getBody().getNumAddresses())
        if count == 0 or covered != body_size:
            log('FUNCTION_LISTING_COVERAGE_PARTIAL entry=%s instruction_bytes=%d body_bytes=%d' % (
                addr, covered, body_size))
            complete = False
        log('FUNCTION_LISTING_END entry=%s instructions=%d instruction_bytes=%d body_bytes=%d capped=%s' % (
            addr, count, covered, body_size, capped))
    log('FUNCTION_LISTING_SCOPE=EXISTING_GHIDRA_LISTING_ONLY REGISTER_STACK_PROVENANCE_NOT_INFERRED')
    return complete


def targeted_decompile(program, addresses, log):
    if not addresses:
        log('DECOMPILATION=SKIPPED no explicit TARGET_FUNCTIONS provided')
        return True
    if len(addresses) > MAX_TARGETS:
        raise ValueError('too many explicit target addresses; limit=%d' % MAX_TARGETS)
    full_output_limit = globals().get('FULL_DECOMP_MAX_CHARS', MAX_DECOMP_CHARS)
    if type(full_output_limit) is not int or not 256 <= full_output_limit <= MAX_FULL_DECOMP_CHARS:
        raise ValueError('FULL_DECOMP_MAX_CHARS must be an integer from 256 to %d' % MAX_FULL_DECOMP_CHARS)
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import TaskMonitor
    decompiler = DecompInterface()
    all_targets_completed = True
    try:
        if not decompiler.openProgram(program):
            raise RuntimeError('decompiler failed to open program')
        for value in addresses:
            numeric = int(str(value), 0)
            target = _address(program, numeric)
            block = program.getMemory().getBlock(target)
            if block is None or not block.isExecute():
                raise ValueError('target address is not in an executable block: %s' % target)
            fn = program.getFunctionManager().getFunctionContaining(target)
            if fn is None:
                log('TARGET_NOT_DEFINED VA=%s no Ghidra function; no creation attempted' % target)
                all_targets_completed = False
                continue
            entry = fn.getEntryPoint()
            log('TARGET_FUNCTION entry=%s name=%s supplied=%s' % (entry, fn.getName(), target))
            n = 0
            for ref in program.getReferenceManager().getReferencesTo(entry):
                if n >= MAX_INCOMING_REFS:
                    log('TARGET_INCOMING_REFS_TRUNCATED=true entry=%s cap=%d' %
                        (entry, MAX_INCOMING_REFS))
                    all_targets_completed = False
                    break
                log('  TARGET_CALLER from=%s kind=%s' % (ref.getFromAddress(), ref.getReferenceType()))
                n += 1
            result = decompiler.decompileFunction(fn, DECOMP_TIMEOUT_SECONDS, TaskMonitor.DUMMY)
            if result is None or not result.decompileCompleted():
                all_targets_completed = False
                log('DECOMPILE_UNAVAILABLE entry=%s reason=%s' % (
                    entry, result.getErrorMessage() if result is not None else 'null-result'))
                continue
            output = result.getDecompiledFunction()
            rendered = output.getC() if output is not None else None
            code = str(rendered) if rendered is not None else ''
            if not code.strip():
                log('DECOMPILER_BODY_UNAVAILABLE=TRUE entry=%s empty_or_missing_C=TRUE' % entry)
                all_targets_completed = False
                continue
            focus_terms = globals().get('DECOMP_FOCUS_TERMS', ())
            if focus_terms:
                excerpt, counts, truncated = decompilation_excerpt(code, focus_terms)
                log('DECOMPILER_BEGIN entry=%s focus=True total_chars=%d excerpt_truncated=%s' % (
                    entry, len(code), truncated))
                for term, count in counts.items():
                    log('FOCUS_TERM term=%r matches=%d' % (term, count))
                log(excerpt)
                if not any(counts.values()) or truncated:
                    all_targets_completed = False
                    log('FOCUS_INCOMPLETE=TRUE no selected evidence or some excerpts omitted')
            else:
                clipped = len(code) > full_output_limit
                log('DECOMPILER_BEGIN entry=%s clipped=%s total_chars=%d output_limit=%d' % (
                    entry, clipped, len(code), full_output_limit))
                log(code[:full_output_limit])
                if clipped:
                    all_targets_completed = False
                    log('DECOMPILER_OUTPUT_INCOMPLETE=TRUE clipped C output; use DECOMP_FOCUS_TERMS')
            log('DECOMPILER_END')
    finally:
        decompiler.dispose()
    return all_targets_completed



# Optional bounded function-reference graph.  All edges come from existing
# Ghidra references; indirect target identities are deliberately not guessed.
def _graph_options(config):
    roots = config.get('GRAPH_ROOTS', ())
    if isinstance(roots, (str, bytes)) or not isinstance(roots, (tuple, list)) or not 1 <= len(roots) <= 4:
        raise ValueError('GRAPH_ROOTS requires a list of 1 to 4 explicit function addresses')
    options = {
        'depth': ('GRAPH_DEPTH', 2, 0, 4),
        'nodes': ('GRAPH_MAX_NODES', 64, 1, 2048),
        'edges': ('GRAPH_MAX_EDGES', 256, 1, 16384),
        'references': ('GRAPH_REFS_PER_FUNCTION', 128, 1, 16384),
        'instructions': ('GRAPH_INSTRUCTIONS_PER_FUNCTION', 6000, 1, 120000),
        'seconds': ('GRAPH_TIMEOUT_SECONDS', 45, 1, 900),
        'decompile': ('GRAPH_DECOMPILE_LIMIT', 0, 0, 128),
        'code_chars': ('GRAPH_CODE_CHARS', 16000, 256, MAX_FULL_DECOMP_CHARS),
    }
    result = {}
    for label, (name, default, minimum, maximum) in options.items():
        value = config.get(name, default)
        if type(value) is not int or value < minimum or value > maximum:
            raise ValueError('%s must be an integer from %d to %d' % (name, minimum, maximum))
        result[label] = value
    direction = config.get('GRAPH_DIRECTION', 'both')
    if direction not in ('both', 'forward', 'backward'):
        raise ValueError('GRAPH_DIRECTION must be both, forward, or backward')
    result['direction'] = direction
    on_walk = config.get('GRAPH_DECOMPILE_ON_WALK', False)
    if type(on_walk) is not bool:
        raise ValueError('GRAPH_DECOMPILE_ON_WALK must be a Boolean')
    if on_walk and result['decompile'] == 0:
        raise ValueError('GRAPH_DECOMPILE_ON_WALK requires GRAPH_DECOMPILE_LIMIT > 0')
    result['decompile_on_walk'] = on_walk
    result['roots'] = roots
    return result


def _graph_dot(nodes, edges):
    """Graphviz DOT: solid calls, dotted address references, dashed unresolved."""
    lines = ['digraph static_function_references {',
             '  graph [rankdir=LR];',
             '  node [shape=box];']
    for key, node in sorted(nodes.items()):
        style = 'doubleoctagon' if node.get('root') else ('ellipse' if node['kind'] != 'FUNCTION' else 'box')
        label = node['label'].replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
        lines.append('  "%s" [shape=%s,label="%s"];' % (key, style, label))
    for edge in sorted(edges.values(), key=lambda x: (x['source'], x['site'], x['target'], x['kind'])):
        dotted = edge['kind'] in ('DATA_REF', 'ADDRESS_TAKEN')
        style = 'dotted' if dotted else ('dashed' if edge['kind'] == 'INDIRECT_UNKNOWN' else 'solid')
        label = '%s @ %s' % (edge['kind'], edge['site'])
        lines.append('  "%s" -> "%s" [style=%s,label="%s"];' % (
            edge['source'], edge['target'], style, label))
    lines.append('}')
    return '\n'.join(lines) + '\n'


def graph_reference_walk(program, roots, log, report_path, options=None):
    """Walk defined functions only. Never create Ghidra functions or infer dynamic targets.

    COMPLETE describes this bounded existing-XREF walk only, not a complete runtime
    call graph, object identity, firmware signer verification, or device execution.
    """
    from collections import deque
    import json

    if options is None:
        options = _graph_options({'GRAPH_ROOTS': roots})
    functions = program.getFunctionManager()
    listing = program.getListing()
    references = program.getReferenceManager()
    memory = program.getMemory()
    deadline = time.monotonic() + options['seconds']
    nodes, edges, omitted = {}, {}, set()
    queue = deque()
    queued = set()
    processed = set()

    def key_of(address):
        return '%x' % int(address.getOffset())

    def checked_time():
        if time.monotonic() >= deadline:
            omitted.add('TIME_BUDGET')
            return False
        return True

    def register_function(fn, distance, root=False, expand=True, orientation=None):
        key = 'f_' + key_of(fn.getEntryPoint())
        if key not in nodes:
            if len(nodes) >= options['nodes']:
                omitted.add('NODE_LIMIT')
                return None
            nodes[key] = {'kind': 'FUNCTION', 'label': '%s\n0x%s' % (
                str(fn.getName()), key_of(fn.getEntryPoint())),
                'entry': '0x' + key_of(fn.getEntryPoint()),
                'distance': distance, 'root': bool(root)}
        else:
            nodes[key]['distance'] = min(distance, nodes[key]['distance'])
            if root:
                nodes[key]['root'] = True
        # An address-taken function can later become a real direct callee:
        # it must then be enqueued rather than silently left as a data-only leaf.
        # Each direction is a separate path from a seed. Never reverse a path
        # at a shared utility, which would pull unrelated callers into the graph.
        directions = ('forward', 'backward') if options['direction'] == 'both' else (options['direction'],)
        for walk in directions if orientation is None else (orientation,):
            state = (key, walk)
            if expand and distance < options['depth'] and state not in processed and state not in queued:
                queue.append((fn, distance, walk))
                queued.add(state)
        return key

    def register_site(kind, address, label):
        key = ('i_' if kind == 'INDIRECT' else 'd_') + key_of(address)
        if key not in nodes:
            if len(nodes) >= options['nodes']:
                omitted.add('NODE_LIMIT')
                return None
            nodes[key] = {'kind': kind, 'label': label, 'root': False}
        return key

    def edge_between(source, target, address, kind):
        if source is None or target is None:
            return
        site = '0x' + key_of(address)
        key = (source, target, site, kind)
        if key not in edges:
            if len(edges) >= options['edges']:
                omitted.add('EDGE_LIMIT')
                return
            edges[key] = {'source': source, 'target': target,
                          'site': site, 'kind': kind}

    def bounded(items):
        count = 0
        for item in items:
            if not checked_time():
                break
            if count >= options['references']:
                omitted.add('REFERENCE_LIMIT')
                break
            count += 1
            yield item

    for raw in roots:
        addr = _address(program, int(str(raw), 0))
        block = memory.getBlock(addr)
        if block is None or not block.isExecute():
            log('GRAPH_ROOT_UNAVAILABLE VA=%s not executable' % addr)
            omitted.add('INVALID_ROOT')
            continue
        fn = functions.getFunctionContaining(addr)
        if fn is None:
            log('GRAPH_ROOT_UNAVAILABLE VA=%s no defined function' % addr)
            omitted.add('INVALID_ROOT')
            continue
        register_function(fn, 0, root=True)

    decompiled_entries = set()
    live_decompiler = None
    if options['decompile_on_walk']:
        from ghidra.app.decompiler import DecompInterface
        live_decompiler = DecompInterface()
        if not live_decompiler.openProgram(program):
            omitted.add('DECOMPILER_OPEN_FAILED')
            live_decompiler.dispose()
            live_decompiler = None
    try:
        while queue and checked_time():
            fn, distance, walk = queue.popleft()
            owner = 'f_' + key_of(fn.getEntryPoint())
            state = (owner, walk)
            queued.discard(state)
            if state in processed:
                continue
            processed.add(state)
            # Decompile at the point of traversal to preserve the evidence order.
            # Each function is attempted once even if both paths reach it.
            if (live_decompiler is not None and owner not in decompiled_entries and len(decompiled_entries) < options['decompile']):
                decompiled_entries.add(owner)
                try:
                    from ghidra.util.task import TaskMonitor
                    result = live_decompiler.decompileFunction(fn, DECOMP_TIMEOUT_SECONDS, TaskMonitor.DUMMY)
                    if result is None or not result.decompileCompleted():
                        omitted.add('DECOMPILE_FAILED')
                        log('GRAPH_DECOMPILE_UNAVAILABLE entry=0x%s distance=%d' % (key_of(fn.getEntryPoint()), distance))
                    else:
                        decompiled = result.getDecompiledFunction()
                        code = str(decompiled.getC()) if decompiled is not None else ''
                        if decompiled is None:
                            omitted.add('DECOMPILE_FAILED')
                            log('GRAPH_DECOMPILE_UNAVAILABLE entry=0x%s reason=missing_c' % key_of(fn.getEntryPoint()))
                        else:
                            clipped = len(code) > options['code_chars']
                            log('GRAPH_DECOMPILER_BEGIN entry=0x%s distance=%d clipped=%s total_chars=%d' % (
                                key_of(fn.getEntryPoint()), distance, clipped, len(code)))
                            log(code[:options['code_chars']])
                            log('GRAPH_DECOMPILER_END entry=0x%s' % key_of(fn.getEntryPoint()))
                            if clipped:
                                omitted.add('DECOMPILER_OUTPUT_CLIPPED')
                except Exception as exc:
                    omitted.add('DECOMPILE_FAILED')
                    log('GRAPH_DECOMPILE_UNAVAILABLE entry=0x%s error_type=%s' % (
                        key_of(fn.getEntryPoint()), type(exc).__name__))
            if walk == 'backward':
                for ref in bounded(references.getReferencesTo(fn.getEntryPoint())):
                    ref_type = ref.getReferenceType()
                    site = ref.getFromAddress()
                    if ref_type.isCall() or ref_type.isJump():
                        caller = functions.getFunctionContaining(site)
                        if caller is None:
                            omitted.add('UNDEFINED_CALLER')
                            continue
                        if ref_type.isJump() and caller.getEntryPoint() == fn.getEntryPoint():
                            continue  # intra-function branch to own entry, not a tail call
                        source = register_function(caller, distance + 1,
                                                   expand=True, orientation='backward')
                        edge_between(source, owner, site, 'CALL' if ref_type.isCall() else 'TAIL_JUMP')
                    elif ref_type.isData():
                        block = memory.getBlock(site)
                        label = 'DATA XREF\n0x%s\n%s' % (
                            key_of(site), str(block.getName()) if block is not None else 'unmapped')
                        data_node = register_site('DATA', site, label)
                        edge_between(data_node, owner, site, 'DATA_REF')
            if walk == 'forward':
                count = 0
                for insn in listing.getInstructions(fn.getBody(), True):
                    if not checked_time():
                        break
                    if count >= options['instructions']:
                        omitted.add('INSTRUCTION_LIMIT')
                        break
                    count += 1
                    mnemonic = str(insn.getMnemonicString()).upper()
                    if mnemonic not in ('CALL', 'JMP', 'LEA', 'MOV'):
                        continue
                    source = insn.getAddress()
                    found_call = False
                    for ref in bounded(references.getReferencesFrom(source)):
                        ref_type = ref.getReferenceType()
                        if ref_type.isCall() or (mnemonic == 'JMP' and ref_type.isJump()):
                            found_call = True
                            target = functions.getFunctionContaining(ref.getToAddress())
                            if target is None:
                                unresolved = register_site('INDIRECT', source,
                                                           'UNRESOLVED DESTINATION\n0x' + key_of(source))
                                edge_between(owner, unresolved, source, 'INDIRECT_UNKNOWN')
                                continue
                            target_key = 'f_' + key_of(target.getEntryPoint())
                            if target_key == owner and mnemonic == 'JMP':
                                continue  # a branch inside the same function, not a call
                            dest = register_function(target, distance + 1,
                                                     expand=True, orientation='forward')
                            edge_between(owner, dest, source,
                                         'CALL' if ref_type.isCall() else 'TAIL_JUMP')
                            if 'guard_dispatch' in str(target.getName()).lower():
                                unresolved = register_site(
                                    'INDIRECT', source, 'GUARDED TARGET UNKNOWN\n0x' + key_of(source))
                                edge_between(owner, unresolved, source, 'INDIRECT_UNKNOWN')
                        elif ref_type.isData() and mnemonic in ('LEA', 'MOV'):
                            target = functions.getFunctionContaining(ref.getToAddress())
                            if target is not None:
                                target_key = register_function(target, distance + 1, expand=False)
                                edge_between(owner, target_key, source, 'ADDRESS_TAKEN')
                    if mnemonic == 'CALL' and not found_call:
                        unresolved = register_site('INDIRECT', source,
                                                   'INDIRECT CALL UNKNOWN\n0x' + key_of(source))
                        edge_between(owner, unresolved, source, 'INDIRECT_UNKNOWN')

    finally:
        if live_decompiler is not None:
            live_decompiler.dispose()

    # Decompile only explicitly budgeted graph nodes. Graphing does not require
    # decompilation and zero is the safe default for large driver functions.
    if options['decompile'] and not options['decompile_on_walk']:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import TaskMonitor
        decompiler = DecompInterface()
        try:
            if not decompiler.openProgram(program):
                omitted.add('DECOMPILER_OPEN_FAILED')
            else:
                selected = sorted(
                    ((key, node) for key, node in nodes.items() if node['kind'] == 'FUNCTION'),
                    key=lambda pair: (pair[1]['distance'], pair[0]))[:options['decompile']]
                for key, node in selected:
                    if not checked_time():
                        break
                    fn = functions.getFunctionAt(_address(program, int(node['entry'], 0)))
                    if fn is None:
                        omitted.add('DECOMPILE_TARGET_UNDEFINED')
                        log('GRAPH_DECOMPILE_UNAVAILABLE entry=%s' % node['entry'])
                        continue
                    result = decompiler.decompileFunction(fn, DECOMP_TIMEOUT_SECONDS, TaskMonitor.DUMMY)
                    if result is None or not result.decompileCompleted():
                        omitted.add('DECOMPILE_FAILED')
                        log('GRAPH_DECOMPILE_UNAVAILABLE entry=%s' % node['entry'])
                        continue
                    decompiled = result.getDecompiledFunction()
                    code = str(decompiled.getC()) if decompiled is not None else ''
                    clipped = len(code) > options['code_chars']
                    log('GRAPH_DECOMPILER_BEGIN entry=%s clipped=%s total_chars=%d' % (
                        node['entry'], clipped, len(code)))
                    log(code[:options['code_chars']])
                    log('GRAPH_DECOMPILER_END entry=%s' % node['entry'])
                    if clipped:
                        omitted.add('DECOMPILER_OUTPUT_CLIPPED')
        finally:
            decompiler.dispose()

    if options['decompile_on_walk']:
        log('GRAPH_DECOMPILE_COUNT=%d GRAPH_DECOMPILE_LIMIT=%d' % (
            len(decompiled_entries), options['decompile']))
    dot_path = report_path.with_name(report_path.stem + '-reference-graph.dot')
    json_path = report_path.with_name(report_path.stem + '-reference-graph.json')
    verdict = 'PARTIAL' if omitted else 'COMPLETE'
    snapshot = {
        'schema': 'ghidra-static-function-references-v3',
        'scope': 'direction-preserving paths from each seed; existing Ghidra references only; no database writes or dynamic target resolution',
        'status': verdict,
        'roots': ['0x%x' % int(str(x), 0) for x in roots],
        'limits': {key: value for key, value in options.items() if key != 'roots'},
        'omissions': sorted(omitted),
        'walk_decompilation_attempted': len(decompiled_entries),
        'nodes': [dict(id=key, **value) for key, value in sorted(nodes.items())],
        'edges': sorted(edges.values(), key=lambda x: (x['source'], x['site'], x['target'], x['kind'])),
    }
    # Exclusive creation preserves an earlier investigation artifact if a name
    # collides. These are report files, not Ghidra program/database changes.
    with dot_path.open('x', encoding='utf-8') as stream:
        stream.write(_graph_dot(nodes, edges))
    with json_path.open('x', encoding='utf-8') as stream:
        json.dump(snapshot, stream, indent=2, sort_keys=True)
        stream.write('\n')
    log('GRAPH_SCOPE=DIRECTION_PRESERVING_STATIC_XREF_ONLY forward-and-backward-paths-not-mixed data-xrefs-not-calls indirect-target-unknown')
    log('GRAPH_NODES=%d GRAPH_EDGES=%d GRAPH_OMISSIONS=%s' % (
        len(nodes), len(edges), ','.join(sorted(omitted)) or 'NONE'))
    log('GRAPH_DOT=%s' % dot_path)
    log('GRAPH_JSON=%s' % json_path)
    log('GRAPH_STATUS=%s' % verdict)
    return not omitted


def main():
    started = time.monotonic()
    program = globals().get('currentProgram')
    status = 'ERROR'
    report_path = None
    stream = None

    def output(line=''):
        line = str(line)
        if stream is not None:
            stream.write(line + '\n')
        if line.startswith(('STATUS=', 'PROGRESS', 'SCAN_', 'GRAPH_', 'CANDIDATE_FUNCTION_COUNT=', 'DECOMPILATION=', 'IDENTITY=')):
            print(line)

    try:
        if program is None:
            raise ValueError('currentProgram missing; pass state.getCurrentProgram() in exec namespace')
        md5 = str(program.getExecutableMD5() or '').lower()
        image_base = int(program.getImageBase().getOffset())
        program_name = str(program.getName())
        if md5 != EXPECTED_MD5 or image_base != EXPECTED_IMAGE_BASE or not program_name.lower().endswith('nvlddmkm.sys'):
            raise ValueError('incorrect Ghidra program: name=%s MD5=%s base=0x%x' % (
                program_name, md5, image_base))
        report_dir = Path(globals().get('REPORT_DIR', DEFAULT_REPORT_DIR))
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / ('nvlddmkm-61742-booter-discovery-%s.txt' % datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
        stream = report_path.open('x', encoding='utf-8', buffering=1)
        output('STATUS=RUNNING')
        output('IDENTITY=nvlddmkm.sys MD5=%s BASE=0x%x NAME=%s' % (md5, image_base, program_name))
        output('MODE=PASSIVE READ_ONLY EXISTING_REFERENCE_MAP NO_DATABASE_WRITES')
        output('LIMIT=Loaded Ghidra address-space VAs, not raw PE file offsets')
        output('LIMIT=Windows 617.42 architecture selection, source of firmware bytes, crypto acceptance and runtime use are NOT proven')
        output('REFERENCE=Linux 615.78.08 kgspAllocateBooterLoadUcodeImage_IMPL -> kgspGetBinArchiveBooterLoadUcode_HAL -> bindataArchiveGetStorage; not assumed identical on Windows')
        output('COMPARISON=610.43.03 versus 615.78.08 production Booter image+wrapper+signatures DIFFER; GSP boot image+descriptor identical')
        scan = bool(globals().get('SCAN_STRINGS', True))
        targets = globals().get('TARGET_FUNCTIONS', ())
        if scan:
            hits, counters, full = scan_memory(program, output, started + MAX_SCAN_SECONDS)
            describe_references(program, hits, output)
            status = 'COMPLETE' if full else 'PARTIAL'
        else:
            output('SCAN_STRINGS=SKIPPED_BY_CALLER')
            status = 'COMPLETE'
        if bool(globals().get('SCAN_CSV_LEADS', False)):
            scan_known_string_references(program, output, leads=globals().get('CSV_LEADS', FIRMWARE_STRING_LEADS))
        slot_displacement = globals().get('SCAN_SLOT_DISPLACEMENT', None)
        if slot_displacement is not None and not scan_existing_slot_displacements(
                program, slot_displacement, output, time.monotonic() + MAX_SCAN_SECONDS,
                focus=globals().get('SLOT_SCAN_FOCUS', 'all'),
                max_recorded=globals().get('SLOT_SCAN_MAX_RECORDED', MAX_SLOT_CANDIDATES)):
            status = 'PARTIAL'
            output('SLOT_SCAN_COMPLETE=FALSE; results incomplete or candidate cap reached')
        if bool(globals().get('TRACE_NESTED_RECEIVER_CANDIDATES', False)):
            if not scan_nested_receiver_candidates(program, output, time.monotonic() + MAX_RECEIVER_SECONDS):
                status = 'PARTIAL'
                output('SCAN_NESTED_RECEIVER_COMPLETE=FALSE; candidate cap or time budget reached')
        symbol_patterns = globals().get('TRACE_SYMBOL_PATTERNS', ())
        if symbol_patterns and not inspect_named_symbol_references(program, symbol_patterns, output):
            status = 'PARTIAL'
            output('SYMBOL_REFERENCES_COMPLETE=FALSE; bounded name or xref limit reached')
        static_sites = globals().get('TRACE_STATIC_BYTES', ())
        if static_sites and not inspect_static_bytes(program, static_sites, output):
            status = 'PARTIAL'
            output('STATIC_BYTES_COMPLETE=FALSE; one or more regions unreadable')
        instruction_sites = globals().get('TRACE_INSTRUCTION_SITES', ())
        if instruction_sites and not inspect_instruction_sites(program, instruction_sites, output):
            status = 'PARTIAL'
            output('INSTRUCTION_SITES_COMPLETE=FALSE; one or more sites unavailable')
        call_functions = globals().get('TRACE_FUNCTION_CALLS', ())
        if call_functions and not inspect_function_calls(program, call_functions, output):
            status = 'PARTIAL'
            output('FUNCTION_CALL_TRACE_COMPLETE=FALSE; function unavailable or bounded callsite limit reached')
        sites = globals().get('TRACE_DATA_SITES', ())
        if sites and not inspect_data_reference_sites(program, sites, output):
            status = 'PARTIAL'
            output('DATA_SITES_COMPLETE=FALSE; unavailable or bounded references')
        roots = globals().get('GRAPH_ROOTS', ())
        if roots:
            graph_options = _graph_options(globals())
            if not graph_reference_walk(program, roots, output, report_path, graph_options):
                status = 'PARTIAL'
                output('GRAPH_COMPLETE=FALSE; some bounded static references or decompilations omitted')
        full_listing = globals().get('TRACE_FUNCTION_LISTING', ())
        if full_listing and not inspect_function_listing(program, full_listing, output):
            status = 'PARTIAL'
            output('FUNCTION_LISTING_COMPLETE=FALSE; original listing omitted instructions or function unavailable')
        if not targeted_decompile(program, targets, output) and status == 'COMPLETE':
            status = 'PARTIAL'
            output('TARGETS_COMPLETE=FALSE; at least one requested function was undefined or could not be decompiled')
        output('STOCK_WINDOWS_BOOTER_ORIGIN_PROVEN=FALSE')
        output('AD102_GA102_RUNTIME_SELECTOR_PROVEN=FALSE')
        output('FIRMWARE_SIGNATURE_AUTHENTICATED=FALSE')
        output('HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE')
    except KeyboardInterrupt:
        status = 'PARTIAL'
        output('INTERRUPTED=KeyboardInterrupt; report may be incomplete')
    except Exception:
        status = 'ERROR'
        output('ERROR=' + traceback.format_exc())
        print(traceback.format_exc())
    finally:
        output('ELAPSED_SECONDS=%.3f' % (time.monotonic() - started))
        output('STATUS=%s REPORT=%s' % (status, report_path if report_path is not None else '<not-created>'))
        if stream is not None:
            stream.close()
        print('STATUS=%s | REPORT=%s | ELAPSED=%.3fs' % (
            status, report_path if report_path is not None else '<not-created>', time.monotonic() - started))
    return status


if __name__ == '__main__':
    main()
