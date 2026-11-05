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
DECOMP_TIMEOUT_SECONDS = 12
MAX_DECOMP_CHARS = 14000

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


def targeted_decompile(program, addresses, log):
    if not addresses:
        log('DECOMPILATION=SKIPPED no explicit TARGET_FUNCTIONS provided')
        return True
    if len(addresses) > MAX_TARGETS:
        raise ValueError('too many explicit target addresses; limit=%d' % MAX_TARGETS)
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
                    log('TARGET_INCOMING_REFS_TRUNCATED=true')
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
            code = str(output.getC()) if output is not None else ''
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
                clipped = len(code) > MAX_DECOMP_CHARS
                log('DECOMPILER_BEGIN entry=%s clipped=%s' % (entry, clipped))
                log(code[:MAX_DECOMP_CHARS])
                if clipped:
                    all_targets_completed = False
                    log('DECOMPILER_OUTPUT_INCOMPLETE=TRUE clipped C output; use DECOMP_FOCUS_TERMS')
            log('DECOMPILER_END')
    finally:
        decompiler.dispose()
    return all_targets_completed


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
        if line.startswith(('STATUS=', 'PROGRESS', 'SCAN_', 'CANDIDATE_FUNCTION_COUNT=', 'DECOMPILATION=', 'IDENTITY=')):
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
            scan_known_string_references(program, output)
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
