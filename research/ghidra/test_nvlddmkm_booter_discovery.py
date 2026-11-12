"""Host-only checks for raw discovery heuristics (no Ghidra runtime needed)."""
import importlib.util
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

MODULE = Path(__file__).with_name('nvlddmkm_booter_discovery.py')
spec = importlib.util.spec_from_file_location('nvlddmkm_booter_discovery', MODULE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class DiscoveryPatternTests(unittest.TestCase):
    def test_ascii_case_insensitive_high_signal_label(self):
        matches = list(probe.marker_hits(b'\0preBootErLoadUcode\0'))
        self.assertEqual([m[2:] for m in matches], [('booterloaducode', 'ASCII')])

    def test_utf16le_and_ascii_are_both_visible(self):
        data = 'ucodes_ga10x.bin'.encode('utf-16le') + b'---' + b'AD102'
        hits = list(probe.marker_hits(data))
        self.assertEqual([(h[2], h[3]) for h in hits],
                         [('ucodes_ga10x.bin', 'UTF16LE'), ('ad102', 'ASCII')])

    def test_boundary_match_is_counted_once(self):
        before = b'Z' * 120 + b'Boo'
        after = b'terLoadUcode\0tail'
        overlap = before[-(probe.MAX_MARKER_BYTES - 1):]
        first_chunk = list(probe.combine_chunk_hits(b'', before))
        second_chunk = list(probe.combine_chunk_hits(overlap, after))
        self.assertFalse(any(x[1] == 'booterloaducode' for x in first_chunk))
        self.assertEqual([x[1] for x in second_chunk], ['booterloaducode'])
        self.assertEqual(second_chunk[0][0], -3)

    def test_previous_overlap_match_is_not_duplicated(self):
        before = b'GspRmBoot' + b'Z' * 4
        after = b'XYZ'
        overlap = before[-(probe.MAX_MARKER_BYTES - 1):]
        self.assertEqual([x[1] for x in probe.combine_chunk_hits(b'', before)], ['gsprmboot'])
        self.assertEqual(list(probe.combine_chunk_hits(overlap, after)), [])

    def test_ghidra_console_without_flush_still_emits_final_status(self):
        # Ghidra's proxy.PyConsole implements write(), but has no flush().
        # A deliberate identity mismatch exercises the unconditional finally
        # path without needing Java or modifying a Ghidra program.
        class PyConsoleLike:
            def __init__(self):
                self.output = []

            def write(self, value):
                self.output.append(value)

        class WrongProgram:
            def getExecutableMD5(self):
                return '0' * 32

            def getImageBase(self):
                return type('Base', (), {'getOffset': lambda self: 0})()

            def getName(self):
                return 'wrong.sys'

        console = PyConsoleLike()
        with patch.object(sys, 'stdout', console), patch.dict(probe.__dict__, {'currentProgram': WrongProgram()}):
            result = probe.main()
        self.assertEqual(result, 'ERROR')
        self.assertIn('STATUS=ERROR | REPORT=<not-created>', ''.join(console.output))

    def test_target_not_defined_does_not_report_complete(self):
        # The scan already succeeded, but an unrecognized target must not
        # be presented as a completed decompilation.
        import tempfile

        class CorrectProgram:
            def getExecutableMD5(self):
                return probe.EXPECTED_MD5

            def getImageBase(self):
                return type('Base', (), {'getOffset': lambda self: probe.EXPECTED_IMAGE_BASE})()

            def getName(self):
                return 'nvlddmkm.sys'

        with tempfile.TemporaryDirectory() as temporary:
            with patch.dict(probe.__dict__, {
                'currentProgram': CorrectProgram(),
                'SCAN_STRINGS': False,
                'TARGET_FUNCTIONS': ['0x140d0c790'],
                'REPORT_DIR': temporary,
            }), patch.object(probe, 'targeted_decompile', return_value=False):
                status = probe.main()
            self.assertEqual(status, 'PARTIAL')
            reports = list(Path(temporary).glob('nvlddmkm-61742-booter-discovery-*.txt'))
            self.assertEqual(len(reports), 1)
            report = reports[0].read_text()
            self.assertIn('TARGETS_COMPLETE=FALSE', report)
            self.assertIn('STATUS=PARTIAL REPORT=', report)

    def test_no_targets_preserves_completed_scan_semantics(self):
        logs = []
        self.assertTrue(probe.targeted_decompile(None, [], logs.append))
        self.assertIn('DECOMPILATION=SKIPPED no explicit TARGET_FUNCTIONS provided', logs)

    def test_explicit_csv_leads_override_default_without_string_scan(self):
        import tempfile

        class CorrectProgram:
            def getExecutableMD5(self):
                return probe.EXPECTED_MD5

            def getImageBase(self):
                return type('Base', (), {'getOffset': lambda self: probe.EXPECTED_IMAGE_BASE})()

            def getName(self):
                return 'nvlddmkm.sys'

        selected = (
            ('FSP boot completion', 0x141806480),
            ('GFW secure boot failed [NV_ERR_SECURE_BOOT_FAILED]', 0x140efb958),
        )
        seen = []
        with tempfile.TemporaryDirectory() as temporary:
            with patch.dict(probe.__dict__, {
                'currentProgram': CorrectProgram(),
                'SCAN_STRINGS': False,
                'SCAN_CSV_LEADS': True,
                'CSV_LEADS': selected,
                'TARGET_FUNCTIONS': [],
                'REPORT_DIR': temporary,
            }), patch.object(probe, 'scan_known_string_references',
                             side_effect=lambda _program, _log, leads: seen.append(leads)):
                status = probe.main()
            report_files = list(Path(temporary).glob('nvlddmkm-61742-booter-discovery-*.txt'))
            self.assertEqual(len(report_files), 1)
            self.assertIn('STATUS=COMPLETE REPORT=', report_files[0].read_text())
        self.assertEqual(status, 'COMPLETE')
        self.assertEqual(seen, [selected])

    def test_selected_csv_lead_rejects_wrong_literal_bytes(self):
        class Memory:
            def getBlock(self, address):
                return type('Block', (), {'isInitialized': lambda self: True})()

        class Program:
            def getMemory(self):
                return Memory()

        with patch.object(probe, '_address', side_effect=lambda _program, value: value), \
             patch.object(probe, '_memory_bytes', return_value=b'not the anchored string'):
            with self.assertRaisesRegex(ValueError, 'CSV lead bytes differ'):
                probe.scan_known_string_references(
                    Program(), lambda _line: None,
                    leads=[('FSP boot completion', 0x141806480)])

    def test_no_assertion_from_missing_raw_strings(self):
        self.assertEqual(list(probe.marker_hits(b'not an Nvidia archive path')), [])


# This test class is intentionally appended: discovery tests remain unchanged.
class FocusedDecompileTests(unittest.TestCase):
    def test_bounded_excerpt_includes_later_use_not_just_function_prefix(self):
        source = '\n'.join(['line %d' % i for i in range(400)] + ['gsp_buffer_loaded_and_used()'])
        text, counts, truncated = probe.decompilation_excerpt(source, ['gsp_buffer_loaded_and_used'], limit=1500)
        self.assertEqual(counts['gsp_buffer_loaded_and_used'], 1)
        self.assertIn('L401: gsp_buffer_loaded_and_used()', text)
        self.assertNotIn('L1: line 0', text)
        self.assertFalse(truncated)

    def test_absent_term_is_not_fabricated(self):
        text, counts, truncated = probe.decompilation_excerpt('int x = 1;', ['FIRMWARE_SUBSYSTEM'])
        self.assertEqual(counts, {'FIRMWARE_SUBSYSTEM': 0})
        self.assertEqual(text, '')
        self.assertFalse(truncated)

    def test_capped_occurrences_flag_missing_context(self):
        source = '\n'.join('buffer_use(x);' for _ in range(30))
        text, counts, truncated = probe.decompilation_excerpt(source, ['buffer_use'])
        self.assertEqual(counts['buffer_use'], 30)
        self.assertTrue(truncated)
        self.assertIn('buffer_use(x)', text)

    def test_excessive_terms_and_multiline_terms_refused(self):
        with self.assertRaisesRegex(ValueError, 'DECOMP_FOCUS_TERMS'):
            probe.decompilation_excerpt('code', ['x'] * 9)
        with self.assertRaisesRegex(ValueError, 'DECOMP_FOCUS_TERMS'):
            probe.decompilation_excerpt('code', ['line\nline'])


class DecompilationCoverageTests(unittest.TestCase):
    def _analyze(self, c_source, full_output_limit=None, incoming_refs=0):
        """Exercise the real targeted path through a minimal Java API simulation."""
        import types

        class Address:
            def __str__(self):
                return '1401b0e00'

        class Function:
            def getEntryPoint(self):
                return Address()

            def getName(self):
                return 'FUN_1401b0e00'

        class Results:
            def decompileCompleted(self):
                return True

            def getDecompiledFunction(self):
                return None if c_source is None else type('Output', (), {'getC': lambda self: c_source})()

        class Decompiler:
            def openProgram(self, program):
                return True

            def decompileFunction(self, function, timeout, monitor):
                return Results()

            def dispose(self):
                pass

        class Program:
            def getMemory(self):
                return type('Mem', (), {'getBlock': lambda self, address:
                            type('Block', (), {'isExecute': lambda self: True})()})()

            def getFunctionManager(self):
                return type('Fns', (), {'getFunctionContaining': lambda self, address: Function()})()

            def getReferenceManager(self):
                class Ref:
                    def getFromAddress(self):
                        return '140000001'

                    def getReferenceType(self):
                        return 'DATA'

                return type('Refs', (), {'getReferencesTo':
                    lambda self, address: [Ref() for _ in range(incoming_refs)]})()

        modules = {name: types.ModuleType(name) for name in
                   ('ghidra', 'ghidra.app', 'ghidra.app.decompiler',
                    'ghidra.util', 'ghidra.util.task')}
        modules['ghidra.app.decompiler'].DecompInterface = Decompiler
        modules['ghidra.util.task'].TaskMonitor = type('TaskMonitor', (), {'DUMMY': None})
        logs = []
        options = {} if full_output_limit is None else {'FULL_DECOMP_MAX_CHARS': full_output_limit}
        with patch.dict(sys.modules, modules), \
             patch.dict(probe.__dict__, options), \
             patch.object(probe, '_address', side_effect=lambda program, address: Address()):
            result = probe.targeted_decompile(Program(), ['0x1401b0e00'], logs.append)
        return result, logs

    def test_incoming_reference_budget_does_not_claim_complete(self):
        # A full decompilation does not make an omitted inbound reference
        # complete evidence. Exactly the cap is not itself truncation.
        completed, lines = self._analyze('int f() {}', incoming_refs=probe.MAX_INCOMING_REFS)
        self.assertTrue(completed)
        self.assertEqual(sum('  TARGET_CALLER ' in line for line in lines),
                         probe.MAX_INCOMING_REFS)
        self.assertFalse(any('TARGET_INCOMING_REFS_TRUNCATED' in line for line in lines))

        completed, lines = self._analyze('int f() {}',
                                         incoming_refs=probe.MAX_INCOMING_REFS + 1)
        self.assertFalse(completed)
        self.assertEqual(sum('  TARGET_CALLER ' in line for line in lines),
                         probe.MAX_INCOMING_REFS)
        self.assertIn('TARGET_INCOMING_REFS_TRUNCATED=true', '\\n'.join(lines))
        self.assertTrue(any('DECOMPILER_BEGIN' in line and 'clipped=False' in line
                            for line in lines))
        self.assertIn('DECOMPILER_END', lines)

    def test_clipped_regular_decompilation_reports_incomplete(self):
        completed, lines = self._analyze('X' * (probe.MAX_DECOMP_CHARS + 5))
        self.assertFalse(completed)
        self.assertTrue(any(line.startswith('DECOMPILER_BEGIN entry=1401b0e00 clipped=True ') for line in lines))
        self.assertTrue(any('DECOMPILER_OUTPUT_INCOMPLETE=TRUE' in item for item in lines))

    def test_missing_or_empty_decompiler_body_is_incomplete(self):
        # A successful decompiler return without C output cannot establish
        # a complete function body, even when its length is below the cap.
        for source in (None, '', '  ', '\\n\\t'):
            with self.subTest(source=source):
                completed, lines = self._analyze(source)
                self.assertFalse(completed)
                self.assertTrue(any('DECOMPILER_BODY_UNAVAILABLE=TRUE' in line
                                    for line in lines))
                self.assertFalse(any(line.startswith('DECOMPILER_BEGIN') for line in lines))

    def test_unclipped_regular_decompilation_remains_complete(self):
        completed, lines = self._analyze('short code')
        self.assertTrue(completed)
        self.assertTrue(any(line.startswith('DECOMPILER_BEGIN entry=1401b0e00 clipped=False ') for line in lines))
        self.assertFalse(any('DECOMPILER_OUTPUT_INCOMPLETE=TRUE' in item for item in lines))

    def test_17087_character_decompilation_is_preserved_without_focus_filter(self):
        # Exact body-size regression: the Ghidra report previously suppressed this
        # complete function when focus terms were missing from emitted C.
        source = 'BEGIN_FUNCTION\n' + ('x' * 17050) + '\nEND_FUNCTION'
        completed, lines = self._analyze(source)
        self.assertTrue(completed)
        self.assertIn(source, lines)
        self.assertTrue(any(line.startswith('DECOMPILER_BEGIN entry=1401b0e00 clipped=False ') for line in lines))
        self.assertFalse(any('DECOMPILER_OUTPUT_INCOMPLETE=TRUE' in item for item in lines))


    def test_explicit_output_budget_preserves_large_complete_function(self):
        source = 'BEGIN_FUNCTION\n' + ('x' * (probe.MAX_DECOMP_CHARS + 100)) + '\nEND_FUNCTION'
        completed, lines = self._analyze(source, full_output_limit=65536)
        self.assertTrue(completed)
        self.assertIn(source, lines)
        self.assertIn('output_limit=65536', '\n'.join(lines))
        self.assertIn('clipped=False', '\n'.join(lines))

    def test_exceeding_extended_output_budget_is_still_incomplete(self):
        completed, lines = self._analyze('x' * 66000, full_output_limit=65536)
        self.assertFalse(completed)
        self.assertTrue(any('clipped=True' in line for line in lines))
        self.assertTrue(any('DECOMPILER_OUTPUT_INCOMPLETE=TRUE' in line for line in lines))
        self.assertNotIn('x' * 66000, '\n'.join(lines))

    def test_invalid_explicit_full_output_limits_are_rejected(self):
        for limit in (0, -1, True, 131073, '65536'):
            with self.subTest(limit=limit):
                with self.assertRaisesRegex(ValueError, 'FULL_DECOMP_MAX_CHARS'):
                    self._analyze('int main() {}', full_output_limit=limit)


class FunctionCallTraceTests(unittest.TestCase):
    """Read-only host fake for bounded call-site evidence, not Ghidra execution."""

    class Instruction:
        def __init__(self, va, mnemonic, assembly):
            self.va, self.mnemonic, self.assembly = va, mnemonic, assembly

        def getAddress(self):
            return self.va

        def getMnemonicString(self):
            return self.mnemonic

        def __str__(self):
            return self.assembly

    class Fixture:
        def __init__(self, calls):
            self.instructions = [FunctionCallTraceTests.Instruction(
                i, 'CALL' if i in calls else 'MOV',
                'CALL qword ptr [0x140e02aa8]' if i in calls else 'MOV RAX,RBX'
            ) for i in range(7)]

        def getListing(self):
            return self

        def getFunctionManager(self):
            return self

        def getFunctionContaining(self, address):
            return self

        def getEntryPoint(self):
            return 0

        def getName(self):
            return 'FUN_FAKE'

        def getBody(self):
            return self

        def contains(self, address):
            return 0 <= address < len(self.instructions)

        def getInstructions(self, body, forward):
            return iter(self.instructions)

        def getInstructionBefore(self, address):
            return self.instructions[address - 1] if address > 0 else None

        def getInstructionAfter(self, address):
            return self.instructions[address + 1] if address + 1 < len(self.instructions) else None

    def test_only_existing_calls_are_reported_with_context(self):
        fixture = self.Fixture({2, 5})
        logs = []
        with patch.object(probe, '_address', side_effect=lambda program, value: value):
            result = probe.inspect_function_calls(fixture, ['0x0'], logs.append)
        output = '\n'.join(logs)
        self.assertTrue(result)
        self.assertEqual(output.count('  FUNCTION_CALL VA='), 2)
        self.assertIn('FUNCTION_CALL VA=2', output)
        self.assertIn('FUNCTION_CALL VA=5', output)
        self.assertIn('BEFORE VA=1', output)
        self.assertIn('AFTER VA=6', output)
        self.assertIn('recorded=2 capped=False', output)

    def test_callsite_cap_is_explicit_partial(self):
        fixture = self.Fixture({1, 2, 3, 4, 5})
        logs = []
        with patch.object(probe, '_address', side_effect=lambda program, value: value), \
             patch.object(probe, 'MAX_CALL_TRACE_SITES', 2):
            result = probe.inspect_function_calls(fixture, ['0x0'], logs.append)
        output = '\n'.join(logs)
        self.assertFalse(result)
        self.assertEqual(output.count('  FUNCTION_CALL VA='), 2)
        self.assertIn('FUNCTION_CALLS_TRUNCATED', output)
        self.assertIn('recorded=2 capped=True', output)

    def test_invalid_requests_rejected(self):
        for targets in ('0x1', ['0x1'] * 3):
            with self.subTest(targets=targets):
                with self.assertRaisesRegex(ValueError, 'TRACE_FUNCTION_CALLS'):
                    probe.inspect_function_calls(None, targets, lambda x: None)


class NestedReceiverCandidateTests(unittest.TestCase):
    """Host-only regression tests for candidate matching, not live Ghidra proof."""

    class _Address(int):
        def getOffset(self):
            return int(self)

    class _Insn:
        def __init__(self, va, asm):
            self.va, self.asm = NestedReceiverCandidateTests._Address(va), asm

        def getAddress(self):
            return self.va

        def getMnemonicString(self):
            return self.asm.split()[0]

        def __str__(self):
            return self.asm

    class _Fixture:
        def __init__(self, asm):
            self.base = 0x140000100
            self.instructions = [
                NestedReceiverCandidateTests._Insn(self.base + i * 8, x)
                for i, x in enumerate(asm)
            ]
            self.data = bytearray(b'\xcc' * (len(asm) * 8))
            # Each fake instruction is eight bytes. Place a real disp32 byte
            # pattern only when the supplied assembly contains that literal.
            for i, instruction in enumerate(self.instructions):
                if '0x108' in str(instruction).lower():
                    self.data[i * 8 + 2:i * 8 + 6] = (0x108).to_bytes(4, 'little')

        def getListing(self):
            return self

        def getFunctionManager(self):
            return self

        def getMemory(self):
            return self

        def getBlocks(self):
            return [self]

        def getStart(self):
            return NestedReceiverCandidateTests._Address(self.base)

        def getSize(self):
            return len(self.data)

        def getName(self):
            return '.text'

        def isInitialized(self):
            return True

        def isExecute(self):
            return True

        def getInstructions(self, forward):
            raise AssertionError('full Ghidra instruction iteration must not be used')

        def getInstructionContaining(self, address):
            index = (int(address) - self.base) // 8
            if not (0 <= index < len(self.instructions)):
                return None
            return self.instructions[index]

        def getInstructionAfter(self, address):
            for index, instruction in enumerate(self.instructions):
                if instruction.va == address:
                    return self.instructions[index + 1] if index + 1 < len(self.instructions) else None
            return None

        def getFunctionContaining(self, address):
            return self

        def getBody(self):
            return self

        def contains(self, address):
            return self.base <= int(address) < self.base + len(self.data)

        def getName(self):
            return 'FUN_TEST_RECEIVER'

        def getEntryPoint(self):
            return NestedReceiverCandidateTests._Address(self.base)

        def read_bytes(self, address, size):
            index = int(address) - self.base
            if index < 0 or index + size > len(self.data):
                raise ValueError('outside fixture block')
            return bytes(self.data[index:index + size])

    def _report(self, asm, deadline=None):
        import time
        lines = []
        program = self._Fixture(asm)
        with patch.object(probe, '_address', side_effect=lambda _p, value: self._Address(value)), \
                patch.object(probe, '_memory_bytes', side_effect=lambda memory, address, length: memory.read_bytes(address, length)):
            status = probe.scan_nested_receiver_candidates(
                program, lines.append, time.monotonic() + 2 if deadline is None else deadline)
        return status, '\n'.join(lines)

    def test_pointer_copy_then_nested_callback_field_is_candidate(self):
        status, report = self._report([
            'MOV RAX,qword ptr [RBX + 0x108]',
            'MOV RDI,RAX',
            'MOV RAX,qword ptr [RDI + 0x250]',
            'CALL qword ptr [0x140e02aa8]'])
        self.assertTrue(status)
        self.assertIn('slot=0x250', report)
        self.assertIn('nearby_transfer=True', report)
        self.assertIn('potential_alias_only=True', report)

    def test_call_clobber_prevents_false_alias(self):
        _, report = self._report([
            'MOV RAX,qword ptr [RBX + 0x108]',
            'CALL qword ptr [0x140e02aa8]',
            'MOV RAX,qword ptr [RAX + 0x170]'])
        self.assertNotIn('RECEIVER_CANDIDATE', report)

    def test_overwritten_register_prevents_false_alias(self):
        _, report = self._report([
            'MOV RAX,qword ptr [RBX + 0x108]',
            'MOV RAX,RSI',
            'MOV RCX,qword ptr [RAX + 0x170]'])
        self.assertNotIn('RECEIVER_CANDIDATE', report)

    def test_result_cap_is_partial(self):
        with patch.object(probe, 'MAX_RECEIVER_RECORDED', 0):
            status, report = self._report([
                'MOV RAX,qword ptr [RBX + 0x108]',
                'MOV RCX,qword ptr [RAX + 0x170]'])
        self.assertFalse(status)
        self.assertIn('capped=True', report)
        self.assertIn('scan_complete=False', report)

    def test_seed_literal_in_nonload_is_not_a_receiver(self):
        status, report = self._report([
            'MOV qword ptr [RBX + 0x108],RAX',
            'MOV RCX,qword ptr [RAX + 0x170]',
            'CALL RDX'])
        self.assertTrue(status)
        self.assertIn('raw_hits=1', report)
        self.assertIn('seeds=0 matched_fields=0', report)
        self.assertNotIn('RECEIVER_CANDIDATE seed_va=', report)

    def test_seed_spanning_memory_chunk_is_found_exactly_once(self):
        with patch.object(probe, 'CHUNK_BYTES', 3):
            status, report = self._report([
                'MOV RAX,qword ptr [RBX + 0x108]',
                'MOV RCX,qword ptr [RAX + 0x170]',
                'CALL RDX'])
        self.assertTrue(status)
        self.assertIn('seeds=1 matched_fields=1', report)
        self.assertEqual(report.count('RECEIVER_CANDIDATE seed_va='), 1)

    def test_byte_cap_cannot_claim_complete(self):
        with patch.object(probe, 'MAX_SCAN_BYTES', 4):
            status, report = self._report([
                'MOV RAX,qword ptr [RBX + 0x108]',
                'MOV RCX,qword ptr [RAX + 0x170]'])
        self.assertFalse(status)
        self.assertIn('reason=BYTE_BUDGET', report)
        self.assertIn('scan_complete=False', report)

    def test_expired_deadline_cannot_claim_complete(self):
        status, report = self._report([
            'MOV RAX,qword ptr [RBX + 0x108]',
            'MOV RCX,qword ptr [RAX + 0x170]'], deadline=0)
        self.assertFalse(status)
        self.assertIn('reason=TIME_BUDGET', report)
        self.assertIn('timed_out=True scan_complete=False', report)

    def test_short_memory_read_is_partial_and_reports_error(self):
        lines = []
        program = self._Fixture([
            'MOV RAX,qword ptr [RBX + 0x108]',
            'MOV RCX,qword ptr [RAX + 0x170]'])
        with patch.object(probe, '_address', side_effect=lambda _p, value: self._Address(value)), \
                patch.object(probe, '_memory_bytes', return_value=b'\x08'):
            import time
            status = probe.scan_nested_receiver_candidates(program, lines.append, time.monotonic() + 2)
        self.assertFalse(status)
        report = '\n'.join(lines)
        self.assertIn('SCAN_NESTED_RECEIVER_READ_ERROR', report)
        self.assertIn('scan_complete=False', report)




class SlotDisplacementBudgetTests(unittest.TestCase):
    """Two verified +0x4B0 instructions prove that the requested cap is enforced."""

    def _scan(self, limit):
        import time

        base = 0x140000100

        class Address(int):
            def getOffset(self):
                return int(self)

        class Instruction:
            def __init__(self, offset):
                self.offset = offset

            def getAddress(self):
                return Address(base + self.offset)

            def __str__(self):
                return 'MOV RAX,qword ptr [RBX + 0x4b0]' if self.offset == 0 else (
                    'MOV qword ptr [RBX + 0x4b0],RAX')

        class Block:
            def getStart(self):
                return Address(base)

            def getSize(self):
                return 8

            def isInitialized(self):
                return True

            def isExecute(self):
                return True

            def getName(self):
                return '.text'

        class Listing:
            def getInstructionContaining(self, where):
                return Instruction(int(where) - base)

        class Functions:
            def getFunctionContaining(self, address):
                return self

            def getName(self):
                return 'FUN_TEST'

            def getEntryPoint(self):
                return Address(base)

        class Program:
            def getMemory(self):
                return self

            def getBlocks(self):
                return [Block()]

            def getListing(self):
                return Listing()

            def getFunctionManager(self):
                return Functions()

        lines = []
        with patch.object(probe, '_address', side_effect=lambda program, value: Address(value)), \
             patch.object(probe, '_memory_bytes',
                          return_value=(0x4b0).to_bytes(4, 'little') * 2):
            complete = probe.scan_existing_slot_displacements(
                Program(), '0x4b0', lines.append, time.monotonic() + 2,
                max_recorded=limit)
        return complete, '\n'.join(lines)

    def test_two_hits_are_complete_with_sufficient_limit(self):
        complete, report = self._scan(2)
        self.assertTrue(complete)
        self.assertEqual(report.count('SLOT_CANDIDATE VA='), 2)
        self.assertIn('selected_candidates=2', report)
        self.assertIn('capped=False scan_complete=True', report)

    def test_truncated_hit_list_is_partial_not_complete(self):
        complete, report = self._scan(1)
        self.assertFalse(complete)
        self.assertEqual(report.count('SLOT_CANDIDATE VA='), 1)
        self.assertIn('selected_candidates=2', report)
        self.assertIn('capped=True scan_complete=False', report)

    def test_invalid_record_limits_fail_before_reading_program(self):
        import time
        for limit in (0, 5001, True, '5000', None):
            with self.subTest(limit=limit):
                with self.assertRaisesRegex(ValueError, 'SLOT_SCAN_MAX_RECORDED'):
                    probe.scan_existing_slot_displacements(
                        None, '0x4b0', lambda line: None, time.monotonic() + 2,
                        max_recorded=limit)


if __name__ == '__main__':
    unittest.main()


class ReferenceGraphWalkTests(unittest.TestCase):
    """Graph edges must reflect original reference kinds, with no invented calls."""

    def setUp(self):
        import tempfile
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def _fixture(self):
        class Address:
            def __init__(self, value):
                self.value = value

            def getOffset(self):
                return self.value

            def __str__(self):
                return '%x' % self.value

            def __eq__(self, other):
                return isinstance(other, Address) and self.value == other.value

            def __hash__(self):
                return hash(self.value)

        class Type:
            def __init__(self, kind):
                self.kind = kind

            def isCall(self):
                return self.kind == 'CALL'

            def isJump(self):
                return self.kind == 'JUMP'

            def isData(self):
                return self.kind == 'DATA'

        class Reference:
            def __init__(self, src, dst, kind):
                self.src, self.dst, self.kind = Address(src), Address(dst), Type(kind)

            def getFromAddress(self):
                return self.src

            def getToAddress(self):
                return self.dst

            def getReferenceType(self):
                return self.kind

        class Instruction:
            def __init__(self, address, mnemonic):
                self.address, self.mnemonic = Address(address), mnemonic

            def getAddress(self):
                return self.address

            def getMnemonicString(self):
                return self.mnemonic

        class Function:
            def __init__(self, address, instructions):
                self.entry = Address(address)
                self.instructions = [Instruction(*item) for item in instructions]

            def getEntryPoint(self):
                return self.entry

            def getName(self):
                return 'FUN_%x' % self.entry.value

            def getBody(self):
                return self

        class FunctionManager:
            def __init__(self, functions):
                self.functions = functions

            def getFunctionContaining(self, address):
                for fn in self.functions:
                    if fn.entry.value <= address.value < fn.entry.value + 0x100:
                        return fn
                return None

            def getFunctionAt(self, address):
                return next((fn for fn in self.functions if fn.entry == address), None)

        class Listing:
            def getInstructions(self, function, forward):
                return iter(function.instructions)

        class RefManager:
            def __init__(self, references):
                self.refs = references

            def getReferencesFrom(self, address):
                return [ref for ref in self.refs if ref.src == address]

            def getReferencesTo(self, address):
                return [ref for ref in self.refs if ref.dst == address]

        class Block:
            def __init__(self, address):
                self.address = address

            def isExecute(self):
                return self.address.value < 0x500

            def getName(self):
                return '.text' if self.isExecute() else '.rdata'

        class Memory:
            def getBlock(self, address):
                return Block(address)

        class Program:
            def __init__(self, functions, references):
                self.functions = FunctionManager(functions)
                self.references = RefManager(references)
                self.listing = Listing()
                self.memory = Memory()

            def getFunctionManager(self):
                return self.functions

            def getReferenceManager(self):
                return self.references

            def getListing(self):
                return self.listing

            def getMemory(self):
                return self.memory

        # A references C as a function pointer before it directly calls B.
        # B directly calls C and A; a standalone data table references A.
        a = Function(0x100, [(0x110, 'CALL'), (0x120, 'LEA'), (0x130, 'CALL')])
        b = Function(0x200, [(0x210, 'CALL'), (0x220, 'CALL')])
        c = Function(0x300, [(0x310, 'CALL')])
        refs = [Reference(0x110, 0x200, 'CALL'),
                Reference(0x120, 0x300, 'DATA'),
                Reference(0x210, 0x300, 'CALL'),
                Reference(0x220, 0x100, 'CALL'),
                Reference(0x310, 0x200, 'CALL'),
                Reference(0x500, 0x100, 'DATA')]
        return Program([a, b, c], refs), Address

    def _run(self, **overrides):
        import json
        from pathlib import Path
        program, Address = self._fixture()
        options = probe._graph_options({
            'GRAPH_ROOTS': ['0x100'],
            'GRAPH_DEPTH': 3,
            **overrides,
        })
        report = Path(self.directory.name) / 'output.txt'
        with patch.object(probe, '_address', side_effect=lambda _program, value: Address(value)):
            completed = probe.graph_reference_walk(
                program, ['0x100'], lambda _line: None, report, options)
        graph = json.loads(report.with_name('output-reference-graph.json').read_text())
        dot = report.with_name('output-reference-graph.dot').read_text()
        return completed, graph, dot

    def test_forward_backward_direct_calls_data_and_unknown_are_distinct(self):
        complete, graph, dot = self._run()
        self.assertTrue(complete)
        self.assertEqual(graph['status'], 'COMPLETE')
        edge_types = {(e['source'], e['target'], e['kind']) for e in graph['edges']}
        self.assertIn(('f_100', 'f_200', 'CALL'), edge_types)
        self.assertIn(('f_200', 'f_300', 'CALL'), edge_types)
        self.assertIn(('f_300', 'f_200', 'CALL'), edge_types)
        self.assertIn(('f_100', 'f_300', 'ADDRESS_TAKEN'), edge_types)
        self.assertIn(('d_500', 'f_100', 'DATA_REF'), edge_types)
        self.assertIn(('f_100', 'i_130', 'INDIRECT_UNKNOWN'), edge_types)
        self.assertIn('style=dotted', dot)
        self.assertIn('style=dashed', dot)
        self.assertTrue(all(e['site'].startswith('0x') for e in graph['edges']))

    def test_existing_data_pointer_target_is_not_lost_as_direct_callee(self):
        complete, graph, _dot = self._run()
        self.assertTrue(complete)
        self.assertIn(('f_300', 'f_200', 'CALL'),
                      {(e['source'], e['target'], e['kind']) for e in graph['edges']})

    def test_node_budget_must_produce_partial_result_and_real_artifact(self):
        complete, graph, _dot = self._run(GRAPH_MAX_NODES=2)
        self.assertFalse(complete)
        self.assertEqual(graph['status'], 'PARTIAL')
        self.assertIn('NODE_LIMIT', graph['omissions'])

    def test_reference_budget_must_produce_partial_not_false_complete(self):
        complete, graph, _dot = self._run(GRAPH_REFS_PER_FUNCTION=1)
        self.assertFalse(complete)
        self.assertIn('REFERENCE_LIMIT', graph['omissions'])

    def test_invalid_graph_settings_rejected(self):
        for settings in (
            {'GRAPH_ROOTS': '0x100'},
            {'GRAPH_ROOTS': ['0x100'], 'GRAPH_DEPTH': -1},
            {'GRAPH_ROOTS': ['0x100'], 'GRAPH_DECOMPILE_LIMIT': 129},
            {'GRAPH_ROOTS': ['0x100'], 'GRAPH_DECOMPILE_ON_WALK': True},
            {'GRAPH_ROOTS': ['0x100'], 'GRAPH_DECOMPILE_ON_WALK': 'yes'},
            {'GRAPH_ROOTS': ['0x100'], 'GRAPH_MAX_NODES': True},
            {'GRAPH_ROOTS': ['0x100'], 'GRAPH_DIRECTION': 'magic'},
        ):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                probe._graph_options(settings)

    def test_unavailable_root_is_partial_not_silent_success(self):
        import json
        from pathlib import Path
        program, Address = self._fixture()
        report = Path(self.directory.name) / 'unavailable.txt'
        settings = probe._graph_options({'GRAPH_ROOTS': ['0x900']})
        with patch.object(probe, '_address', side_effect=lambda _p, value: Address(value)):
            complete = probe.graph_reference_walk(program, ['0x900'],
                                                  lambda _line: None, report, settings)
        graph = json.loads(report.with_name('unavailable-reference-graph.json').read_text())
        self.assertFalse(complete)
        self.assertEqual(graph['omissions'], ['INVALID_ROOT'])



    def test_bidirectional_walk_preserves_direction_at_shared_helper(self):
        # Root A calls helper B; unrelated D calls B. No D -> A path exists.
        # In both mode, a wrong forward-then-backward pivot pulls D into graph.
        program, Address = self._fixture()
        function_type = type(program.functions.functions[0])
        reference_type = type(program.references.refs[0])
        program.functions.functions.append(function_type(0x400, [(0x410, 'CALL')]))
        program.references.refs = [
            ref for ref in program.references.refs if ref.src.value != 0x220
        ]
        program.references.refs.append(reference_type(0x410, 0x200, 'CALL'))
        with patch.object(self, '_fixture', return_value=(program, Address)):
            complete, graph, _dot = self._run(GRAPH_DIRECTION='both', GRAPH_DEPTH=2)
        self.assertTrue(complete)
        self.assertNotIn('f_400', {node['id'] for node in graph['nodes']})
        self.assertEqual(graph['schema'], 'ghidra-static-function-references-v3')
        self.assertIn(('f_100', 'f_200', 'CALL'),
                      {(e['source'], e['target'], e['kind']) for e in graph['edges']})

    def test_authorized_increased_graph_and_decompile_limits(self):
        options = probe._graph_options({
            'GRAPH_ROOTS': ['0x100'],
            'GRAPH_MAX_NODES': 1024,
            'GRAPH_MAX_EDGES': 8192,
            'GRAPH_REFS_PER_FUNCTION': 8192,
            'GRAPH_INSTRUCTIONS_PER_FUNCTION': 100000,
            'GRAPH_TIMEOUT_SECONDS': 600,
            'GRAPH_DECOMPILE_LIMIT': 64,
            'GRAPH_DECOMPILE_ON_WALK': True,
        })
        self.assertEqual(options['nodes'], 1024)
        self.assertEqual(options['edges'], 8192)
        self.assertEqual(options['decompile'], 64)
        self.assertTrue(options['decompile_on_walk'])

    def test_decompiles_during_walk_once_per_function_with_single_session(self):
        import json
        import sys
        from pathlib import Path
        from types import ModuleType, SimpleNamespace

        instances = []

        class FakeDecompiler:
            def __init__(self):
                self.calls = []
                self.disposed = False
                instances.append(self)

            def openProgram(self, program):
                return True

            def decompileFunction(self, fn, _timeout, _monitor):
                self.calls.append(fn.getEntryPoint().value)
                return SimpleNamespace(
                    decompileCompleted=lambda: True,
                    getDecompiledFunction=lambda: SimpleNamespace(
                        getC=lambda: 'void FUN_%x() {}' % fn.getEntryPoint().value))

            def dispose(self):
                self.disposed = True

        modules = {name: ModuleType(name) for name in (
            'ghidra', 'ghidra.app', 'ghidra.app.decompiler',
            'ghidra.util', 'ghidra.util.task')}
        modules['ghidra.app.decompiler'].DecompInterface = FakeDecompiler
        modules['ghidra.util.task'].TaskMonitor = SimpleNamespace(DUMMY=object())

        program, Address = self._fixture()
        report = Path(self.directory.name) / 'during-walk.txt'
        settings = probe._graph_options({
            'GRAPH_ROOTS': ['0x100'],
            'GRAPH_DIRECTION': 'forward',
            'GRAPH_DEPTH': 3,
            'GRAPH_DECOMPILE_ON_WALK': True,
            'GRAPH_DECOMPILE_LIMIT': 2,
        })
        logs = []
        with patch.dict(sys.modules, modules), patch.object(
                probe, '_address', side_effect=lambda _p, value: Address(value)):
            complete = probe.graph_reference_walk(program, ['0x100'],
                                                  logs.append, report, settings)
        graph = json.loads(report.with_name('during-walk-reference-graph.json').read_text())
        self.assertTrue(complete)
        self.assertEqual(graph['status'], 'COMPLETE')
        self.assertEqual(graph['walk_decompilation_attempted'], 2)
        self.assertEqual(len(instances), 1)
        self.assertTrue(instances[0].disposed)
        self.assertEqual(len(instances[0].calls), 2)
        self.assertEqual(len(set(instances[0].calls)), 2)
        self.assertEqual(instances[0].calls[0], 0x100)
        self.assertTrue(any('GRAPH_DECOMPILER_BEGIN entry=0x100' in line for line in logs))
        self.assertTrue(any('GRAPH_DECOMPILER_END entry=0x100' in line for line in logs))
        self.assertTrue(any('GRAPH_DECOMPILE_COUNT=2' in line for line in logs))

    def test_failed_or_clipped_walk_decompile_is_partial(self):
        import json
        import sys
        from pathlib import Path
        from types import ModuleType, SimpleNamespace

        class FakeDecompiler:
            def openProgram(self, _program):
                return True

            def decompileFunction(self, _fn, _timeout, _monitor):
                return SimpleNamespace(
                    decompileCompleted=lambda: True,
                    getDecompiledFunction=lambda: SimpleNamespace(getC=lambda: 'C' * 300))

            def dispose(self):
                pass

        modules = {name: ModuleType(name) for name in (
            'ghidra', 'ghidra.app', 'ghidra.app.decompiler',
            'ghidra.util', 'ghidra.util.task')}
        modules['ghidra.app.decompiler'].DecompInterface = FakeDecompiler
        modules['ghidra.util.task'].TaskMonitor = SimpleNamespace(DUMMY=object())

        program, Address = self._fixture()
        report = Path(self.directory.name) / 'clipped.txt'
        settings = probe._graph_options({
            'GRAPH_ROOTS': ['0x100'], 'GRAPH_DIRECTION': 'forward',
            'GRAPH_DECOMPILE_ON_WALK': True, 'GRAPH_DECOMPILE_LIMIT': 1,
            'GRAPH_CODE_CHARS': 256,
        })
        with patch.dict(sys.modules, modules), patch.object(
                probe, '_address', side_effect=lambda _p, value: Address(value)):
            complete = probe.graph_reference_walk(program, ['0x100'],
                                                  lambda _s: None, report, settings)
        graph = json.loads(report.with_name('clipped-reference-graph.json').read_text())
        self.assertFalse(complete)
        self.assertEqual(graph['status'], 'PARTIAL')
        self.assertIn('DECOMPILER_OUTPUT_CLIPPED', graph['omissions'])


class BoundedFunctionListingTests(unittest.TestCase):
    """Independent mock checks: preserve evidence and fail on incomplete listings."""

    @staticmethod
    def fixture(assemblies=('MOV R15,qword ptr [RCX + 0x2138]',
                             'LEA R8,[RSP + 0x58]'), executable=True,
                entry=0x100, body_bytes=None):
        from types import SimpleNamespace

        class Address:
            def __init__(self, value):
                self.value = value

            def __eq__(self, other):
                return isinstance(other, Address) and self.value == other.value

            def __str__(self):
                return '0x%x' % self.value

        class Instruction:
            def __init__(self, address, asm):
                self.address, self.asm = Address(address), asm

            def getAddress(self):
                return self.address

            def getLength(self):
                return 3

            def __str__(self):
                return self.asm

        instructions = [Instruction(0x100 + i * 3, asm)
                        for i, asm in enumerate(assemblies)]
        body = SimpleNamespace(getNumAddresses=lambda: (
            3 * len(instructions) if body_bytes is None else body_bytes))
        function = SimpleNamespace(getEntryPoint=lambda: Address(entry),
                                   getName=lambda: 'FUN_100', getBody=lambda: body)
        program = SimpleNamespace(
            getMemory=lambda: SimpleNamespace(getBlock=lambda _address: (
                SimpleNamespace(isExecute=lambda: executable))),
            getFunctionManager=lambda: SimpleNamespace(
                getFunctionContaining=lambda _address: function),
            getListing=lambda: SimpleNamespace(
                getInstructions=lambda _body, _forward: iter(instructions)))
        return program, Address

    def test_complete_listing_preserves_register_and_stack_machine_evidence(self):
        program, address = self.fixture()
        records = []
        with patch.object(probe, '_address', side_effect=lambda _p, n: address(n)):
            self.assertTrue(probe.inspect_function_listing(program, ['0x100'], records.append))
        self.assertEqual(sum('  LISTING VA=' in record for record in records), 2)
        self.assertTrue(any('MOV R15,qword ptr [RCX + 0x2138]' in record for record in records))
        self.assertTrue(any('LEA R8,[RSP + 0x58]' in record for record in records))
        self.assertTrue(any('REGISTER_STACK_PROVENANCE_NOT_INFERRED' in record for record in records))
        self.assertFalse(any('TRUNCATED' in record for record in records))

    def test_cap_is_a_reported_partial_result_not_success(self):
        program, address = self.fixture()
        records = []
        with patch.object(probe, '_address', side_effect=lambda _p, n: address(n)), \
             patch.object(probe, 'MAX_FUNCTION_LISTING_INSTRUCTIONS', 1):
            self.assertFalse(probe.inspect_function_listing(program, ['0x100'], records.append))
        self.assertTrue(any('FUNCTION_LISTING_TRUNCATED' in record for record in records))
        self.assertEqual(sum('  LISTING VA=' in record for record in records), 1)

    def test_missing_instruction_coverage_is_partial(self):
        program, address = self.fixture(body_bytes=7)
        records = []
        with patch.object(probe, '_address', side_effect=lambda _p, n: address(n)):
            self.assertFalse(probe.inspect_function_listing(program, ['0x100'], records.append))
        self.assertTrue(any('FUNCTION_LISTING_COVERAGE_PARTIAL' in record for record in records))

    def test_rejects_nonentry_and_nonexecutable_targets(self):
        for kwargs in ({'entry': 0x200}, {'executable': False}):
            with self.subTest(kwargs=kwargs):
                program, address = self.fixture(**kwargs)
                records = []
                with patch.object(probe, '_address', side_effect=lambda _p, n: address(n)):
                    self.assertFalse(probe.inspect_function_listing(program, ['0x100'], records.append))
                self.assertTrue(any('FUNCTION_LISTING_UNAVAILABLE' in record for record in records))

    def test_rejects_unbounded_or_malformed_target_sets(self):
        program, _ = self.fixture()
        for invalid in ('0x100', ['0x100', '0x200'], {0x100}, None):
            with self.subTest(targets=invalid), self.assertRaises(ValueError):
                probe.inspect_function_listing(program, invalid, lambda _line: None)

