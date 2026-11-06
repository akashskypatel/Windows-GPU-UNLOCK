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
    def _analyze(self, c_source):
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
                return type('Output', (), {'getC': lambda self: c_source})()

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
                return type('Refs', (), {'getReferencesTo': lambda self, address: []})()

        modules = {name: types.ModuleType(name) for name in
                   ('ghidra', 'ghidra.app', 'ghidra.app.decompiler',
                    'ghidra.util', 'ghidra.util.task')}
        modules['ghidra.app.decompiler'].DecompInterface = Decompiler
        modules['ghidra.util.task'].TaskMonitor = type('TaskMonitor', (), {'DUMMY': None})
        logs = []
        with patch.dict(sys.modules, modules), \
             patch.object(probe, '_address', side_effect=lambda program, address: Address()):
            result = probe.targeted_decompile(Program(), ['0x1401b0e00'], logs.append)
        return result, logs

    def test_clipped_regular_decompilation_reports_incomplete(self):
        completed, lines = self._analyze('X' * (probe.MAX_DECOMP_CHARS + 5))
        self.assertFalse(completed)
        self.assertIn('DECOMPILER_BEGIN entry=1401b0e00 clipped=True', lines)
        self.assertTrue(any('DECOMPILER_OUTPUT_INCOMPLETE=TRUE' in item for item in lines))

    def test_unclipped_regular_decompilation_remains_complete(self):
        completed, lines = self._analyze('short code')
        self.assertTrue(completed)
        self.assertIn('DECOMPILER_BEGIN entry=1401b0e00 clipped=False', lines)
        self.assertFalse(any('DECOMPILER_OUTPUT_INCOMPLETE=TRUE' in item for item in lines))


class NestedReceiverCandidateTests(unittest.TestCase):
    """Host-only regression tests for candidate matching, not live Ghidra proof."""

    class _Insn:
        def __init__(self, va, asm):
            self.va, self.asm = va, asm

        def getAddress(self):
            return self.va

        def getMnemonicString(self):
            return self.asm.split()[0]

        def __str__(self):
            return self.asm

    class _Fixture:
        def __init__(self, asm):
            self.instructions = [NestedReceiverCandidateTests._Insn(i + 1, x)
                                 for i, x in enumerate(asm)]

        def getListing(self):
            return self

        def getFunctionManager(self):
            return self

        def getMemory(self):
            return self

        def getInstructions(self, forward):
            return iter(self.instructions)

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
            return True

        def getName(self):
            return 'FUN_TEST_RECEIVER'

        def getEntryPoint(self):
            return 0x140000100

        def getBlock(self, address):
            return self

        def isExecute(self):
            return True

    def _report(self, asm):
        import time
        lines = []
        status = probe.scan_nested_receiver_candidates(
            self._Fixture(asm), lines.append, time.monotonic() + 2)
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


if __name__ == '__main__':
    unittest.main()
