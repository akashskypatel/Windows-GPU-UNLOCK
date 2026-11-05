"""Host-only regression tests for exact, bounded Ghidra string-lead probing."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

path = Path(__file__).with_name('nvlddmkm_booter_discovery.py')
spec = importlib.util.spec_from_file_location('nvlddmkm_booter_discovery', path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Block:
    def __init__(self, initialized=True):
        self.initialized = initialized

    def isInitialized(self):
        return self.initialized

    def isExecute(self):
        return False

    def getName(self):
        return '.text'


class Memory:
    def __init__(self, initialized=True):
        self.block = Block(initialized)

    def getBlock(self, address):
        return self.block


class Program:
    def __init__(self, initialized=True):
        self.memory = Memory(initialized)

    def getMemory(self):
        return self.memory


class ExactStringLeadTests(unittest.TestCase):
    def test_exact_byte_match_reuses_existing_reference_reporter(self):
        output, discovered = [], []
        program = Program()
        leads = [('GSP_LOAD_EXEC_HS_BINARY', 0x140d090a0)]
        with patch.object(probe, '_address', side_effect=lambda _, n: n), \
             patch.object(probe, '_memory_bytes', return_value=b'GSP_LOAD_EXEC_HS_BINARY'), \
             patch.object(probe, 'describe_references', side_effect=lambda p, hits, log: discovered.extend(hits)):
            probe.scan_known_string_references(program, output.append, leads)
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0]['va'], 0x140d090a0)
        self.assertEqual(discovered[0]['term'], 'GSP_LOAD_EXEC_HS_BINARY')
        self.assertEqual(discovered[0]['encoding'], 'CSV_EXACT_ASCII')
        self.assertTrue(any('CSV_LEAD_COUNT=1' in line for line in output))

    def test_mismatched_driver_literal_refused_before_xrefs(self):
        with patch.object(probe, '_address', side_effect=lambda _, n: n), \
             patch.object(probe, '_memory_bytes', return_value=b'MISMATCH'), \
             patch.object(probe, 'describe_references') as reporter:
            with self.assertRaisesRegex(ValueError, 'differ from expected literal'):
                probe.scan_known_string_references(Program(), lambda line: None, [('GSP_LOAD_EXEC_HS_BINARY', 0x140d090a0)])
            reporter.assert_not_called()

    def test_uninitialized_memory_refused_before_any_reads(self):
        with patch.object(probe, '_address', side_effect=lambda _, n: n), \
             patch.object(probe, '_memory_bytes') as reader:
            with self.assertRaisesRegex(ValueError, 'not in initialized'):
                probe.scan_known_string_references(Program(initialized=False), lambda line: None,
                                                  [('GSP_LOAD_EXEC_HS_BINARY', 0x140d090a0)])
            reader.assert_not_called()

    def test_excessive_explicit_leads_refused(self):
        with self.assertRaisesRegex(ValueError, 'too many'):
            probe.scan_known_string_references(Program(), lambda line: None, [('test', 0)] * 25)



class DataReferenceSiteTests(unittest.TestCase):
    def test_data_site_reports_outbound_pointer_and_inbound_table_owner(self):
        from types import SimpleNamespace
        site = 0x140e19a0c
        table_start = 0x140e19a00
        fn_address = 0x140bf3880

        class Ref:
            def __init__(self, source, dest):
                self.source, self.dest = source, dest
            def getFromAddress(self):
                return self.source
            def getToAddress(self):
                return self.dest
            def getReferenceType(self):
                return 'DATA'

        class RefManager:
            def getReferencesFrom(self, address):
                return [Ref(site, fn_address)] if address == site else []
            def getReferencesTo(self, address):
                return [Ref(0x140001234, table_start)] if address == table_start else []

        class ProgramWithTable(Program):
            def getListing(self):
                return SimpleNamespace(getDataContaining=lambda address: SimpleNamespace(
                    isDefined=lambda: True, getMinAddress=lambda: table_start))
            def getReferenceManager(self):
                return RefManager()
            def getFunctionManager(self):
                return SimpleNamespace(getFunctionContaining=lambda address: SimpleNamespace(
                    getName=lambda: 'FUN_%x' % address,
                    getEntryPoint=lambda: address))

        lines = []
        with patch.object(probe, '_address', side_effect=lambda p, n: n):
            self.assertTrue(probe.inspect_data_reference_sites(ProgramWithTable(), ['0x140e19a0c'], lines.append))
        self.assertTrue(any('OUTBOUND target=%d' % fn_address in x for x in lines))
        self.assertTrue(any('INBOUND_ROOT VA=%d count=1' % table_start in x for x in lines))
        self.assertTrue(any('INBOUND from=5368713780' in x for x in lines))

    def test_missing_initialized_data_site_reports_partial_not_complete(self):
        from types import SimpleNamespace
        class MissingSite(Program):
            pass
        lines = []
        with patch.object(probe, '_address', side_effect=lambda p, n: n):
            self.assertFalse(probe.inspect_data_reference_sites(MissingSite(initialized=False), ['0x140e19a0c'], lines.append))
        self.assertTrue(any('DATA_SITE_UNAVAILABLE' in x for x in lines))

    def test_unbounded_site_requests_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'TRACE_DATA_SITES'):
            probe.inspect_data_reference_sites(Program(), ['0x140e19a0c'] * 9, lambda line: None)
        with self.assertRaisesRegex(ValueError, 'TRACE_DATA_SITES'):
            probe.inspect_data_reference_sites(Program(), '0x140e19a0c', lambda line: None)


class InstructionSiteTests(unittest.TestCase):
    class Insn:
        def __init__(self, addr, op):
            self.addr, self.op = addr, op
        def getAddress(self):
            return self.addr
        def __str__(self):
            return self.op

    def test_existing_callsite_context_is_bounded_and_ordered(self):
        from types import SimpleNamespace
        base = 0x1402e7e60
        insns = [self.Insn(base + i, op) for i, op in enumerate(
            ['mov rcx,rbx', 'mov rdx,rsi', 'call 0x1406b3fd0', 'test eax,eax', 'ret'])]
        by_addr = {i.getAddress(): i for i in insns}
        listing = SimpleNamespace(
            getInstructionContaining=lambda a: by_addr.get(a),
            getInstructionBefore=lambda a: by_addr.get(a - 1),
            getInstructionAfter=lambda a: by_addr.get(a + 1))
        fn = SimpleNamespace(
            getEntryPoint=lambda: base, getName=lambda: 'test_function',
            getBody=lambda: SimpleNamespace(contains=lambda a: base <= a < base + 5))
        class ExecutableBlock(Block):
            def isExecute(self):
                return True
        class TestProgram(Program):
            def getListing(self):
                return listing
            def getFunctionManager(self):
                return SimpleNamespace(getFunctionContaining=lambda a: fn)
        p = TestProgram()
        p.memory.block = ExecutableBlock()
        out = []
        with patch.object(probe, '_address', side_effect=lambda program, n: n):
            self.assertTrue(probe.inspect_instruction_sites(p, [hex(base + 2)], out.append))
        self.assertEqual(sum('  AT VA=' in line for line in out), 1)
        self.assertTrue(any('  BEFORE VA=' in line and 'mov rcx,rbx' in line for line in out))
        self.assertTrue(any('  AT VA=' in line and 'call 0x1406b3fd0' in line for line in out))
        self.assertTrue(any('  AFTER VA=' in line and 'test eax,eax' in line for line in out))
        self.assertTrue(any('ABI_OR_RUNTIME_NOT_PROVEN' in line for line in out))

    def test_nonexecutable_site_reports_partial(self):
        p = Program()
        out = []
        with patch.object(probe, '_address', side_effect=lambda program, n: n):
            self.assertFalse(probe.inspect_instruction_sites(p, ['0x1402e7e6b'], out.append))
        self.assertTrue(any('INSTRUCTION_SITE_UNAVAILABLE' in line for line in out))

    def test_unbounded_or_scalar_site_input_rejected(self):
        with self.assertRaisesRegex(ValueError, 'TRACE_INSTRUCTION_SITES'):
            probe.inspect_instruction_sites(Program(), ['0x1402e7e6b'] * 5, lambda line: None)
        with self.assertRaisesRegex(ValueError, 'TRACE_INSTRUCTION_SITES'):
            probe.inspect_instruction_sites(Program(), '0x1402e7e6b', lambda line: None)

if __name__ == '__main__':
    unittest.main()
