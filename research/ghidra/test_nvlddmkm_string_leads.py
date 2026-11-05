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


class SlotDisplacementScanTests(unittest.TestCase):
    class Instruction:
        def __init__(self, addr, assembly):
            self.addr, self.assembly = addr, assembly
        def getAddress(self):
            return self.addr
        def __str__(self):
            return self.assembly

    def run_scan(self, data, asm, *, max_bytes=512, chunk_bytes=4, focus='all'):
        from types import SimpleNamespace
        base = 0x140000000
        starts = [n for n in range(len(data)) if data.startswith(b'\x70\x01\x00\x00', n)]
        assert len(starts) <= 1
        instruction = self.Instruction(base + starts[0], asm) if starts else None

        class ExecutableMemoryBlock:
            def isInitialized(self):
                return True
            def isExecute(self):
                return True
            def getName(self):
                return '.text'
            def getStart(self):
                return SimpleNamespace(getOffset=lambda: base)
            def getSize(self):
                return len(data)

        class MemoryWithCode:
            def getBlocks(self):
                return [ExecutableMemoryBlock()]

        class ProgramWithCode:
            def getMemory(self):
                return MemoryWithCode()
            def getListing(self):
                return SimpleNamespace(getInstructionContaining=lambda a: instruction if instruction is not None and a >= instruction.addr and a < instruction.addr + 4 else None)
            def getFunctionManager(self):
                return SimpleNamespace(getFunctionContaining=lambda a: SimpleNamespace(getName=lambda: 'FUN_target', getEntryPoint=lambda: base))

        out = []
        with patch.object(probe, '_address', side_effect=lambda program, integer: integer), \
             patch.object(probe, '_memory_bytes', side_effect=lambda mem, addr, n: data[addr-base:addr-base+n]), \
             patch.object(probe, 'CHUNK_BYTES', chunk_bytes), \
             patch.object(probe, 'MAX_SCAN_BYTES', max_bytes), \
             patch.object(probe.time, 'monotonic', return_value=1.0):
            result = probe.scan_existing_slot_displacements(ProgramWithCode(), 0x170, out.append, 2.0, focus=focus)
        return result, out

    def test_write_focus_selects_qword_store_and_not_memory_read(self):
        result, out = self.run_scan(b'AB\x70\x01\x00\x00CD',
                                    'MOV qword ptr [RCX + 0x170],RAX', focus='write')
        self.assertTrue(result)
        self.assertEqual(sum('SLOT_CANDIDATE' in line for line in out), 1)
        self.assertTrue(any('FIELD_WRITE_QWORD' in line for line in out))
        self.assertTrue(any('selected_candidates=1 focus=write' in line for line in out))
        result, out = self.run_scan(b'AB\x70\x01\x00\x00CD',
                                    'MOV RAX,qword ptr [RCX + 0x170]', focus='write')
        self.assertTrue(result)
        self.assertFalse(any('SLOT_CANDIDATE' in line for line in out))
        self.assertTrue(any('selected_candidates=0 focus=write' in line for line in out))

    def test_write_focus_excludes_lea_cmp_and_keeps_simd_store(self):
        for assembly in ('LEA RAX,[RCX + 0x170]',
                         'CMP qword ptr [RCX + 0x170],RAX'):
            with self.subTest(assembly=assembly):
                result, out = self.run_scan(b'AB\x70\x01\x00\x00CD',
                                            assembly, focus='write')
                self.assertTrue(result)
                self.assertFalse(any('SLOT_CANDIDATE' in line for line in out))
        result, out = self.run_scan(b'AB\x70\x01\x00\x00CD',
                                    'MOVUPS xmmword ptr [RCX + 0x170],XMM0', focus='write')
        self.assertTrue(result)
        self.assertTrue(any('FIELD_WRITE_XMMWORD' in line for line in out))

    def test_transfer_focus_keeps_direct_memory_call(self):
        result, out = self.run_scan(b'AB\x70\x01\x00\x00CD',
                                    'CALL qword ptr [RCX + 0x170]', focus='transfer')
        self.assertTrue(result)
        self.assertEqual(sum(x.startswith('SLOT_CANDIDATE') for x in out), 1)
        self.assertTrue(any('DIRECT_MEMORY_TRANSFER' in x for x in out))
        self.assertTrue(any('selected_candidates=1 focus=transfer' in x for x in out))

    def test_transfer_focus_excludes_other_memory_fields_without_false_partial(self):
        result, out = self.run_scan(b'AB\x70\x01\x00\x00CD',
                                    'CMP dword ptr [RCX + 0x170],0x0', focus='transfer')
        self.assertTrue(result)
        self.assertEqual(sum(x.startswith('SLOT_CANDIDATE') for x in out), 0)
        self.assertTrue(any('distinct_instruction_candidates=1' in x and
                            'selected_candidates=0 focus=transfer' in x for x in out))

    def test_disp32_spanning_chunk_boundary_matches_existing_instruction(self):
        result, out = self.run_scan(b'AB\x70\x01\x00\x00CD', 'MOV RAX,qword ptr [RCX + 0x170]')
        self.assertTrue(result)
        found = [x for x in out if x.startswith('SLOT_CANDIDATE')]
        self.assertEqual(len(found), 1)
        self.assertIn('FUN_target', found[0])
        self.assertTrue(any('raw_hits=1 distinct_instruction_candidates=1' in x for x in out))

    def test_unrelated_immediate_does_not_become_a_dispatch_candidate(self):
        result, out = self.run_scan(b'AB\x70\x01\x00\x00CD', 'MOV EAX,0x170')
        self.assertTrue(result)
        self.assertFalse(any(x.startswith('SLOT_CANDIDATE') for x in out))
        self.assertTrue(any('raw_hits=1 distinct_instruction_candidates=0' in x for x in out))

    def test_incomplete_byte_budget_is_reported_as_partial(self):
        result, out = self.run_scan(b'ABCDEFGHIJKLMNO', '', max_bytes=4)
        self.assertFalse(result)
        self.assertTrue(any('SLOT_SCAN_TRUNCATED' in x for x in out))
        self.assertTrue(any('scan_complete=False' in x for x in out))

    def test_candidate_cap_marks_scan_partial(self):
        with patch.object(probe, 'MAX_SLOT_CANDIDATES', 0):
            result, out = self.run_scan(b'AB\x70\x01\x00\x00CD',
                                        'MOV RAX,qword ptr [RCX + 0x170]')
        self.assertFalse(result)
        self.assertTrue(any('distinct_instruction_candidates=1 recorded=0 capped=True' in x for x in out))

    def test_exact_budget_on_first_of_two_blocks_does_not_report_complete(self):
        from types import SimpleNamespace
        class Section:
            def __init__(self, base):
                self.base = base
            def isInitialized(self):
                return True
            def isExecute(self):
                return True
            def getName(self):
                return '.text'
            def getStart(self):
                return SimpleNamespace(getOffset=lambda: self.base)
            def getSize(self):
                return 4
        class MemoryWithTwoBlocks:
            def getBlocks(self):
                return [Section(0x1000), Section(0x2000)]
        class ProgramWithTwoBlocks:
            def getMemory(self):
                return MemoryWithTwoBlocks()
            def getListing(self):
                return SimpleNamespace(getInstructionContaining=lambda addr: None)
            def getFunctionManager(self):
                return SimpleNamespace(getFunctionContaining=lambda addr: None)
        out = []
        with patch.object(probe, '_address', side_effect=lambda p, n: n), \
             patch.object(probe, '_memory_bytes', return_value=b'ABCD'), \
             patch.object(probe, 'MAX_SCAN_BYTES', 4), \
             patch.object(probe.time, 'monotonic', return_value=1.0):
            result = probe.scan_existing_slot_displacements(ProgramWithTwoBlocks(), 0x170, out.append, 2.0)
        self.assertFalse(result)
        self.assertTrue(any('SLOT_SCAN_UNVISITED_BLOCKS count=1' in x for x in out))
        self.assertTrue(any('scan_complete=False' in x for x in out))

    def test_invalid_slot_displacement_is_rejected(self):
        from types import SimpleNamespace
        program = SimpleNamespace()
        with self.assertRaisesRegex(ValueError, 'SLOT_DISPLACEMENT'):
            probe.scan_existing_slot_displacements(program, 0x20, lambda _: None, 2.0)



class SlotWriteEvidenceTests(unittest.TestCase):
    class Instruction:
        def __init__(self, assembly):
            self.assembly = assembly
        def __str__(self):
            return self.assembly

    def test_explicit_pointer_store_at_2160(self):
        result = probe._slot_write_evidence(
            self.Instruction('MOV qword ptr [RBX + 0x2160],RAX'), 0x2160)
        self.assertEqual(result[0], 'FIELD_WRITE_QWORD')

    def test_exchange_with_memory_as_second_operand(self):
        result = probe._slot_write_evidence(
            self.Instruction('XCHG RAX,qword ptr [RBX + 0x2160]'), 0x2160)
        self.assertEqual(result[0], 'FIELD_EXCHANGE')

    def test_unrelated_field_and_stack_pointer_are_excluded(self):
        for assembly in ('MOV qword ptr [RBX + 0x170],RAX',
                         'MOV RAX,qword ptr [RBX + 0x2160]',
                         'LEA RAX,[RBX + 0x2160]',
                         'CMP qword ptr [RBX + 0x2160],0x0'):
            with self.subTest(assembly=assembly):
                self.assertIsNone(probe._slot_write_evidence(
                    self.Instruction(assembly), 0x2160))


class SlotTransferEvidenceTests(unittest.TestCase):
    class Instruction:
        def __init__(self, address, assembly):
            self.address, self.assembly = address, assembly
        def getAddress(self):
            return self.address
        def __str__(self):
            return self.assembly

    def setup_listing(self, instructions, end=None):
        from types import SimpleNamespace
        items = {obj.getAddress(): obj for obj in instructions}
        ordered = sorted(items)
        listing = SimpleNamespace(getInstructionAfter=lambda address:
                                  items[ordered[ordered.index(address)+1]]
                                  if address in items and ordered.index(address)+1 < len(ordered)
                                  else None)
        limit = end if end is not None else ordered[-1] + 1
        fn = SimpleNamespace(getBody=lambda: SimpleNamespace(contains=lambda address:
                                                              ordered[0] <= address < limit))
        functions = SimpleNamespace(getFunctionContaining=lambda address: fn)
        return listing, functions

    def test_direct_call_through_displacement_is_candidate(self):
        insn = self.Instruction(0x1000, 'CALL qword ptr [RCX + 0x170]')
        listing, functions = self.setup_listing([insn])
        self.assertEqual(probe._slot_transfer_evidence(insn, listing, functions, 0x170)[0],
                         'DIRECT_MEMORY_TRANSFER')

    def test_qword_load_followed_by_indirect_register_call_is_candidate(self):
        first = self.Instruction(0x1000, 'MOV RAX,qword ptr [RBX + 0x170]')
        middle = self.Instruction(0x1005, 'MOV R8,R9')
        call = self.Instruction(0x1008, 'CALL RAX')
        listing, functions = self.setup_listing([first, middle, call])
        evidence = probe._slot_transfer_evidence(first, listing, functions, 0x170)
        self.assertEqual(evidence[0], 'REGISTER_TRANSFER_NEARBY')
        self.assertIn('2 instructions later', evidence[1])

    def test_qword_load_followed_by_guard_dispatch_is_candidate(self):
        first = self.Instruction(0x1000, 'MOV RAX,qword ptr [RBX + 0x170]')
        call = self.Instruction(0x1005, 'JMP qword ptr [PTR__guard_dispatch_icall]')
        listing, functions = self.setup_listing([first, call])
        self.assertEqual(probe._slot_transfer_evidence(first, listing, functions, 0x170)[0],
                         'GUARD_TRANSFER_NEARBY')

    def test_nonpointer_access_and_unrelated_call_are_rejected(self):
        first = self.Instruction(0x1000, 'MOV EAX,dword ptr [RBX + 0x170]')
        second = self.Instruction(0x1005, 'CALL RAX')
        listing, functions = self.setup_listing([first, second])
        self.assertIsNone(probe._slot_transfer_evidence(first, listing, functions, 0x170))
        self.assertIsNone(probe._slot_transfer_evidence(
            self.Instruction(0x1000, 'MOV RAX,qword ptr [RBX + 0x170]'),
            self.setup_listing([self.Instruction(0x1000, 'MOV RAX,qword ptr [RBX + 0x170]'),
                                self.Instruction(0x1005, 'CALL RCX')])[0],
            functions, 0x170))

    def test_nearby_call_from_another_function_is_not_a_candidate(self):
        first = self.Instruction(0x1000, 'MOV RAX,qword ptr [RBX + 0x170]')
        call = self.Instruction(0x1005, 'JMP RAX')
        listing, functions = self.setup_listing([first, call], end=0x1005)
        self.assertIsNone(probe._slot_transfer_evidence(first, listing, functions, 0x170))

    def test_invalid_focus_is_rejected_before_memory_scan(self):
        with self.assertRaisesRegex(ValueError, 'SLOT_SCAN_FOCUS'):
            probe.scan_existing_slot_displacements(Program(), 0x170, lambda line: None,
                                                   1.0, focus='all_and_everything')

if __name__ == '__main__':
    unittest.main()
