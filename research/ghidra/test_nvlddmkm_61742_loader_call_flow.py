"""Host tests of loader call-site predicate and constrained p-code def-use."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('flow', Path(__file__).with_name('nvlddmkm_61742_loader_call_flow.py'))
flow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flow)

class Node:
    def __init__(self, op=None, const=None):
        self.op, self.const = op, const
    def getDef(self):
        return self.op
    def isConstant(self):
        return self.const is not None
    def getOffset(self):
        return self.const

class Op:
    def __init__(self, name, *inputs):
        self.name, self.inputs = name, inputs
    def getMnemonic(self):
        return self.name
    def getNumInputs(self):
        return len(self.inputs)
    def getInput(self, i):
        return self.inputs[i]

def n(name, *args):
    return Node(Op(name, *args))

def field(base, offset):
    return n('LOAD', Node(const=0), n('INT_ADD', base, Node(const=offset)))

class EvidenceTests(unittest.TestCase):
    def test_read_seed_and_writer_are_separate(self):
        self.assertTrue(flow.read_candidate('MOV RAX,qword ptr [RCX + 0x170]'))
        self.assertTrue(flow.read_candidate('CALL qword ptr [R9 + 0x170]'))
        self.assertFalse(flow.read_candidate('MOV qword ptr [R9 + 0x170],RAX'))
        self.assertFalse(flow.read_candidate('ADD EAX,0x170'))
        self.assertFalse(flow.read_candidate('MOV RAX,qword ptr [RCX + 0x171]'))

    def test_direct_nested_from_owner_chain(self):
        owner = Node()
        nested = field(owner, 0x108)
        target = field(nested, 0x170)
        self.assertEqual(flow.classify_call_input(target), (True, True))

    def test_outer_slot_alone_cannot_prove_method(self):
        self.assertEqual(flow.classify_call_input(field(Node(), 0x108)), (False, False))
        self.assertEqual(flow.classify_call_input(field(Node(), 0x170)), (True, False))

    def test_independent_fields_not_chain(self):
        owner = field(Node(), 0x108)
        unrelated = field(Node(), 0x170)
        wrapped = n('MULTIEQUAL', unrelated, owner)
        self.assertEqual(flow.classify_call_input(wrapped), (True, False))

    def test_cast_and_phi_on_same_chain(self):
        nested = n('CAST', field(Node(), 0x108))
        target = n('MULTIEQUAL', n('COPY', field(nested, 0x170)), Node())
        self.assertEqual(flow.classify_call_input(target), (True, True))

    def test_non_memory_constant_not_promoted(self):
        self.assertEqual(flow.classify_call_input(n('INT_ADD', Node(), Node(const=0x170))), (False, False))

    def test_ptradd_stride_and_false_stride(self):
        nested = field(Node(), 0x108)
        good = n('LOAD', Node(const=0), n('PTRADD', nested, Node(const=0x2e), Node(const=8)))
        bad = n('LOAD', Node(const=0), n('PTRADD', nested, Node(const=0x2e), Node(const=4)))
        self.assertEqual(flow.classify_call_input(good), (True, True))
        self.assertEqual(flow.classify_call_input(bad), (False, False))

    def test_cycle_is_bounded(self):
        op = Op('COPY', None)
        cycled = Node(op)
        op.inputs = (cycled,)
        self.assertEqual(flow.classify_call_input(cycled), (False, False))

if __name__ == '__main__':
    unittest.main()

# Additional independent checks of the original-run failure path and the
# completed-graph candidate contract. The original Ghidra runtime is not mocked
# as a proof of physical execution; only tool inputs/outputs are verified here.
import json
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch


def graph_fixture(site='0x140bf3bca'):
    return {
        'schema': flow.GRAPH_SCHEMA, 'status': 'COMPLETE', 'omissions': [],
        'roots': sorted(flow.GRAPH_ROOTS),
        'nodes': [
            {'id': 'f_140bf3880', 'kind': 'FUNCTION', 'entry': '0x140bf3880'},
            {'id': 'f_14179e530', 'kind': 'FUNCTION', 'entry': '0x14179e530'},
            {'id': 'f_140aece90', 'kind': 'FUNCTION', 'entry': '0x140aece90'},
            {'id': 'i_' + site[2:], 'kind': 'INDIRECT'},
        ],
        'edges': [{
            'kind': 'INDIRECT_UNKNOWN', 'source': 'f_140bf3880',
            'target': 'i_' + site[2:], 'site': site,
        }],
    }


class GraphInputTests(unittest.TestCase):
    def test_valid_completed_original_root_graph(self):
        self.assertEqual(flow.validate_graph(graph_fixture()), {0x140bf3bca: 0x140bf3880})

    def test_partial_or_unrelated_reference_graph_is_not_accepted(self):
        g = graph_fixture()
        g['status'] = 'PARTIAL'
        self.assertRaises(ValueError, flow.validate_graph, g)
        g['status'] = 'COMPLETE'
        g['roots'] = ['0x140bf3880']
        self.assertRaises(ValueError, flow.validate_graph, g)
        g['roots'] = sorted(flow.GRAPH_ROOTS)
        g['omissions'] = ['TIME_BUDGET']
        self.assertRaises(ValueError, flow.validate_graph, g)

    def test_graph_missing_or_malformed_indirect_edge_fails_closed(self):
        g = graph_fixture()
        g['nodes'].pop()
        self.assertRaises(ValueError, flow.validate_graph, g)
        g = graph_fixture()
        g['edges'][0]['site'] = '0x170'
        self.assertRaises(ValueError, flow.validate_graph, g)
        g = graph_fixture()
        g['edges'][0]['kind'] = 'DATA_REF'
        self.assertRaises(ValueError, flow.validate_graph, g)

    def test_duplicate_node_id_and_excess_calls_rejected(self):
        g = graph_fixture()
        g['nodes'].append(g['nodes'][0])
        self.assertRaises(ValueError, flow.validate_graph, g)
        g = graph_fixture()
        # Distinct indirect sites with an existing node for each.
        for i in range(flow.MAX_GRAPH_CALL_SITES):
            address = '0x%x' % (0x140bf3bcb + i)
            g['nodes'].append({'id': 'i_' + address[2:], 'kind': 'INDIRECT'})
            g['edges'].append({'kind': 'INDIRECT_UNKNOWN',
                               'source': 'f_140bf3880', 'target': 'i_' + address[2:],
                               'site': address})
        self.assertRaises(ValueError, flow.validate_graph, g)

    def test_completed_graph_checks_existing_instruction_and_owner(self):
        class Address(int):
            def getOffset(self):
                return int(self)

        class Instruction:
            def __init__(self, op):
                self.op = op
            def getMnemonicString(self):
                return self.op
            def __str__(self):
                return self.op + ' qword ptr [RAX + 0x170]'

        def make_program(op):
            space = SimpleNamespace(getAddress=lambda v: Address(v))
            factory = SimpleNamespace(getDefaultAddressSpace=lambda: space)
            listing = SimpleNamespace(getInstructionAt=lambda a: Instruction(op))
            owner = SimpleNamespace(getEntryPoint=lambda: Address(0x140bf3880))
            manager = SimpleNamespace(getFunctionContaining=lambda a: owner)
            return SimpleNamespace(getAddressFactory=lambda: factory,
                                   getListing=lambda: listing,
                                   getFunctionManager=lambda: manager)

        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path
            path = Path(tmp) / 'graph.json'
            path.write_text(json.dumps(graph_fixture()), encoding='utf-8')
            logged = []
            found = flow.graph_function_candidates(make_program('CALL'), path, logged.append)
            self.assertEqual(list(found.keys()), [0x140bf3880])
            self.assertEqual(found[0x140bf3880][0][0], 0x140bf3bca)
            self.assertTrue(any('GRAPH_INPUT' in row and 'sha256=' in row for row in logged))
            self.assertRaises(ValueError, flow.graph_function_candidates,
                              make_program('MOV'), path, lambda _: None)
            # A different current owner must not inherit the graph source edge.
            unrelated_program = make_program('CALL')
            foreign = SimpleNamespace(getEntryPoint=lambda: Address(0x140bf3890))
            unrelated_program.getFunctionManager().getFunctionContaining = lambda _: foreign
            self.assertRaises(ValueError, flow.graph_function_candidates,
                              unrelated_program, path, lambda _: None)

    def test_graph_missing_or_oversized_not_silently_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path
            p = Path(tmp) / 'graph.json'
            self.assertRaises(FileNotFoundError, flow.graph_function_candidates,
                              None, p, lambda _: None)
            p.write_bytes(b'X' * (flow.MAX_GRAPH_BYTES + 1))
            self.assertRaises(ValueError, flow.graph_function_candidates,
                              None, p, lambda _: None)


class MemoryConversionTests(unittest.TestCase):
    def test_java_array_bulk_buffer_not_iterated_per_byte(self):
        class Buffer(bytearray):
            def __iter__(self):
                raise AssertionError('slow per-element bridge is forbidden on fast path')

        class Memory:
            def getBytes(self, addr, output):
                output[:] = b'\x00\x80\xff\x11'
                return len(output)

        jpype = SimpleNamespace(JArray=lambda _: lambda size: Buffer(size), JByte=object())
        with patch.dict(sys.modules, {'jpype': jpype}):
            self.assertEqual(flow._memory_bytes(Memory(), 123, 4), b'\x00\x80\xff\x11')

    def test_short_memory_read_is_rejected(self):
        class Memory:
            def getBytes(self, addr, output):
                return len(output) - 1

        jpype = SimpleNamespace(JArray=lambda _: lambda size: bytearray(size), JByte=object())
        with patch.dict(sys.modules, {'jpype': jpype}):
            self.assertRaises(ValueError, flow._memory_bytes, Memory(), 1, 4)
