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