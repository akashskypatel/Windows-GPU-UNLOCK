"""Independent machine-code path-scope tests for the original x64 CFG target probe."""
from pathlib import Path
import importlib.util
import unittest

spec = importlib.util.spec_from_file_location('loader_call_flow', Path(__file__).with_name('nvlddmkm_61742_loader_call_flow.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

class Address(int):
    def getOffset(self):
        return int(self)
    def getAddressSpace(self):
        return 'register'

class Output:
    def __init__(self, offset=0, size=8, space='register'):
        self.address, self.size, self.space = Address(offset), size, space
    def getAddress(self):
        if self.space == 'register':
            return self.address
        return type('NonRegAddress', (), {'getAddressSpace': lambda s: 'unique', 'getOffset': lambda s: 0})()
    def getSize(self):
        return self.size

class Op:
    def __init__(self, output):
        self.output = output
    def getOutput(self):
        return self.output

class Register:
    def getAddress(self):
        return Address(0)
    def getMinimumByteSize(self):
        return 8

class Instruction:
    def __init__(self, addr, text, output=None, failure=False):
        self.address, self.text, self.output, self.failure = Address(addr), text, output, failure
    def getAddress(self):
        return self.address
    def __str__(self):
        return self.text
    def getPcode(self):
        if self.failure:
            raise RuntimeError('unavailable raw p-code')
        return [] if self.output is None else [Op(self.output)]

class Listing:
    def __init__(self, instructions):
        self.instructions = {i.getAddress(): i for i in instructions}
        self.keys = sorted(self.instructions)
    def getInstructionAt(self, addr):
        return self.instructions.get(addr)
    def getInstructionBefore(self, addr):
        lower = [x for x in self.keys if x < addr]
        return self.instructions[max(lower)] if lower else None

class Program:
    def __init__(self, instructions, register=True):
        self.listing = Listing(instructions)
        self.register = Register() if register else None
    def getListing(self):
        return self.listing
    def getRegister(self, name):
        return self.register if name == 'RAX' else None

class Function:
    def __init__(self, allowed):
        self.allowed = set(allowed)
    def getBody(self):
        return self
    def contains(self, address):
        return address in self.allowed

class GuardRaxTests(unittest.TestCase):
    def setUp(self):
        self.old_address = getattr(probe, '_address', None)
        probe._address = lambda program, site: Address(site)
    def tearDown(self):
        if self.old_address is None:
            delattr(probe, '_address')
        else:
            probe._address = self.old_address

    def test_full_width_guard_target_and_label_are_evidence_only(self):
        p = Program([Instruction(100, 'MOV RAX,qword ptr [RCX + 0x170]', Output()),
                     Instruction(106, 'CALL qword ptr [0x140e02aa8]')])
        log = []
        self.assertTrue(probe.inspect_guard_rax_window(p, Function([100, 106]), 106, log.append))
        self.assertTrue(any('kinds=FULL_RAX' in x and 'explicit_0x170_read=True' in x for x in log))
        self.assertTrue(any('no_runtime_or_path_proof=TRUE' in x for x in log))

    def test_partial_eax_write_is_not_full_pointer(self):
        p = Program([Instruction(100, 'MOV EAX,1', Output(size=4)),
                     Instruction(106, 'CALL qword ptr [0x140e02aa8]')])
        log = []
        self.assertTrue(probe.inspect_guard_rax_window(p, Function([100, 106]), 106, log.append))
        self.assertTrue(any('kinds=PARTIAL_RAX' in x for x in log))
        self.assertFalse(any('kinds=FULL_RAX' in x for x in log))

    def test_unrelated_register_does_not_qualify(self):
        p = Program([Instruction(100, 'MOV RDX,2', Output(space='unique')),
                     Instruction(106, 'CALL qword ptr [0x140e02aa8]')])
        log = []
        self.assertTrue(probe.inspect_guard_rax_window(p, Function([100, 106]), 106, log.append))
        self.assertTrue(any('writers=0' in x for x in log))

    def test_foreign_function_is_not_sliced(self):
        p = Program([Instruction(100, 'MOV RAX,qword ptr [RCX + 0x170]', Output()),
                     Instruction(106, 'CALL qword ptr [0x140e02aa8]')])
        log = []
        self.assertTrue(probe.inspect_guard_rax_window(p, Function([106]), 106, log.append))
        self.assertTrue(any('preceding=0' in x for x in log))
        self.assertFalse(any('GUARD_BEFORE ' in x for x in log))

    def test_store_is_not_rax_producer(self):
        p = Program([Instruction(100, 'MOV qword ptr [R9 + 0x170],RAX'),
                     Instruction(106, 'JMP qword ptr [0x140e02aa8]')])
        log = []
        self.assertTrue(probe.inspect_guard_rax_window(p, Function([100,106]), 106, log.append))
        self.assertTrue(any('explicit_0x170_reads=0' in x for x in log))

    def test_unrelated_call_is_skipped(self):
        p = Program([Instruction(100, 'MOV RAX,qword ptr [RCX + 0x170]', Output()),
                     Instruction(106, 'CALL qword ptr [0x140e02aa0]')])
        log = []
        self.assertTrue(probe.inspect_guard_rax_window(p, Function([100,106]), 106, log.append))
        self.assertTrue(any('GUARD_RAX_SKIPPED' in x for x in log))

    def test_missing_code_or_register_fails_closed(self):
        p = Program([Instruction(106, 'CALL qword ptr [0x140e02aa8]')], register=False)
        log=[]
        self.assertFalse(probe.inspect_guard_rax_window(p, Function([106]), 106, log.append))
        self.assertTrue(any('UNAVAILABLE' in x for x in log))
        self.assertFalse(probe.inspect_guard_rax_window(p, Function([106]), 104, log.append))

    def test_pcode_failure_reports_incomplete(self):
        p=Program([Instruction(100, 'MOV RAX,1', failure=True), Instruction(106, 'CALL qword ptr [0x140e02aa8]')])
        log=[]
        self.assertFalse(probe.inspect_guard_rax_window(p, Function([100,106]), 106, log.append))
        self.assertTrue(any('GUARD_RAX_PCODE_UNAVAILABLE' in x for x in log))

    def test_limits_refuse_unbounded_window(self):
        p=Program([])
        for v in (0, -1, probe.MAX_GUARD_PRECEDING+1, True):
            self.assertRaises(ValueError, probe.inspect_guard_rax_window,
                              p, Function([]), 106, lambda _: None, v)

if __name__ == '__main__':
    unittest.main()