"""Host-only tests of the original-driver read-only callback data-flow probe.

Tests run without PyGhidra or a driver. They validate the bounded evidence
selection, missing-source behavior and original-file identity check.
"""
from __future__ import annotations
import contextlib
from io import StringIO
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nvlddmkm_61742_callback_receiver_pcode as probe


class Address:
    def __init__(self, number):
        self.number = number

    def getOffset(self):
        return self.number

    def __str__(self):
        return "0x%x" % self.number


class Function:
    def __init__(self, number):
        self.address = Address(number)

    def getEntryPoint(self):
        return self.address


class Reference:
    def __init__(self, number):
        self.source = Address(number)

    def getFromAddress(self):
        return self.source

    def getReferenceType(self):
        return "DATA"


class Functions:
    def __init__(self, owners, loader=True):
        self.owners = owners
        self.loader = loader

    def getFunctionAt(self, address):
        return Function(probe.LOADER) if self.loader and address.getOffset() == probe.LOADER else None

    def getFunctionContaining(self, address):
        return self.owners.get(address.getOffset())


class References:
    def __init__(self, sites):
        self.sites = sites

    def getReferencesTo(self, address):
        return [Reference(a) for a in self.sites.get(address.getOffset(), ())]


class Program:
    def __init__(self, owners, refs=None, loader=True):
        self.functions = Functions(owners, loader)
        self.refs = References(refs or {})

    def getAddressFactory(self):
        return self

    def getDefaultAddressSpace(self):
        return self

    def getAddress(self, number):
        return Address(number)

    def getFunctionManager(self):
        return self.functions

    def getReferenceManager(self):
        return self.refs


class Node:
    def __init__(self, name, constant=None, definition=None):
        self.name = name
        self.constant = constant
        self.definition = definition

    def __str__(self):
        return self.name

    def isConstant(self):
        return self.constant is not None

    def getOffset(self):
        return self.constant

    def getDef(self):
        return self.definition


class Definition:
    def __init__(self, inputs):
        self.inputs = inputs

    def getNumInputs(self):
        return len(self.inputs)

    def getInput(self, index):
        return self.inputs[index]

    def getMnemonic(self):
        return "INT_ADD"


class CallbackDataflowTests(unittest.TestCase):
    def registration_owners(self):
        owner = Function(0x1417e8e00)
        return {point: owner for point in probe.REGISTRATION_SITES}

    def test_bounded_callback_owner_selection_has_real_addresses(self):
        owners = self.registration_owners()
        owners[0x140001000] = Function(0x140a00000)
        observed = []
        program = Program(owners, {
            probe.FUNCTION_RECORD: [0x140001000],
            probe.LOADER: [0x140001000],
        })
        functions, complete = probe.candidate_functions(program, observed.append)
        self.assertTrue(complete)
        self.assertEqual([int(f.getEntryPoint().getOffset()) for f in functions],
                         sorted([probe.LOADER, 0x1417e8e00, 0x140a00000]))
        self.assertTrue(any("FUNCTION_RECORD_CANDIDATE" in line for line in observed))
        self.assertTrue(any("LOADER_ENTRY" in line for line in observed))
        self.assertFalse(any("runtime_proven" in line for line in observed))

    def test_overflow_is_reported_as_partial_and_does_not_select_extra_owners(self):
        owners = self.registration_owners()
        points = [0x140200000 + i * 16 for i in range(probe.MAX_FUNCTIONS + 4)]
        for i, point in enumerate(points):
            owners[point] = Function(0x140300000 + i * 16)
        observed = []
        program = Program(owners, {probe.FUNCTION_RECORD: points})
        functions, complete = probe.candidate_functions(program, observed.append)
        self.assertFalse(complete)
        self.assertEqual(len(functions), probe.MAX_FUNCTIONS)
        self.assertTrue(any("FUNCTION_LIMIT_OMISSION" in line for line in observed))

    def test_missing_loader_or_registration_cannot_be_complete(self):
        program = Program(self.registration_owners(), loader=False)
        self.assertEqual(probe.candidate_functions(program, lambda _: None),
                         (None, False))
        program = Program({probe.REGISTRATION_SITES[0]: Function(0x1417e8e00)})
        self.assertEqual(probe.candidate_functions(program, lambda _: None),
                         (None, False))

    def test_definition_trace_is_bounded_and_reports_exact_constants(self):
        constant = Node("field", 0x170)
        child = Node("base", definition=Definition([constant]))
        root = Node("sum", definition=Definition([child]))
        self.assertIn("[const=0x170]", probe.fmt_node(root, depth=3))
        self.assertNotIn("[const=0x170]", probe.fmt_node(root, depth=1))
        self.assertEqual(probe.fmt_node(None), "NULL")

    def test_function_metadata_is_three_rvas_not_a_64_bit_pointer(self):
        record = probe.decode_runtime_function_record(
            (0x00bf3880, 0x00bf3e60, 0x00c00000),
            probe.EXPECTED_BASE, probe.LOADER)
        self.assertTrue(record["candidate"])
        self.assertEqual(record["begin"], 0x140bf3880)
        self.assertEqual(record["end"], 0x140bf3e60)
        self.assertEqual(record["unwind"], 0x140c00000)
        for words in ((0x00bf3880, 0x00bf3880, 0x00c00000),
                      (0x00bf3880, 0x00bf3e60, 0),
                      (0x00bf3881, 0x00bf3e60, 0x00c00000)):
            with self.subTest(words=words):
                self.assertFalse(probe.decode_runtime_function_record(
                    words, probe.EXPECTED_BASE, probe.LOADER)["candidate"])
        for invalid in ((0x00bf3880, 0x00bf3e60), (-1, 7, 1),
                        (0x100000000, 7, 1)):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    probe.decode_runtime_function_record(
                        invalid, probe.EXPECTED_BASE, probe.LOADER)

    def test_12_byte_record_is_checked_and_reported_without_pointer_claim(self):
        class Block:
            def isInitialized(self):
                return True
            def isExecute(self):
                return True
            def getName(self):
                return ".pdata"
        class Memory:
            def __init__(self, words):
                self.words = words
            def getBlock(self, address):
                return Block()
            def getInt(self, address):
                return self.words[address.getOffset()]
        class ProgramWithMemory:
            def __init__(self, words):
                self.memory = Memory(words)
            def getMemory(self):
                return self.memory
            def getAddressFactory(self):
                return self
            def getDefaultAddressSpace(self):
                return self
            def getAddress(self, value):
                return Address(value)
        words = {probe.FUNCTION_RECORD: 0x00bf3880,
                 probe.FUNCTION_RECORD + 4: 0x00bf3e60,
                 probe.FUNCTION_RECORD + 8: 0x00c00000}
        messages = []
        self.assertTrue(probe.inspect_function_record(
            ProgramWithMemory(words), messages.append))
        self.assertIn("pointer_slot=FALSE", messages[0])
        self.assertIn("end_exclusive_va=0x140bf3e60", messages[0])
        self.assertIn("section=.pdata", messages[0])
        messages.clear()
        self.assertFalse(probe.inspect_function_record(
            ProgramWithMemory({probe.FUNCTION_RECORD: 0x00bf3880}),
            messages.append))
        self.assertIn("FUNCTION_RECORD_READ_ERROR", messages[0])

    def test_focused_pcode_reports_store_without_claiming_an_invocation(self):
        class Pcode:
            def getMnemonic(self):
                return "STORE"
            def getOutput(self):
                return None
            def getNumInputs(self):
                return 3
            def getInput(self, index):
                return (Node("memspace", 0x1b1),
                        Node("address", definition=Definition([Node("field", 0x170)])),
                        Node("callback", definition=Definition([Node("loader")])))[index]
        line = probe.format_focused_op(Function(0x1417e8550), Pcode(),
                                       Address(0x1417e8e45))
        self.assertIn("op=STORE", line)
        self.assertIn("const=0x170", line)
        self.assertIn("callback_invoke_not_proven=TRUE", line)
        self.assertEqual(probe.MAX_FOCUSED_OPS_PER_SITE, 16)

    def test_initializer_inbound_keeps_call_refs_not_address_taken_data(self):
        class CallType:
            def __init__(self, is_call):
                self.called = is_call
            def isCall(self):
                return self.called
            def __str__(self):
                return "CALL" if self.called else "DATA"
        class TypedRef:
            def __init__(self, source, is_call):
                self.source = Address(source)
                self.kind = CallType(is_call)
            def getFromAddress(self):
                return self.source
            def getReferenceType(self):
                return self.kind
        class TypedReferences:
            def getReferencesTo(self, addr):
                return [TypedRef(0x140100000, False),
                        TypedRef(0x140100010, True),
                        TypedRef(0x140100010, True),
                        TypedRef(0x140100020, True)]
        owner = Function(0x1400ffff0)
        program = Program({0x140100000: owner, 0x140100010: owner,
                           0x140100020: owner})
        program.functions.getFunctionAt = lambda address: Function(probe.INITIALIZER)
        program.refs = TypedReferences()
        found = []
        calls, complete = probe.select_initializer_callers(program, found.append)
        self.assertTrue(complete)
        self.assertEqual([addr.getOffset() for _, addr in calls],
                         [0x140100010, 0x140100020])
        self.assertTrue(any("direct_call=False" in line for line in found))
        self.assertTrue(any("explicit_calls=2" in line for line in found))

    def test_missing_initializer_and_callsite_overflow_fail_closed(self):
        class CallType:
            def isCall(self):
                return True
            def __str__(self):
                return "CALL"
        class Ref:
            def __init__(self, at):
                self.at = Address(at)
            def getFromAddress(self):
                return self.at
            def getReferenceType(self):
                return CallType()
        class ManyReferences:
            def getReferencesTo(self, addr):
                return [Ref(0x140300000 + i * 8)
                        for i in range(probe.MAX_INITIALIZER_CALLSITES + 4)]
        missing = Program({})
        missing.functions.getFunctionAt = lambda address: None
        found, complete = probe.select_initializer_callers(missing, lambda _: None)
        self.assertFalse(complete)
        self.assertEqual(found, [])
        points = [0x140300000 + i * 8
                  for i in range(probe.MAX_INITIALIZER_CALLSITES + 4)]
        source = Program({point: Function(0x140200000) for point in points})
        source.functions.getFunctionAt = lambda address: Function(probe.INITIALIZER)
        source.refs = ManyReferences()
        messages = []
        found, complete = probe.select_initializer_callers(source, messages.append)
        self.assertFalse(complete)
        self.assertEqual(len(found), probe.MAX_INITIALIZER_CALLSITES)
        self.assertIn("INITIALIZER_CALLSITE_TRUNCATED",
                      "\n".join(messages))

    def test_constructor_caller_only_selects_real_direct_calls(self):
        class Type:
            def __init__(self, call):
                self.call = call
            def isCall(self):
                return self.call
            def __str__(self):
                return "UNCONDITIONAL_CALL" if self.call else "DATA"
        class Ref:
            def __init__(self, address, call):
                self.address, self.kind = Address(address), Type(call)
            def getFromAddress(self):
                return self.address
            def getReferenceType(self):
                return self.kind
        class Refs:
            def getReferencesTo(self, address):
                self_address = address.getOffset()
                self_test = probe.CONSTRUCTOR
                if self_address != self_test:
                    return []
                return [Ref(0x140050000, False), Ref(0x140050008, True),
                        Ref(0x140050008, True), Ref(0x140050010, True)]
        owner = Function(0x14004f000)
        program = Program({0x140050000: owner, 0x140050008: owner,
                           0x140050010: owner})
        program.functions.getFunctionAt = lambda address: (
            Function(probe.CONSTRUCTOR) if address.getOffset() == probe.CONSTRUCTOR
            else None)
        program.refs = Refs()
        records = []
        calls, complete = probe.select_initializer_callers(
            program, records.append, target=probe.CONSTRUCTOR, label="CONSTRUCTOR",
            max_inbound=probe.MAX_CONSTRUCTOR_INBOUND,
            max_callsites=probe.MAX_CONSTRUCTOR_CALLSITES)
        self.assertTrue(complete)
        self.assertEqual([site.getOffset() for _, site in calls],
                         [0x140050008, 0x140050010])
        self.assertIn("CONSTRUCTOR_INBOUND", "\n".join(records))
        self.assertIn("explicit_calls=2", "\n".join(records))
        self.assertFalse(any("INITIALIZER_INBOUND" in record for record in records))

    def test_constructor_call_limit_marks_incomplete(self):
        class RefType:
            def isCall(self):
                return True
            def __str__(self):
                return "CALL"
        class Ref:
            def __init__(self, addr):
                self.addr = Address(addr)
            def getFromAddress(self):
                return self.addr
            def getReferenceType(self):
                return RefType()
        class Refs:
            def getReferencesTo(self, addr):
                return [Ref(0x140500000 + i * 8) for i in range(8)]
        source = {0x140500000 + i*8: Function(0x140600000)
                  for i in range(8)}
        program = Program(source)
        program.functions.getFunctionAt = lambda address: Function(probe.CONSTRUCTOR)
        program.refs = Refs()
        output = []
        calls, complete = probe.select_initializer_callers(
            program, output.append, target=probe.CONSTRUCTOR, label="CONSTRUCTOR",
            max_inbound=32, max_callsites=3)
        self.assertFalse(complete)
        self.assertEqual(len(calls), 3)
        self.assertIn("CONSTRUCTOR_CALLSITE_TRUNCATED", "\n".join(output))

    def test_constructor_linear_window_never_crosses_function_boundary(self):
        class Insn:
            def __init__(self, offset):
                self.address = Address(offset)
            def getAddress(self):
                return self.address
            def __str__(self):
                return "MOV RAX,RBX"
        class Listing:
            def __init__(self, addresses):
                self.entries = {addr: Insn(addr) for addr in addresses}
                self.all = addresses
            def getInstructionContaining(self, addr):
                return self.entries.get(addr.getOffset())
            def getInstructionAfter(self, addr):
                at = self.all.index(addr.getOffset())
                return (self.entries[self.all[at+1]] if at+1 < len(self.all)
                        else None)
        class Body:
            def contains(self, addr):
                return addr.getOffset() < 0x140070018
        class Caller(Function):
            def getBody(self):
                return Body()
        class ProgramWithListing:
            def __init__(self, addresses):
                self.listing = Listing(addresses)
            def getListing(self):
                return self.listing
        owner = Caller(0x140070000)
        program = ProgramWithListing([0x140070000, 0x140070008,
                                      0x140070010, 0x140070018])
        output = []
        actual = probe.bounded_constructor_following(
            program, owner, Address(0x140070008), output.append)
        self.assertEqual(actual, {0x140070008, 0x140070010})
        self.assertTrue(any("not_control_flow_proof=TRUE" in line
                            for line in output))
        self.assertFalse(any("address=0x140070018" in line for line in output))
        output.clear()
        missing = probe.bounded_constructor_following(
            program, owner, Address(0x140070009), output.append)
        self.assertIsNone(missing)
        self.assertIn("CONSTRUCTOR_CALLSITE_UNAVAILABLE", output[0])

    def test_original_driver_md5_rejects_lookalikes_without_output_file(self):
        class WrongDriver:
            def getExecutableMD5(self):
                return "0" * 32

            def getImageBase(self):
                return Address(probe.EXPECTED_BASE)
        previous = getattr(probe, "currentProgram", None)
        try:
            probe.currentProgram = WrongDriver()
            captured = StringIO()
            with contextlib.redirect_stdout(captured):
                result = probe.main()
            self.assertEqual(result, "ERROR")
            self.assertIn("driver mismatch", captured.getvalue())
            self.assertIn("STATUS=ERROR REPORT=<not-created>", captured.getvalue())
        finally:
            if previous is None:
                del probe.currentProgram
            else:
                probe.currentProgram = previous


if __name__ == "__main__":
    unittest.main()
