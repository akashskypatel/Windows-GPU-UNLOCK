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
            probe.SLOT: [0x140001000],
            probe.LOADER: [0x140001000],
        })
        functions, complete = probe.candidate_functions(program, observed.append)
        self.assertTrue(complete)
        self.assertEqual([int(f.getEntryPoint().getOffset()) for f in functions],
                         sorted([probe.LOADER, 0x1417e8e00, 0x140a00000]))
        self.assertTrue(any("LOADER_POINTER_SLOT" in line for line in observed))
        self.assertTrue(any("LOADER_ENTRY" in line for line in observed))
        self.assertFalse(any("runtime_proven" in line for line in observed))

    def test_overflow_is_reported_as_partial_and_does_not_select_extra_owners(self):
        owners = self.registration_owners()
        points = [0x140200000 + i * 16 for i in range(probe.MAX_FUNCTIONS + 4)]
        for i, point in enumerate(points):
            owners[point] = Function(0x140300000 + i * 16)
        observed = []
        program = Program(owners, {probe.SLOT: points})
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
