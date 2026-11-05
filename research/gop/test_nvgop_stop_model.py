"""Evidence-oriented tests of the host-only teardown model's stated assumptions."""
import unittest
from unittest.mock import patch
from pathlib import Path
import tempfile

from nvgop_stop_model import FAULTS, FIRMWARE, State, build_report, model_parent_stop, verify_images


class ParentStopModelTests(unittest.TestCase):
    def test_diags_starts_with_non_null_objects_and_null_optional_allocation(self):
        state = State()
        self.assertTrue(all((state.device_alive, state.adapter_alive, state.embedded_alive,
                             state.auxiliary_alive, state.factory_alive, state.context_alive)))
        self.assertFalse(state.optional_allocation_alive)

    def test_normal_path_does_not_claim_recovery(self):
        case = model_parent_stop()
        state = case["state"]
        self.assertFalse(state["private_protocol_installed"])
        self.assertFalse(state["pci_by_driver_open"])
        self.assertFalse(state["context_alive"])
        for field in ("device_alive", "adapter_alive", "embedded_alive", "auxiliary_alive", "factory_alive"):
            self.assertFalse(state[field], field)
        self.assertEqual(case["recovery"], "RECOVERY_UNPROVEN")
        self.assertEqual(case["restart_pci_open_prediction"], "NOT_DETERMINED")
        self.assertEqual(state["context_references"]["auxiliary"], "dangling")
        self.assertEqual(case["helper_result"], "RETURNED_STATUS_UNDETERMINED")
        stages = [entry["stage"] for entry in case["trace"]]
        self.assertLess(stages.index("private_uninstall_protocol"), stages.index("device_destructor"))
        self.assertLess(stages.index("device_destructor"), stages.index("pci_close_protocol"))
        self.assertLess(stages.index("pci_close_protocol"), stages.index("free_context"))
        self.assertIn("EMBEDDED_BAR0_6104E0_RMW_AND_610630_POLL_POSSIBLE", case["hardware_paths"])
        self.assertNotIn("OUTPUT_MASK_BAR0_WRITE_POSSIBLE", case["hardware_paths"])

    def test_private_protocol_open_failure_exits_without_cleanup(self):
        case = model_parent_stop(fault="private_open_error")
        self.assertTrue(case["state"]["private_protocol_installed"])
        self.assertTrue(case["state"]["pci_by_driver_open"])
        self.assertTrue(case["state"]["context_alive"])
        self.assertTrue(case["state"]["device_alive"])
        self.assertEqual([e["stage"] for e in case["trace"]], ["private_open_protocol"])
        self.assertFalse(case["hardware_paths"])

    def test_uninstall_failure_short_circuits_before_destructors_and_close(self):
        case = model_parent_stop(fault="private_uninstall_error")
        self.assertTrue(case["state"]["private_protocol_installed"])
        self.assertTrue(case["state"]["pci_by_driver_open"])
        self.assertTrue(case["state"]["device_alive"])
        self.assertFalse(case["hardware_paths"])
        self.assertEqual([e["stage"] for e in case["trace"]][-1], "private_uninstall_protocol")

    def test_reset_flag_adds_callback_but_not_destructor_guard(self):
        case = model_parent_stop(reset_flag=1, fault="private_uninstall_error")
        self.assertIn("OUTPUT_MASK_BAR0_WRITE_POSSIBLE", case["hardware_paths"])
        self.assertNotIn("EMBEDDED_BAR0_6104E0_RMW_AND_610630_POLL_POSSIBLE", case["hardware_paths"])
        self.assertTrue(case["state"]["private_protocol_installed"])
        normal = model_parent_stop(reset_flag=1)
        self.assertIn("EMBEDDED_BAR0_6104E0_RMW_AND_610630_POLL_POSSIBLE", normal["hardware_paths"])
        self.assertFalse(normal["state"]["context_alive"])

    def test_interrupt_before_destructor_does_not_fabricate_mmio(self):
        case = model_parent_stop(fault="before_device_destructor_interrupt")
        self.assertEqual(case["helper_result"], "INTERRUPTED_NOT_EFI_STATUS")
        self.assertFalse(case["state"]["private_protocol_installed"])
        self.assertTrue(case["state"]["device_alive"])
        self.assertTrue(case["state"]["pci_by_driver_open"])
        self.assertFalse(case["hardware_paths"])
        self.assertNotIn("pci_close_protocol", [e["stage"] for e in case["trace"]])

    def test_embedded_cleanup_can_interrupt_with_uncertain_hardware_state(self):
        case = model_parent_stop(fault="during_embedded_cleanup_interrupt")
        self.assertEqual(case["helper_result"], "INTERRUPTED_NOT_EFI_STATUS")
        self.assertTrue(case["state"]["device_alive"])
        self.assertTrue(case["state"]["embedded_alive"])
        self.assertFalse(case["state"]["private_protocol_installed"])
        self.assertTrue(case["state"]["pci_by_driver_open"])
        self.assertIn("EMBEDDED_BAR0_6104E0_RMW_AND_610630_POLL_POSSIBLE", case["hardware_paths"])
        self.assertEqual(case["trace"][-1]["result"], "INTERRUPTED_UNKNOWN_PARTIAL_HARDWARE_STATE")

    def test_auxiliary_and_factory_interruptions_have_distinct_partial_states(self):
        aux = model_parent_stop(fault="before_auxiliary_destructor_interrupt")
        factory = model_parent_stop(fault="before_factory_destructor_interrupt")
        self.assertFalse(aux["state"]["device_alive"])
        self.assertTrue(aux["state"]["auxiliary_alive"])
        self.assertTrue(aux["state"]["factory_alive"])
        self.assertFalse(factory["state"]["auxiliary_alive"])
        self.assertTrue(factory["state"]["factory_alive"])
        self.assertTrue(factory["state"]["pci_by_driver_open"])

    def test_ignored_device_free_error_creates_dangling_untracked_allocation(self):
        case = model_parent_stop(fault="device_free_error_ignored")
        self.assertTrue(case["state"]["device_alive"])
        self.assertEqual(case["state"]["context_references"]["device"], "null")
        self.assertFalse(case["state"]["context_alive"])
        self.assertTrue(any(e["result"] == "EFI_DEVICE_ERROR_INJECTED_BUT_UNCHECKED" for e in case["trace"]))

    def test_pci_close_failure_leaves_orphan_context_and_owner(self):
        case = model_parent_stop(fault="pci_close_error_owner_retained")
        state = case["state"]
        self.assertFalse(state["private_protocol_installed"])
        self.assertTrue(state["pci_by_driver_open"])
        self.assertTrue(state["context_alive"])
        self.assertFalse(state["device_alive"])
        self.assertFalse(state["factory_alive"])
        self.assertEqual(state["context_references"]["auxiliary"], "dangling")
        self.assertEqual(case["restart_pci_open_prediction"], "EFI_ALREADY_STARTED_IF_EXISTING_OWNER_RETAINED")
        self.assertNotIn("free_context", [e["stage"] for e in case["trace"]])
        self.assertEqual(case["recovery"], "RECOVERY_UNPROVEN")

    def test_ignored_context_free_error_does_not_restore_private_protocol(self):
        case = model_parent_stop(fault="context_free_error_ignored")
        self.assertTrue(case["state"]["context_alive"])
        self.assertFalse(case["state"]["private_protocol_installed"])
        self.assertFalse(case["state"]["pci_by_driver_open"])
        self.assertEqual(case["helper_result"], "RETURNED_STATUS_UNDETERMINED")

    def test_all_faults_are_named_and_model_never_claims_unlock(self):
        report = build_report()
        self.assertEqual(report["status"], "COMPLETE")
        self.assertEqual(len(report["scenarios"]), len(FIRMWARE) * (len(FAULTS) + 1))
        self.assertEqual({c["fault"] for c in report["scenarios"]}, set(FAULTS))
        self.assertFalse(report["safety"]["hardware_tested"])
        self.assertFalse(report["safety"]["can_detach"])
        self.assertFalse(report["safety"]["can_unlock"])
        self.assertFalse(report["safety"]["writes_gpu_registers"])
        self.assertTrue(all(c["recovery"] == "RECOVERY_UNPROVEN" for c in report["scenarios"]))
        self.assertTrue(all(c["physical_gpu_behavior"] == "NOT_OBSERVED" for c in report["scenarios"]))

    def test_invalid_fault_and_flag_are_rejected(self):
        with self.assertRaises(ValueError):
            model_parent_stop(fault="magic_recover")
        with self.assertRaises(ValueError):
            model_parent_stop(reset_flag=256)

    def test_capture_binary_provenance_refuses_unknown_images(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "IMG00.BIN").write_bytes(b"mismatched")
            (root / "IMG01.BIN").write_bytes(b"mismatched")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                verify_images(root)


if __name__ == "__main__":
    unittest.main()
