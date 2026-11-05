#!/usr/bin/env python3
"""Host-only NVIDIA GOP zero-child Stop lifecycle fault model.

The sequence is manually transcribed from the matching RTX 3080/4090 Ghidra
exports. It NEVER executes firmware, invokes UEFI services, or accesses GPUs.
It tests implications of modeled control flow, not physical recovery.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path


FIRMWARE = {
    "RTX4090": {
        "image": "IMG00.BIN",
        "sha256": "0fbd44f3455d4df5ade4bc738dbbc73fbd213487a7456a953af9e8ccbc14c2ba",
        "stop_parent_rva": "0x209c",
        "device_destructor_rva": "0xafd8",
        "embedded_destructor_rva": "0x12d20",
        "embedded_mmio_helper_rva": "0x11dd8",
    },
    "RTX3080": {
        "image": "IMG01.BIN",
        "sha256": "a9da4af0bf448feb458f55da926329e135b2739e043dd0bfda69915747b728e9",
        "stop_parent_rva": "0x20b0",
        "device_destructor_rva": "0xad0c",
        "embedded_destructor_rva": "0xf754",
        "embedded_mmio_helper_rva": "0xe80c",
    },
}

# Fault names express the precise source of failure. The interrupt conditions
# are hypotheses about non-returning/hanging vendor methods, NOT EFI_STATUS.
FAULTS = (
    "none",
    "private_open_error",
    "private_uninstall_error",
    "before_device_destructor_interrupt",
    "during_embedded_cleanup_interrupt",
    "before_auxiliary_destructor_interrupt",
    "before_factory_destructor_interrupt",
    "device_free_error_ignored",
    "pci_close_error_owner_retained",
    "context_free_error_ignored",
)


@dataclass
class State:
    """Separate logical allocations from references retained in context."""

    private_protocol_installed: bool = True
    pci_by_driver_open: bool = True
    context_alive: bool = True
    optional_allocation_alive: bool = False  # DIAG10 context+0x68 == 0 on both
    device_alive: bool = True
    adapter_alive: bool = True
    embedded_alive: bool = True
    auxiliary_alive: bool = True
    factory_alive: bool = True
    context_references: dict[str, str] = field(default_factory=lambda: {
        "device": "live", "auxiliary": "live", "factory": "live", "pci_io": "live"
    })


def model_parent_stop(*, reset_flag: int = 0, fault: str = "none") -> dict:
    """Model the exported zero-child Stop helper with DIAG10 object presence.

    EFI service errors short-circuit only where the exported code checks them.
    Destructors and FreePool calls have no checked status in this caller.
    Hardware paths are recorded as *possible*, not simulated or confirmed.
    """
    if fault not in FAULTS:
        raise ValueError(f"unsupported fault: {fault}")
    if not 0 <= reset_flag <= 255:
        raise ValueError("reset flag must be an unsigned byte")

    state = State()
    trace: list[dict[str, str]] = []
    paths: list[str] = []
    outcome = "RETURNED_STATUS_UNDETERMINED"

    def record(stage: str, result: str = "MODELED", detail: str = "") -> None:
        entry = {"stage": stage, "result": result}
        if detail:
            entry["detail"] = detail
        trace.append(entry)

    def result() -> dict:
        return {
            "fault": fault,
            "reset_flag": reset_flag,
            "helper_result": outcome,
            "state": asdict(state),
            "hardware_paths": paths,
            "trace": trace,
            "restart_pci_open_prediction": (
                "EFI_ALREADY_STARTED_IF_EXISTING_OWNER_RETAINED"
                if state.pci_by_driver_open and not state.private_protocol_installed
                else "NOT_DETERMINED"
            ),
            "recovery": "RECOVERY_UNPROVEN",
            "physical_gpu_behavior": "NOT_OBSERVED",
        }

    # BootServices.OpenProtocol(private, GET_PROTOCOL). If error, return void.
    if fault == "private_open_error":
        record("private_open_protocol", "EFI_DEVICE_ERROR_INJECTED")
        return result()
    record("private_open_protocol", "EFI_SUCCESS")

    # Only the reset flag guards the extra virtual callback, not destruction.
    if reset_flag:
        record("device_output_callback", detail="flag != 0; return value not checked")
        paths.append("OUTPUT_MASK_BAR0_WRITE_POSSIBLE")
    else:
        record("device_output_callback", "SKIPPED_FLAG_ZERO")

    # BootServices.UninstallProtocolInterface. Stop helper returns on error.
    if fault == "private_uninstall_error":
        record("private_uninstall_protocol", "EFI_DEVICE_ERROR_INJECTED")
        return result()
    state.private_protocol_installed = False
    record("private_uninstall_protocol", "EFI_SUCCESS")

    # DIAG10: optional allocation at context+0x68 is zero in both GPUs.
    if state.optional_allocation_alive:
        state.optional_allocation_alive = False
        record("free_optional_allocation", "RETURN_UNCHECKED")
    else:
        record("free_optional_allocation", "SKIPPED_NULL")

    if state.device_alive:
        if fault == "before_device_destructor_interrupt":
            outcome = "INTERRUPTED_NOT_EFI_STATUS"
            record("device_destructor", "INTERRUPTED_BEFORE_CALL")
            return result()
        record("device_destructor", "ENTERED")
        if state.embedded_alive:
            # This models call reachability. A BAR0 read/write or unbounded
            # status poll could be conditional or fail; NOT actual hardware IO.
            paths.append("EMBEDDED_BAR0_6104E0_RMW_AND_610630_POLL_POSSIBLE")
            record("embedded_cleanup", "ENTERED", "possible unbounded status wait")
            if fault == "during_embedded_cleanup_interrupt":
                outcome = "INTERRUPTED_NOT_EFI_STATUS"
                record("embedded_cleanup", "INTERRUPTED_UNKNOWN_PARTIAL_HARDWARE_STATE")
                return result()
        state.embedded_alive = False
        state.adapter_alive = False
        record("device_destructor", "RETURNED", "nested objects modeled released")
        if fault == "device_free_error_ignored":
            record("free_device", "EFI_DEVICE_ERROR_INJECTED_BUT_UNCHECKED")
            # The caller still zeroes the pointer despite FreePool failure.
        else:
            state.device_alive = False
            record("free_device", "EFI_SUCCESS")
        state.context_references["device"] = "null"

    if state.auxiliary_alive:
        if fault == "before_auxiliary_destructor_interrupt":
            outcome = "INTERRUPTED_NOT_EFI_STATUS"
            record("auxiliary_destructor", "INTERRUPTED_BEFORE_CALL")
            return result()
        record("auxiliary_destructor", "ENTERED_AND_RETURNED")
        state.auxiliary_alive = False
        # Decompiled Stop frees this object but does NOT clear context+0x40.
        state.context_references["auxiliary"] = "dangling"
        record("free_auxiliary", "RETURN_UNCHECKED_POINTER_NOT_CLEARED")

    if state.factory_alive:
        if fault == "before_factory_destructor_interrupt":
            outcome = "INTERRUPTED_NOT_EFI_STATUS"
            record("factory_destructor", "INTERRUPTED_BEFORE_CALL")
            return result()
        record("factory_cleanup_method_0x28", "RETURN_UNCHECKED")
        record("factory_destructor", "ENTERED_AND_RETURNED")
        state.factory_alive = False
        state.context_references["factory"] = "null"
        record("free_factory", "RETURN_UNCHECKED")

    # Late CloseProtocol(PCI_IO); only this specific error is checked.
    if state.pci_by_driver_open:
        if fault == "pci_close_error_owner_retained":
            record("pci_close_protocol", "EFI_DEVICE_ERROR_INJECTED", "assume existing BY_DRIVER open remains")
            return result()
        state.pci_by_driver_open = False
        record("pci_close_protocol", "EFI_SUCCESS")

    if fault == "context_free_error_ignored":
        record("free_context", "EFI_DEVICE_ERROR_INJECTED_BUT_UNCHECKED")
    else:
        state.context_alive = False
        record("free_context", "RETURN_UNCHECKED")
    return result()


def verify_images(directory: Path) -> None:
    """Optional provenance check, never required to execute the host-only model."""
    for gpu, identity in FIRMWARE.items():
        path = directory / identity["image"]
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError(f"{gpu}: missing, symlinked, or oversized binary: {path}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != identity["sha256"]:
            raise ValueError(f"{gpu}: captured image hash mismatch: {path}")


def build_report() -> dict:
    cases = []
    for gpu in FIRMWARE:
        for fault in FAULTS:
            record = model_parent_stop(fault=fault)
            record["gpu"] = gpu
            cases.append(record)
        record = model_parent_stop(reset_flag=1, fault="private_uninstall_error")
        record["gpu"] = gpu
        cases.append(record)
    return {
        "schema": "nvgop-host-teardown-model/1",
        "status": "COMPLETE",
        "model_scope": "HOST_ONLY_ZERO_CHILD_PARENT_STOP",
        "grounding": "DIAG10 live non-null objects plus Ghidra IMG00/IMG01 exported C",
        "firmware": FIRMWARE,
        "assumptions": [
            "Existing PCI BY_DRIVER owner remains on injected CloseProtocol failure; actual failure semantics may vary",
            "Destructor object release on normal return is simplified; internal nested error handling is not fully recovered",
            "An interrupted destructor is modeled as a stop in execution, not an EFI_STATUS return",
            "Hardware MMIO and timing are NOT simulated, only possible call paths recorded",
            "FreePool failures assumed to leave allocation alive although NVIDIA's caller ignores their return",
            "Ghidra infers void for the parent helper; its machine-level or outer DriverBinding.Stop EFI_STATUS result is not established",
            "A clean software state does not demonstrate successful restart or physical GPU recovery",
        ],
        "scenarios": cases,
        "safety": {
            "can_detach": False,
            "can_unlock": False,
            "hardware_tested": False,
            "writes_gpu_registers": False,
            "executes_uefi": False,
            "recovery_verified": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--image-directory", type=Path, help="optional matching DIAG08/10 IMG00/IMG01 binaries")
    parser.add_argument("--output", type=Path, help="output JSON path; otherwise prints JSON to stdout")
    args = parser.parse_args()
    try:
        if args.image_directory is not None:
            verify_images(args.image_directory)
        report = build_report()
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
            print(f"STATUS=COMPLETE REPORT={args.output} SCENARIOS={len(report['scenarios'])}")
        else:
            print(rendered, end="")
            print(f"STATUS=COMPLETE SCENARIOS={len(report['scenarios'])}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"STATUS=ERROR REASON={exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
