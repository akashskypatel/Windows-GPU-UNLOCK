#!/usr/bin/env python3
"""Host-only return/partial-state contract for original MSI B850 1A70 Stop bodies.

The paths reflect the static source-RVA trace in
research/firmware/msi_b850_1a70_shared_console_stop_static_analysis.md.
No EFI callbacks are invoked. The model does not predict display survival,
firmware timing, rollback, or hardware recovery.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json


@dataclass(frozen=True)
class StopTrace:
    returned_status: str
    actions: tuple[str, ...]
    masked_failures: tuple[str, ...]
    shared_member_unlinked: bool = False
    output_marker_removed: bool = False
    text_output_removed: bool = False
    gop_closed: bool = False
    # An EFI_SUCCESS return alone never establishes complete release or
    # AMD/other-NVIDIA continuity after a proprietary callback.
    release_verified: bool = False
    console_survival_verified: bool = False
    cold_recovery_verified: bool = False


def consplitter_output_stop(
    *,
    children: int = 1,
    valid_child: bool = True,
    member_found: bool = True,
    close_text_failed: bool = False,
    mode_refresh_failed: bool = False,
    free_member_failed: bool = False,
    uninstall_marker_failed: bool = False,
) -> StopTrace:
    """Model the *reported* outcome of ConSplitter output Stop RVA 0x1480.

    In the actual binary, two CloseProtocol statuses are ignored; the member
    is unlinked before the no-return-status mode helper; the marker uninstall
    status is discarded in favor of the previously saved FreePool result.
    """
    if children == 0:
        return StopTrace('EFI_SUCCESS', ('zero_child_early_return',), ())
    if children != 1 or not valid_child:
        return StopTrace('EFI_INVALID_PARAMETER', ('validate_child',), ())
    if not member_found:
        return StopTrace('EFI_UNSUPPORTED', ('find_shared_output_member',), ())

    ignored = []
    if close_text_failed:
        ignored.append('close_text_protocol')
    if mode_refresh_failed:
        ignored.append('recompute_shared_mode')
    if uninstall_marker_failed:
        ignored.append('uninstall_output_marker')
    actions = (
        'close_text_protocol',
        'unlink_shared_output_member',
        'recompute_shared_mode',
        'free_shared_output_member',
        'uninstall_output_marker',
    )
    return StopTrace(
        'FREEPOOL_ERROR' if free_member_failed else 'EFI_SUCCESS',
        actions,
        tuple(ignored),
        shared_member_unlinked=True,
        output_marker_removed=not uninstall_marker_failed,
    )


def graphics_console_stop(
    *,
    get_text_failed: bool = False,
    close_text_failed: bool = False,
    uninstall_text_failed: bool = False,
    close_gop_failed: bool = False,
    private_free_failed: bool = False,
) -> StopTrace:
    """Model the *reported* outcome of GraphicsConsole Stop RVA 0xE28.

    The compiled body fails early for GET_PROTOCOL and TextOut uninstall.
    Later GOP close and private frees do not affect its returned success.
    """
    if get_text_failed:
        return StopTrace('EFI_NOT_STARTED', ('get_text_protocol',), ())
    actions = ['get_text_protocol', 'close_text_protocol', 'uninstall_text_protocol']
    ignored = ['close_text_protocol'] if close_text_failed else []
    if uninstall_text_failed:
        return StopTrace('TEXT_UNINSTALL_ERROR', tuple(actions), tuple(ignored))
    actions.extend(('close_gop_protocol', 'free_private_allocations'))
    if close_gop_failed:
        ignored.append('close_gop_protocol')
    if private_free_failed:
        ignored.append('free_private_allocations')
    return StopTrace(
        'EFI_SUCCESS', tuple(actions), tuple(ignored),
        text_output_removed=True, gop_closed=not close_gop_failed,
    )


def main() -> int:
    # Synthetic contrasting traces. Not an on-device test or permission grant.
    cases = {
        'no_child_return_success': asdict(consplitter_output_stop(children=0)),
        'marker_failure_masked': asdict(consplitter_output_stop(uninstall_marker_failed=True)),
        'shared_mode_failure_masked': asdict(consplitter_output_stop(mode_refresh_failed=True)),
        'graphics_console_cleanup_failure_masked': asdict(
            graphics_console_stop(close_gop_failed=True)),
    }
    print(json.dumps({'provenance': 'MSI_1A70_SOURCE_STATIC_MODEL_ONLY',
                      'hardware_tested': False, 'cases': cases}, indent=2))
    print('STATUS=COMPLETE CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false '
          'RECOVERY_VERIFIED=false')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
