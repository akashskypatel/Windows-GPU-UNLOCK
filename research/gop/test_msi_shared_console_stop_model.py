"""Negative host assertions against original MSI 1A70 Stop return contracts."""
import unittest

from msi_shared_console_stop_model import (
    consplitter_output_stop,
    graphics_console_stop,
)


class OriginalMsiSharedConsoleStopTests(unittest.TestCase):
    def test_zero_children_success_does_not_mean_any_release(self):
        trace = consplitter_output_stop(children=0)
        self.assertEqual(trace.returned_status, 'EFI_SUCCESS')
        self.assertEqual(trace.actions, ('zero_child_early_return',))
        self.assertFalse(trace.shared_member_unlinked)
        self.assertFalse(trace.release_verified)

    def test_wrong_child_count_or_identity_refuses(self):
        for args in ({'children': 2}, {'valid_child': False}):
            with self.subTest(args=args):
                trace = consplitter_output_stop(**args)
                self.assertEqual(trace.returned_status, 'EFI_INVALID_PARAMETER')
                self.assertFalse(trace.shared_member_unlinked)

    def test_absent_shared_member_refuses_before_mutation(self):
        trace = consplitter_output_stop(member_found=False)
        self.assertEqual(trace.returned_status, 'EFI_UNSUPPORTED')
        self.assertFalse(trace.shared_member_unlinked)

    def test_marker_uninstall_failure_is_masked_by_successful_free(self):
        trace = consplitter_output_stop(uninstall_marker_failed=True)
        self.assertEqual(trace.returned_status, 'EFI_SUCCESS')
        self.assertTrue(trace.shared_member_unlinked)
        self.assertFalse(trace.output_marker_removed)
        self.assertIn('uninstall_output_marker', trace.masked_failures)
        self.assertFalse(trace.release_verified)

    def test_mode_helper_failure_follows_unlink_and_is_not_returned(self):
        trace = consplitter_output_stop(mode_refresh_failed=True)
        self.assertEqual(trace.returned_status, 'EFI_SUCCESS')
        self.assertTrue(trace.shared_member_unlinked)
        self.assertIn('recompute_shared_mode', trace.masked_failures)
        self.assertFalse(trace.console_survival_verified)

    def test_text_close_errors_are_ignored_by_consplitter(self):
        trace = consplitter_output_stop(close_text_failed=True)
        self.assertEqual(trace.returned_status, 'EFI_SUCCESS')
        self.assertIn('close_text_protocol', trace.masked_failures)

    def test_free_failure_wins_over_marker_uninstall_result(self):
        trace = consplitter_output_stop(free_member_failed=True)
        self.assertEqual(trace.returned_status, 'FREEPOOL_ERROR')
        self.assertTrue(trace.output_marker_removed)
        self.assertTrue(trace.shared_member_unlinked)

    def test_graphics_console_get_protocol_failure_returns_early(self):
        trace = graphics_console_stop(get_text_failed=True)
        self.assertEqual(trace.returned_status, 'EFI_NOT_STARTED')
        self.assertEqual(trace.actions, ('get_text_protocol',))

    def test_graphics_console_text_uninstall_error_aborts_later_cleanup(self):
        trace = graphics_console_stop(uninstall_text_failed=True)
        self.assertEqual(trace.returned_status, 'TEXT_UNINSTALL_ERROR')
        self.assertNotIn('close_gop_protocol', trace.actions)
        self.assertFalse(trace.text_output_removed)

    def test_graphics_console_cleanup_failures_return_success(self):
        trace = graphics_console_stop(close_text_failed=True,
                                      close_gop_failed=True,
                                      private_free_failed=True)
        self.assertEqual(trace.returned_status, 'EFI_SUCCESS')
        self.assertTrue(trace.text_output_removed)
        self.assertFalse(trace.gop_closed)
        self.assertEqual(set(trace.masked_failures),
                         {'close_text_protocol', 'close_gop_protocol',
                          'free_private_allocations'})
        self.assertFalse(trace.release_verified)

    def test_no_synthetic_case_proves_console_survival_or_cold_recovery(self):
        traces = [consplitter_output_stop(), graphics_console_stop(),
                  consplitter_output_stop(uninstall_marker_failed=True),
                  graphics_console_stop(close_gop_failed=True)]
        for trace in traces:
            self.assertFalse(trace.release_verified)
            self.assertFalse(trace.console_survival_verified)
            self.assertFalse(trace.cold_recovery_verified)


if __name__ == '__main__':
    unittest.main()
