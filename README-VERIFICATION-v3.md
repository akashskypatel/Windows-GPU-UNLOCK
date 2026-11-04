# Dual-NVIDIA UEFI diagnostic — host verification bundle v3

Contains two **separate** packages:

- `dual-uefi-probe-implementation/`: inventory source patcher, topology reporter, audit and 22 original tests; content copied from the prior fixed package. Existing `probe.c` patch must not be re-applied.
- `dual-uefi-probe-handoff-fix/`: unchanged v2 handoff source patch, unchanged production `audit_handoff.py`, and corrected cross-platform host tests (12 tests). Existing `handoff.c` patch must not be re-applied.

Extract with paths intact into your `Windows-GPU-UNLOCK` repository root. Do not flatten either package into repository-level `tests` or `tools`.

From PowerShell in the repository root, run these separately:

```powershell
python -I -m unittest discover -s .\dual-uefi-probe-implementation\tests -v
```

```powershell
python -I -m unittest discover -s .\dual-uefi-probe-handoff-fix\tests -v
```

If you already copied old tests to repository-root `tests/`, ignore that stale test directory for this validation. Reconcile/delete it only after confirming it contains no independent project tests.

The corrected fixture uses an exact byte-for-byte source hash and verifies both valid LF and CRLF inputs. The patch EOF test still verifies correct semantic end-of-file, expected guarded return, and refuses double application.

After validation, rebuild only the diagnostic EFI and run both existing audits. Record the resulting EFI SHA-256; previous binary hashes cannot substantiate new source builds. Do not boot an image just because host tests or static audits pass.
