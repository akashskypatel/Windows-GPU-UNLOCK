# NVIDIA GOP parent Stop host-only lifecycle model

\`nvgop_stop_model.py\` is a **simulation of software-control flow**, not an EFI
application, hardware driver, firmware parser, or permission to disconnect a GPU.
It contains no UEFI entry point, PCI/MMIO calls, firmware loading or GPU writes.

Its two fixed identities are the captured loaded \`IMG00.BIN\` (RTX 4090) and
\`IMG01.BIN\` (RTX 3080). These images are **not** flashable VBIOS ROMs.
The model is based on the recovered zero-child parent \`Stop()\` sequence,
DIAG10 object presence, and deliberately injected service and interruption
failures. It does not execute proprietary NVIDIA code.

Run tests from \`research/gop\` using a single command:

\`\`\`powershell
python -m unittest -v test_nvgop_stop_model
\`\`\`

Generate the 22-scenario report, optionally verifying the real raw captures
first (replace the example path with your archived images directory):

\`\`\`powershell
python .\nvgop_stop_model.py --image-directory 'G:\RTX3090-UNLOCK\archive' --output .\nvgop-stop-recovery-fault-matrix.json
\`\`\`

The \`--image-directory\` option is optional; it SHA-256-checks both image files
before modeling and never opens them for execution or writing. When omitted,
there is no claim of binary-integrity checking at run time.

Failure markers represent modeled state and possible MMIO call reachability,
**not** actual GPU register changes. The \`pci_close_error_owner_retained\`
scenario assumes a failed \`CloseProtocol\` leaves the existing \`BY_DRIVER\`
open; the exact live firmware error semantics have not been observed.
\`RETURNED_STATUS_UNDETERMINED\` deliberately does not assert the outer
\`DriverBinding.Stop()\` EFI_STATUS because Ghidra's parent-helper return type
is an inference. Every case remains \`RECOVERY_UNPROVEN\`.

References:
- \`nvidia-tensor-core-unlock-investigation-v93.md\` sections v86–v93
- \`nvgop-diag10-live-context-analysis-v93.md\`
- \`nvgop-next-investigation-plan-v90.md\` §3

The model does not enable an active GPU-unlock path. It should be reviewed
against the pinned captured binaries when any firmware version changes.
