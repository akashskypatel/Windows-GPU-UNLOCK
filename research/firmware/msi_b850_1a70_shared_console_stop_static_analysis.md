# MSI B850 1A70 shared-console Stop — exact original-image static analysis

**Scope:** offline x86-64 disassembly and PE metadata from owner-supplied, MSI-checksum-matching archive. **No Ghidra decompiler run, driver Stop call, MMIO, DMA, FLR or BIOS flashing.** The running RAM image has not yet been byte-correlated to the original image. See [authoritative execution map](../nvidia_unlock_evidence_to_execution_map.md) for gate status and next actions.

## Input and original binaries

| Source | Size | SHA-256 / identity |
|---|---:|---|
| Correct original MSI archive `7E56v1A7.zip` | 13,723,045 B | `1d924e6bebb76b09fb7cccfb4551f659a2c0b95563194923c013b792ec7645a9` (matches manufacturer listing, ZIP CRC passes) |
| Contained `E7E56AMSI.1A70` | 33,554,432 B | `f9e32efb322221d829822ede474cf3a9fce20cc0324f98f4380741de0f5118e3` |
| GraphicsConsole FFS / PE | 18,762 / 18,464 B | FFS `43e7abdd-e352-4cfb-a230-4cdc1d350e5c`; PE `7fb940fd81d384bace5579cecb5ab20d6b963698b7e4294d05fa11015a030c65` |
| ConSplitter FFS / PE | 28,450 / 28,160 B | FFS `628a497d-2bf6-4264-8741-069dbd3399d6`; PE `3f5af6315d9f965de35694de32b5b0fab13350ca1377a38b6356dc6c376cb558` |

Firmware LZMA GUID-defined section `ee4e5898-3914-4259-9d6e-dc7bd79403cf` at raw image offset `0x113C418` expands to 15,167,504 B, SHA `c297b1213cc3d90a40480bfbd6cce7ce56b9751e03443e5f96c2a89fc6a4df74`. In the decompressed volume GraphicsConsole FFS starts at `0x806D58`, ConSplitter at `0x7FFE30`. Both original PE images are PE32+ x86-64 UEFI boot-service drivers; original sizes and FFS identities correlate to passive `GPU-TOPOLOGY-DIAGNOSTIC-0016.TXT`, **not** a running byte-for-byte attestation.

## Real compiled DriverBinding tables and roles

| Module/role | Binding RVA | Supported | Start | Stop | Evidence |
|---|---:|---:|---:|---:|---|
| GraphicsConsole | `0x2C48` | `0xA80` | `0xB3C` | **`0xE28`** | SimpleTextOut/GOP |
| ConSplitter output | `0x5F20` | `0x1314` | `0x13A0` | **`0x1480`** | SimpleTextOut GUID `387477c2-69c7-11d2-8e39-00a0c969723b`; ConsoleOutDevice GUID `d3b36f2c-d551-11d4-9a46-0090273fc14d` |
| ConSplitter console input | `0x5DE8` | `0x1644` | `0x17A4` | **`0x19C8`** | SimpleTextInput `387477c1-69c7-11d2-8e39-00a0c969723b` and SimpleTextInputEx `dd9e7534-7762-4698-8c14-f58517a625aa` |
| ConSplitter pointer input | `0x5E30` | `0x1B1C` | `0x1C24` | **`0x1DB8`** | SimplePointer `31878c87-0b75-11d5-9a4f-0090273fc14d` and AbsolutePointer `8d59d32b-c655-4ae9-9b15-f25904992a43` |

Three ConSplitter table references are registered by the PE initializer (at `0xF8C`, `0xFBB`, `0xFFB`). **Correction:** the other ConSplitter Stop RVAs `0x19C8` and `0x1DB8` are **input**, not independently evidenced StandardError output callbacks. The StandardErrorDevice GUID `d3b36f2d-d551-11d4-9a46-0090273fc14d` is absent from this binary. This does not settle error-output behavior of the entire platform. All addresses are source-image RVAs, not boot-local VAs.

## Exact MSI ConSplitter output Stop `0x1480`

| RVA | Static instruction-level finding | Classification |
|---|---|---|
| `0x14AC–0x14B3` | `NumberOfChildren == 0` returns EFI_SUCCESS without release | **PROVEN STATIC; success is not detach evidence** |
| `0x14B8–0x14D5`, `0x161F` | Nonzero count must be exactly one; non-null ChildHandleBuffer must identify virtual child `0x6390`; otherwise EFI_INVALID_PARAMETER | **PROVEN STATIC** |
| `0x14DB–0x14F7` | Search shared output-list head `0x6508`, node controller at `+0x18`; absent node retains EFI_UNSUPPORTED | **PROVEN STATIC; runtime reachability unknown** |
| `0x150F`, `0x1531` | Two BootServices.CloseProtocol `+0x120` calls on TextOut relationships; **return statuses not tested** | **PROVEN STATIC ignored statuses** |
| `0x1541` / helper `0x5A04` | Unlink node from doubly linked list; decrement global count at `0x6500` | **PROVEN STATIC shared-state mutation** |
| `0x154C` / helper `0x4664` | Re-evaluate graphics/mode state, use GOP HandleProtocol and allocate/update global buffers `0x6418`/`0x6410`; helper has no return-status contract to Stop | **PROVEN STATIC helper call, runtime display effect unknown** |
| `0x155B` / `0x1575` | FreePool(node) result captured into nonvolatile RBP | **PROVEN STATIC** |
| **`0x1578` / `0x161A`** | UninstallMultipleProtocolInterfaces `+0x150` of ConsoleOutDevice marker is called; its result is **discarded**; function returns **previous FreePool result** via `mov rax,rbp` | **PROVEN STATIC status masking; real failure not observed** |
| `0x157F–0x1600` | Conditional global buffers/flags cleanup after shared output list changes, including when list is empty | **PROVEN STATIC conditional branch, AMD/other-NVIDIA effect untested** |

**Important:** this is a demonstrable *masked-result path*, not evidence that the service failed in any actual boot. Because the shared list can already change before the output Stop returns, a success return alone cannot certify independent console survival.

## GraphicsConsole Stop `0xE28`

- `0xE67`: OpenProtocol `+0x118` SimpleTextOut/GET_PROTOCOL; on failure return EFI_NOT_STARTED at `0xE72`.
- `0xE99`: CloseProtocol `+0x120` SimpleTextOut; returned status not tested.
- `0xED1–0xEDA`: UninstallMultipleProtocolInterfaces `+0x150` on SimpleTextOut; error returns immediately at `0xF25` without GOP close/private frees, after the earlier CloseProtocol attempt.
- `0xEF4`, `0xF05`, `0xF13`, `0xF20`: success path closes GOP and frees three private allocations, ignoring cleanup return codes, then returns EFI_SUCCESS.
- This compiled Stop body does not inspect NumberOfChildren or ChildHandleBuffer. **No live callback/Stop sequence has been tested.**

## Additional bounded static trace: shared mode helper `0x4664`

The original ConSplitter PE `Stop(0x1480)` calls helper `0x4664` **after** unlinking the matching TextOut member from shared list `0x6508` and **before** freeing its node and attempting to uninstall the ConsoleOutDevice marker. Direct disassembly bounds `0x4664–0x4762` and its allocation helper `0x4E54–0x4E84` show:

- At `0x467C–0x4693`, obtain GOP using `BootServices.HandleProtocol(+0x98)` and **check its return**; on failure return early. Thus there is a branch where member unlink has already happened but mode recalculation never completes.
- At `0x4699–0x46B8`, compute a size from shared state `0x63D8` minus `0x63E8`, call helper `0x4E54` (a wrapper around `BootServices.AllocatePool(+0x40)`, memory type `4`) and assign result to global buffer `0x6418`. On failure it exits with no status returned to the caller.
- At `0x46BE–0x46EF`, request a second, double-sized allocation and assign global `0x6410`. If it fails, it invokes `BootServices.FreePool(+0x48)` on the first allocation and clears global `0x6418`, then exits.
- At `0x46F1–0x474E`, the success path calls boot-service helpers, copies portions of prior shared output-mode buffers into the newly allocated state and calls `0x4410` to update a mode/console structure. This helper is not returning a UEFI EFI_STATUS to its Stop caller; no successful mode reconstruction has been observed on hardware.

**Additional static partial-failure risk, not a measured fault:** `Stop` has already modified the shared member list when `0x4664` encounters GOP lookup or allocation failure. No direct failure status is propagated back through the `Stop` call, which later bases its return on other cleanup results. The exact downstream buffer validity, physical display continuity and caller unwind remain UNKNOWN. Do not assume this code path is a successful or failed hardware transaction.

## Original-vs-running `.text` hashes (correction to earlier raw digest)

| Module | `.text` RVA | VirtualSize used by loaded PE parser | SizeOfRawData | **Comparable original SHA-256** | PE relocations into `.text` |
|---|---:|---:|---:|---|---:|
| GraphicsConsole | `0x280` | `0x2860` = 10,336 B | 10,336 B | `7966680e5bb1d764b7a70b3d20362658e549de51138a3582070ab0cca00ae695` | 0 |
| ConSplitter | `0x280` | `0x59B8` = 22,968 B | **22,976 B** | **`b2ce93060babbb674d67cc9e07fa36a4dde10e7c5c17170d8ea577c920525006`** | 0 |

**Correction:** previous ConSplitter raw `.text` digest `e0a2a59faeafcfe1ecc0462b8d35892037d6a32914718d44b6a292a950b153f5` includes **eight zero-padding bytes** and is **not** comparable with the existing `GuLoadedPeTextRange` VirtualSize read of 22,968 bytes. No base-relocation records fall in either PE `.text`, but matching mapped hashes still does not authenticate signatures, runtime code execution or the whole firmware.

## Passive provenance collector and remaining gates

Universal diagnostic `src/gpu_topology_efi.c` now logs `SHARED_CONSOLE_TEXT` for unique LoadedImage.ImageHandle values from GOP/TextOut consumer owners. Bounded to eight image handles, 8 MiB per image, existing `GuLoadedPeTextRange` and SHA-256, with `SIGNATURE_NOT_VERIFIED` / `STOP_NOT_CALLED`. This is passive-only and **not hardware-run yet**. CI compiling the change is independent evidence of build correctness, not of a valid resident hash. A new USB capture is only warranted after explicit owner review of local unsigned-build/signing path and stays **read-only**.

**Static fault conclusions:** Zero-child ConSplitter Stop success without detach; invalid/nonmatching child rejection; ignored CloseProtocol statuses; shared-list unlink before cleanup; ignored uninstall status with return of earlier FreePool status; GraphicsConsole uninstall failure halts further cleanup; on success GOP close/free errors ignored. **Do not merge these MSI shared-driver conditions into the existing 22-case NVIDIA-parent Stop host model.** Actual AMD/other NVIDIA behavior, cold-boot recovery and signed Windows GA102/AD102 Booter producer remain open.

**Independent Windows Booter task:** the latest `research/ghidra/windows_61742_booter_investigation.md` entry (2026-11-06 13:44 PST) leaves `flcnCreateHsOvlSigBlob_GA10X` data VA `0x140D2EB10` and `RmAllocIsoSysMemFromCarveout` `0x140D0AD10` untraced. Next bounded passive Ghidra read uses TRACE_DATA_SITES for those addresses and `0x140D2EAE0`; real original Windows driver MD5 `3fb9afac9d0e394723e830aa14e60512` is not available in this session, so **no new decompilation or signed Booter proof** is claimed.

**Hold:** Stage 3 CONFLICT; Stage 4 PARTIAL overall (physical 0016 graph PASS; static MSI Stop analysis advanced); `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`. No active authorization.
