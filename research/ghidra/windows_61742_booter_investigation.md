# 2026-11-05 — UCODES offset search inconclusive in GSP initialization function

## Evidence reviewed

User-run read-only Ghidra report: `nvlddmkm-61742-booter-discovery-20261105-114742-741405.txt` (SHA-256 `b2a019b46b15ac07fcf65b1b6ab8f23a198a125e97b9f352ce2f830ba8aa6513`). `nvlddmkm.sys` 617.42 MD5 `3fb9afac9d0e394723e830aa14e60512`, image base `0x140000000`; `HARDWARE_ACTION=NONE`, `GHIDRA_MUTATION=NONE`.

`FUN_1401B0E00` decompiled to 16,563 C characters. Focused report `excerpt_truncated=False` for four requested literals (NOT the complete function). Exact counts:

| Search | Matches |
|---|---:|
| `0x69f70` (the previously observed UCODES destination resource offset) | 0 |
| `0x69f78` (adjacent resource state field) | 0 |
| `FUN_1401b2c10` | 1 |
| `FUN_1401a7840` | 1 |

The displayed call `FUN_1401B2C10(param_1,param_2,0)` occurs after RMARGS-associated staging at C line 213 and before additional GSP initialization/boot-attempt work. `FUN_1401A7840(param_1,param_2,param_3,local_54)` is shown in the retry loop at C line 277. Decompiler-printed arguments in large functions may omit stack-passed values, as seen previously; preserve that caveat.

## What this does and does not establish

- It **does not** show a direct offset-based access to `param_2+0x69F70` or `param_2+0x69F78` inside this particular function.
- It **does not prove the staged UCODES resource is unused**; references might occur in callees, through a passed object, aliases, or indirect vtable calls. Literal zero counts are not cross-function data-flow proof.
- `STATUS=COMPLETE` is valid for the **requested excerpt collection**, because two requested function names matched and all selected snippets fit. It does not attest the other two terms were present or that the full function was reviewed. The report explicitly prints both missing term counts.
- Prior independently analyzed `FUN_1401AA580` remains a GSP logging initializer, not a Booter/UCODES selector. The known external file read / ELF section parse / UCODES staging chain remains intact, but Windows production Booter record location, selector and authentication remain unproven.

## Next small, read-only investigation step

Decompile `FUN_1401B2C10` once to determine whether it initializes boot state, accesses the staged UCODES resource or only handles an unrelated operation. Do not assume it is a Booter parser based solely on its position in the sequence:

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1401b2c10"], "__name__": "__main__"})
```

If it is clipped, the corrected script must mark `STATUS=PARTIAL` and its own C output incomplete. If it does not access UCODES, continue tracing actual consumers of the staged resource at `param_2+0x69F70` through existing driver-code references, rather than expanding a generic search of all firmware-related functions. Avoid any Ghidra database writes or device changes. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`.

---

# 2026-11-05 — GSP logging initializer classified; excluded from Booter provenance shortlist

## Source and verification

User-run read-only Ghidra report: `nvlddmkm-61742-booter-discovery-20261105-114128-691537.txt`, SHA-256 `79ce078bdb09428a0f82d628146d518108fa90633ee10114fad8dcffd660d14a`. Same verified `nvlddmkm.sys` 617.42 binary (MD5 `3fb9afac9d0e394723e830aa14e60512`, image base `0x140000000`). `FUN_1401AA580` complete decompilation (`clipped=False`, `STATUS=COMPLETE`); `HARDWARE_ACTION=NONE`, `GHIDRA_MUTATION=NONE`. Caller `0x1401B10B6` in `FUN_1401B0E00` is an existing unconditional call, as previously observed.

## Concrete function classification

`FUN_1401AA580(param_1,param_2)` configures **GSP firmware logging buffers**. It reads `RmGspLogBufferSizeTaskInit`, `RmGspLogBufferSizeTaskIntr`, `RmGspLogBufferSizeTaskRm`, and `RmGspLogBufferSizeTaskMnoc`; visible defaults include `0x10000` for several task log buffers, with some descriptors using `0x1000`. It constructs seven logging descriptors indexed through the static `PTR_s_LOGINIT_140E8A790`/associated tables, calls `FUN_1401AEBE0` to set them up, and optionally selects a chip-family/revision-dependent `fwlogging_kernel_*` descriptor for `LOGKRNL`. It references `FUN_140637160`, `FUN_140633AF0`, and calls `FUN_1401A97F0` in a finalization/error branch. No raw `UCODES`, `NVUCODES`, `Booter`, or firmware image-selection logic appears in this complete decompilation.

**Corrected prioritization:** this function was previously nominated as an unknown post-staging UCODES consumer. That hypothesis is not supported by the newly available source; reclassify as a **logging-only initializer** and remove from Booter/SEC2 production-image search targets. Chip-family checks here select *logging resource descriptions*, not production Booter images. The default logging-buffer sizes are static observations, not recommended system settings.

## Most useful next static trace

Previously grounded stages remain: `FUN_1400F3350` opens GSP/UCODES files; `FUN_1401AB740` parses GSP ELF and stages GSP and optional UCODES bytes through `FUN_1401AFD60` into distinct resource contexts (GSP near `param_2+0xB00`; UCODES near `param_2+0x69F70`). `FUN_1401B0E00` subsequently contains the GSP boot-attempt loop, but its former broad decompilation was clipped. The next analysis should **look for code using the staged UCODES resource** before attributing an actual Windows production Booter.

Run a bounded, read-only focused decompilation of `FUN_1401B0E00` at known source-level anchor names/offsets, without repeating the full memory scan:

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1401b0e00"], "DECOMP_FOCUS_TERMS": ["0x69f70", "0x69f78", "FUN_1401a7840", "FUN_1401b2c10"], "__name__": "__main__"})
```

If offset literals are absent, that is **not** proof the UCODES resource is unused: its pointer may be propagated through objects, aliases or indirect dispatch. Use resulting concrete callsites to narrow subsequent analysis. Do not investigate `FUN_1401AEBE0` as Booter-related solely because it is called here; it is a logging-setup lead. **No production Booter source/selection/cryptographic acceptance proven; no device action.** `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`.

---

# 2026-11-05 — FUN_1401AFD60 decoded: common GSP/UCODES mapping and copy helper

## Evidence and scope

User-run read-only Ghidra report: `nvlddmkm-61742-booter-discovery-20261105-113623-765552.txt`, SHA-256 `e9ea9187bdd3d964eb0ca5454556dee66e3c04918a2636833b70b387d2e19c6d`. Driver `nvlddmkm.sys` 617.42 (MD5 `3fb9afac9d0e394723e830aa14e60512`, base `0x140000000`). Function `FUN_1401AFD60` decompiled in full (`clipped=False`, `STATUS=COMPLETE`); original Ghidra report says `HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE`.

### Grounded callee contract and behavior

Decompiler prototype: `int FUN_1401AFD60(undefined8 param_1, undefined8 param_2, longlong *param_3, longlong param_4, longlong param_5, longlong param_6)`. The observed behavior gives a probable semantic model, **not an ABI-independent type definition**:

- `param_3` is a pointer to an output resource handle. Null is rejected, and the first field is populated on allocation.
- It rejects a simultaneous non-null `param_4` (existing descriptor/resource) and `param_5` (host-source pointer). With `param_5 != 0` and `param_4 == 0`, `param_6` supplies the data length. With `param_5 == 0`, it may obtain a length from the existing descriptor at `param_4 + 0x30` if no explicit size is provided.
- It computes 4-KiB page counts, page-table-related sizes and an allocation region; `FUN_1401B9020(param_3,param_1,lVar5,0x1000)` allocates; `FUN_1401BD1C0`, `FUN_1401B87B0`, `FUN_1401BBE70`, `FUN_1401BB110`, and `FUN_1401BD4C0` perform setup/mapping steps. The allocated resource has an observed type-like field `*(uint *)(*param_3+0x9C)=0x32` in the path shown. Return/error paths include allocation failure, unsupported mapping geometry and resource cleanup.
- In the host-buffer copy branch, `local_a8=param_5` and the exact operation is `FUN_1400DF7C0(lVar2+local_50,param_6,local_a8,param_6)`, followed by clearing unused allocation space. The copy proves the helper can stage supplied bytes. It **does not parse** NVUCODES entries, choose an AD102/GA102 Booter, inspect Booter signatures or establish cryptographic verification.

### Caller provenance and next gate

Existing direct callsites: `0x1401ABB83` and `0x1401ABC5A` within `FUN_1401AB740`, and `0x14091F922` in a separate caller. The earlier complete `FUN_1401AB740` decompilation prepares source pointers/sizes for (1) GSP `.fwimage` and (2) the separate, optional UCODES file, with output resource state at `param_2 + 0xB00` and `param_2 + 0x69F70`. This six-parameter callee **strengthens** that interpretation; however, Ghidra printed only four arguments at these callsites, so the exact two stack-passed arguments must be verified from actual callsite assembly before the source pointer/length binding is marked definitive.

The next highest-value post-staging operation is `FUN_1401AA580(param_1,param_2)`, which `FUN_1401B0E00` invokes after `FUN_1401AB740` and before the boot-attempt loop. Check whether it consumes the staged UCODES resource, delegates to a record selector, or performs unrelated work. Do not decompile the common mapping helper again.

**Next read-only Ghidra Python 3 command (existing script, no 114-MB scan):**

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1401aa580"], "__name__": "__main__"})
```

If that function is clipped, retain the `PARTIAL` report and use evidence-driven focused terms. Optionally verify the two `FUN_1401AFD60` caller argument layouts by read-only Ghidra Listing/disassembly before claiming final source/size provenance. No EFI/driver change, firmware flash, GPU mutation or actual Booter signature acceptance has occurred. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`.

---

# 2026-11-05 — Windows GSP ELF64 parser, signature architecture suffix, and GSP/UCODES staging

## Evidence from user-run Ghidra

- nvlddmkm-61742-booter-discovery-20261105-112603-202276.txt; SHA256 0e625ef7ebdd7c07cb04cdaac373dfd07d5424ce1b1822b892886c6f4ca26877. FUN_1401AB740 and FUN_1401A7840 fully decompiled, clipped=False, STATUS=COMPLETE.
- nvlddmkm-61742-booter-discovery-20261105-112607-237998.txt; SHA256 ad2d85348595116afb470101a9e9a181c7b3d9e07e65bcfa633635a5fc27f5c2. FUN_1401A9AE0 and FUN_1401AA0E0 fully decompiled, clipped=False, STATUS=COMPLETE.
- Windows driver identity: nvlddmkm.sys 617.42, MD5 3fb9afac9d0e394723e830aa14e60512, Ghidra base 0x140000000. Reported Ghidra and hardware mutation: NONE. No local Windows run was independently performed by the assistant.

## ELF section lookup, not signature verification

**FUN_1401A9AE0** is a named-section lookup for an ELF64 little-endian source buffer. Observed checks: non-null buffer/name/output pointers; input size at least 0x40; ELF magic 0x464C457F; EI_DATA byte +5 equals 1; ELFCLASS byte +4 equals 2; section-header entry size +0x3A equals 0x40; section-count/header-table offsets, overflow and bounds; section-name string-table index and range; section name comparison and section data offset/size bounds. On a matching terminated section name, outputs source-buffer-relative section pointer and length. This is structural validation, NOT proof of cryptographic authentication, complete parser soundness, or successful firmware runtime acceptance.

**FUN_1401AA0E0** constructs a section name by appending a chip-family suffix to a caller-supplied prefix, using device fields at param_1+0xDBC and param_1+0xDC0. The visible switch chooses these literal suffixes:

| Family field | Revision selector | Suffix |
|---|---|---|
| 0x160 | below 7 / otherwise | tu10x / tu11x |
| 0x170 | zero / nonzero | ga100 / ga10x |
| 0x180 | any | gh100 |
| 0x190 (Ghidra rendered as decimal 400) | any | ad10x |
| 0x1A0 | revision 0xB / otherwise | gb10y / gb10x |
| 0x1B0 | below 0xB / otherwise | gb20x / gb20y |
| 0x1C0 | any | gr10x |

It checks that prefix+suffix+terminating NUL fits the output, then copies/concatenates. The prefix appears to derive from the previously established signature-prefix vtable slot (normal, CC, or SPDM-lite). Thus normal-path names may be .fwsignature_ga10x and .fwsignature_ad10x. Exact device-field values actually selected at runtime for the user's GA102/AD102 have not been recorded.

**FUN_1401AB740** invokes the ELF lookup for .fwversion, .fwimage, a dynamically selected signature-section name, and .note.gnu.build-id. It checks the version string for a terminating NUL. It saves image section pointer/length to param_3+2/+3; signature section pointer/length to param_3+4/+5. It allocates a DMA-associated staging buffer at param_2+0xB08 rounded to the signature-section size and copies signature bytes using FUN_1401B9020, FUN_1401BC180, and FUN_1400DF7C0. The build ID is copied to an allocated buffer at param_2+0x69EC0 (size at +0x69EC8). Staging does not prove verification or acceptance.

## Highest-priority new data-provenance lead

The same FUN_1401AB740 calls **FUN_1401AFD60** twice: first after local_a8 is set to param_3[2] (GSP .fwimage pointer), with nearby local_a0 holding its size, destination state param_2+0xB00; second conditional on param_3[8] non-null, after local_a8 is set to param_3[8] (UCODES external-file pointer), with nearby local_a0 set to the length at param_3+9, destination state param_2+0x69F70.

**Decompiler ABI warning:** the printed calls to FUN_1401AFD60 expose only four explicit parameters while local_a8/local_a0 appear prepared immediately before each call. Do not assert the effective parameter bindings, caller stack layout, or copy semantics without examining the callee (or callsite assembly). This is evidence of two staging paths, not proof that the actual Windows SEC2 Booter originates from UCODES or that any signature is accepted. Distinguish 4096-byte GSP ELF signature sections from the pinned Linux production Booter bundles' 768-byte signature records.

## Boot-attempt wrapper

The complete FUN_1401A7840 decompilation shows multiple indirect calls, checks a retry-flag output pointer, responds to nonzero return codes, consults RmGspScanWprEndMargin, and can increment param_2+0x69ED8 and update RmGspBootInitialShift. The indirect target identities are still unknown. These observations do not establish a runtime unlock, firmware verification bypass, or GPU hardware execution.

## Next bounded Ghidra Python 3 command (no full scan, no DB writes)

~~~python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1401afd60"], "__name__": "__main__"})
~~~

Inspect whether FUN_1401AFD60 receives explicit stack arguments from these two sites; then trace the destinations and UCODES record selection. If clipped, report PARTIAL and rerun with evidence-driven DECOMP_FOCUS_TERMS. No firmware, driver, EFI or GPU modification authorized. CAN_DETACH=false, CAN_UNLOCK=false, CAN_FLASH=false.

---

# 2026-11-05 — Windows 617.42 GSP ELF version/image/signature section extraction traced

## Evidence and verification

Two user-executed, read-only PyGhidra reports from the previously verified nvlddmkm.sys 617.42 (MD5 3fb9afac9d0e394723e830aa14e60512, base 0x140000000):

- nvlddmkm-61742-booter-discovery-20261105-112154-719245.txt — SHA-256 aa0b1222732c0cea4922b57be3e0cbb2cf9037fd2b615108a693ed4506fb7a71. Target FUN_1401AB740; total decompiled C 7,207 characters, but broad focused search (param_3, FUN_1401) exceeded the script's 8 matches per term, and the excerpt omitted source lines. STATUS=PARTIAL; excerpt_truncated=True. Meaningful excerpts remain valid; missing lines are unreviewed.
- nvlddmkm-61742-booter-discovery-20261105-112158-471883.txt — SHA-256 578ce9f1dda88a53006c84bff4bb047fa566e96d6ed21dd2518663c0f5d0cbfd. Target FUN_1401A7840; 2,844 C characters, selected term excerpts complete, STATUS=COMPLETE for request, but only excerpts displayed. This does not demonstrate firmware runtime success or full function coverage.

## Major advance: installed Windows GSP ELF is processed by the driver

The composite firmware structure previously populated by FUN_1400F3350 and passed by FUN_1401B0E00 reaches FUN_1401AB740(param_1,param_2,param_3). The observed code:

1. Assigns local_a8=".fwversion" and calls FUN_1401A9AE0(param_1,param_2,*param_3,*(undefined4 *)(param_3+1)), twice in the visible path, with output pointers configured in adjacent local variables. It checks the returned version section is non-null and NUL-terminated; on failure logs an error and returns a nonzero status. Exact function calling convention/extra stack arguments are not fully recovered by the decompiler.
2. Assigns local_a8=".fwimage"; sets output-pointer locations to param_3+2 and param_3+3, and calls FUN_1401A9AE0 again. This strongly supports GSP ELF section discovery with image pointer and length returned into the composite firmware structure, but precise struct types and bounds require inspection.
3. Obtains a section-name prefix via an indirect call through Ghidra's guard dispatch mechanism, then calls FUN_1401AA0E0(param_1,param_2,local_68,0x20). It subsequently passes local_68 as the requested section name to FUN_1401A9AE0 with output locations at param_3+4 and param_3+5. In combination with earlier FUN_140631750 slot +0x938 dispatch, this supports a path for selecting an appropriate GSP ELF .fwsignature_* section, **but the exact indirect target and complete constructed name have not yet been proven at runtime**.
4. Allocates/initializes a DMA-capable resource via FUN_1401B9020, using the newly located section's length rounded up to a 0x100-byte boundary, and invokes mapping helpers (e.g. FUN_1401B87B0 and FUN_1401BC180). This is static code for staging a section; it is not proof of signature authentication or hardware acceptance.

**Important scope distinction:** These sections are from the external Windows GSP ELF. The known 4,096-byte ELF .fwsignature_ad10x / .fwsignature_ga10x are separate from the 768-byte production Booter signature records in the verified Linux archive comparison. This new evidence does **not** identify the signed Windows Booter image, prove it comes from NVUCODES, or demonstrate an unlock sequence.

## Boot-attempt wrapper FUN_1401A7840

The displayed excerpt validates a non-null output flag param_5, clears it, checks several device-context flags, and makes a crucial indirect call with (param_1,param_2,param_3), returning on nonzero error. It also references RmGspScanWprEndMargin in a later conditional branch. The indirect call target and exact semantics of param_3 are NOT resolved; it is not yet supportable to identify it as Booter execution, attestation, signature acceptance, or GSP start without tracing the vtable slot and complete decompilation. The visible excerpt is incomplete even though requested focus matches were covered.

## Required next static evidence

Priority 1: **Full decompilation** of FUN_1401AB740 and FUN_1401A7840, both short enough for the current MAX_DECOMP_CHARS 14,000 limit. Set SCAN_STRINGS=False, do not supply DECOMP_FOCUS_TERMS, and capture complete readable bodies before making data-flow claims:

~~~python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1401ab740", "0x1401a7840"], "__name__": "__main__"})
~~~

Priority 2: Inspect the exact ELF section lookup and generated signature-name helper to determine their input/output contracts. Initial bounded decompilation:

~~~python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1401a9ae0", "0x1401aa0e0"], "__name__": "__main__"})
~~~

Next after these: identify the function-pointer target of the GSP signature-prefix call, the param_3 pointer/size layout, and the origin of Windows 617.42's actual GA102/AD102 Booter image/signature records. No firmware/driver/UEFI changes or hardware execution are authorized by these findings; CAN_DETACH=false, CAN_UNLOCK=false, CAN_FLASH=false.

---

# 2026-11-05 — Firmware-structure validation and GSP ELF signature-prefix vtable slot resolved

## New evidence (two actual Ghidra runs)

Program identity remains `nvlddmkm.sys` 617.42, MD5 `3fb9afac9d0e394723e830aa14e60512`, Ghidra base `0x140000000`. Read-only reports:

- `nvlddmkm-61742-booter-discovery-20261105-111652-902437.txt`, SHA-256 `9a304133da55d6b1b7ee47904ad1d46fab91a1d619fe6746ff601a8721b069cf`: `FUN_1401B0E00` clipped, `FUN_140633180` complete; accurately reports **STATUS=PARTIAL**.
- `nvlddmkm-61742-booter-discovery-20261105-111656-249203.txt`, SHA-256 `0f8d0ea51dc7e3a7df5dee3319aa7d0f77a211bd079e20a7066a273bb959f9c1`: focused `FUN_140631750`, 31,705 decompiled characters, all three requested function-name excerpts retained, **STATUS=COMPLETE** for excerpt coverage (not whole-function visibility).

## GSP file-read structure: stronger data flow and correction

`FUN_1400F1310` calls `FUN_1401B0E00(lVar12, *(...+0x2238), &local_15b8)`, after obtaining GSP and UCODES images from `FUN_1400F3350`. `FUN_1401B0E00` types this third argument as `longlong *param_3`, validates `param_3 != NULL`, `*param_3 != 0` and `(int)param_3[1] != 0` (failure returns `0x1f`), and checks `param_3[6]` in a later branch.

**Correction:** `&local_15b8` was previously described as simply a file-size output; that was inaccurate. The earlier reader's fourth argument points at a pointer-output location, with a distinct fifth stack argument for its size. The decompiler's contiguous locals `local_15b8` and `uStack_15b0` correspond to the leading pointer/size entries passed to `FUN_1401B0E00`. The apparent `param_3[6]` at +0x30 aligns with `local_1588` (optional GSP-log buffer) and `param_3[8]` at +0x40 with `local_1578` (UCODES pointer), assuming the shown stack layout. **Treat that mapping as an inferred layout until all callee accesses are independently checked**, not a validated structure declaration.

The callee forwards the composite `param_3` to **`FUN_1401AB740(param_1,param_2,param_3)`**, then later executes a boot-retry loop using `FUN_1401A7840(param_1,param_2,param_3,local_54)`. Registry/config labels `RmGspBootRetryAttempts` and `RmGspBootInitialShift` are read in this loop; no register modifications are requested or implied by this investigation. This is the strongest observed static consumer chain, **but neither exact UCODES record extraction nor the production Booter image/signature origin has been established**. The `FUN_1401B0E00` decompilation was clipped at 14,000 characters; do not treat its omitted tail as analyzed.

## Signature-prefix dispatch: exact slot and prior source

`FUN_140633180` allocates and initializes a large object, resolves two provider objects `lVar4`/`lVar6`, calls `FUN_140631750(puVar2,lVar4,lVar6)`, then performs later setup and stores the object. It does **not** by itself establish a specific AD102/GA102 device mapping.

The focused `FUN_140631750` excerpt now proves an assignment to **function-pointer slot `param_1 + 0x938`**, chosen among:
- `FUN_140633AA0`: constant normal `.fwsignature_` prefix.
- `FUN_1409211C0`: normal/CC prefix dependent on a context flag.
- `FUN_140922420`: normal/CC/SPDM-lite prefix dependent on context flags.

Branch inputs include the 16-bit fields at `param_2 + 0x10` and `param_3 + 0x10`; the excerpt tests bit masks/architecture-class-like values, **not independently verified Windows GPU hardware IDs**. A separate nearby function-pointer slot `+0x940` selects other providers. Do not equate prefix selection with GSP ELF section parsing, signature authentication, or the production SEC2/Falcon Booter signature records.

## Next high-value, read-only PyGhidra runs

First inspect the earliest composite firmware consumer (existing function, no full string scan):

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1401ab740"], "DECOMP_FOCUS_TERMS": ["param_3", "FUN_1401"], "__name__": "__main__"})
```

Then inspect the boot-loop consumer in a **separate** bounded report:

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1401a7840"], "DECOMP_FOCUS_TERMS": ["param_3", "FUN_1401"], "__name__": "__main__"})
```

Matching many occurrences may intentionally produce `STATUS=PARTIAL` and limited first-eight windows; this is valid partial evidence and must be followed by narrower source identifiers. No firmware execution, device changes, Ghidra DB writes, or active unlock performed. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`.

---

# 2026-11-05 — Ghidra 11:09 reports: firmware handoff and device-specific dispatch

## Evidence provenance and coverage

Read-only Ghidra reports from the exact Windows 617.42 `nvlddmkm.sys` (MD5 `3fb9afac9d0e394723e830aa14e60512`, base `0x140000000`):

- `nvlddmkm-61742-booter-discovery-20261105-110913-832370.txt`, SHA-256 `646880ef7a015510908819d93a9b423d66eb1431813feaac3f4795702667c7a1`: focused `FUN_1400F1310` (full decompiler text length 31,686 characters; selected excerpt windows complete, not the full function).
- `nvlddmkm-61742-booter-discovery-20261105-110917-156584.txt`, SHA-256 `1097d49a2c6432c9784feb49c1303cc4ea094e8266ab84084b963b51728d1b22`: `FUN_140631750`, decompiler C output **clipped=True** at 14,000 characters even though the old script emitted `STATUS=COMPLETE`. Therefore the exposed function body is incomplete.

The prior 11:03 reports had already demonstrated the firmware-buffer allocations, separate GSP/UCODES/log cleanup, wrapper `FUN_1400EF8E0`, and constant fallback prefix provider `FUN_140633AA0`. That earlier review was recorded in a local addendum after a blocked GitHub write; this section integrates those findings into the remote investigation ledger rather than claiming they were already pushed.

## Firmware handoff: new source-to-sink anchor

In `FUN_1400F1310` the file-reading calls produce `lStack_1688` (GSP), `lStack_1678` (UCODES), and conditional `lStack_1670` (GSP logs); buffer lengths/outputs are associated with `&local_15b8`, `&local_1578`, and `&local_1588`. A later branch includes the exact decompiled statement:

```c
iVar7 = FUN_1401b0e00(lVar12, *(undefined8 *)(lVar12 + 0x2238), &local_15b8);
```

This establishes that an address previously supplied to the **GSP** file reader is passed to `FUN_1401B0E00` during later initialization. The report does **not** show the full intervening branch conditions or demonstrate that its third argument is itself a raw image pointer: it may address a compound length/buffer output layout. Earlier string evidence links `FUN_1401B0E00` with `RmGspBootRetryAttempts`. Next step: inspect the callee's argument interpretation and how the GSP/UCODES structures are consumed before assigning it a firmware-loader identity.

## Architecture/device dispatch table: distinct from cryptographic validation

`FUN_140631750(param_1,param_2,param_3)` extracts 16-bit fields at `param_3+0x10` and `param_2+0x10`, then uses shifts, masks and hardware-class-dependent conditions to choose many function pointers stored into `param_1+0x728`, `+0x730`, `+0x738`, `+0x740`, and subsequent slots. An existing direct caller is `0x14063349A`; there are additional data XREFs at `0x1414188C0`, `0x141091E84`, `0x141091E9C`, `0x141091EB0`, and `0x141091EC0`.

The submitted address `0x140632E8B`, previously identified as a cross-reference to signature-prefix provider `FUN_140633AA0`, lies inside this dispatch initializer. Therefore the signature provider is selected through an architecture-dependent dispatch mechanism **in the driver**, but the specific AD102/GA102 branches, runtime-selected provider, ELF-section bytes and authentication are **not yet established**. As these references can be data/function pointers, direct runtime calls are not implied.

## Corrected evidence reporting

The earlier implementation wrongly treated un-focused, clipped decompiler output as `COMPLETE`. The script now sets `all_targets_completed=False`, logs `DECOMPILER_OUTPUT_INCOMPLETE=TRUE`, and yields `STATUS=PARTIAL` for a clipped ordinary decompilation. Two tests cover both clipped and unclipped real targeted-decompilation paths with mocked Ghidra APIs: the clipped test **fails against the former script** and passes after correction; all **18/18** host tests across both Ghidra test modules pass, and Python compilation succeeds. Real execution of the corrected script remains pending.

## Next two non-mutating Python 3 Ghidra commands

**1. Inspect the GSP handoff callee and dispatcher caller (existing functions only):**

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1401b0e00", "0x14063349a"], "__name__": "__main__"})
```

**2. Read only the relevant provider assignments inside the giant dispatch initializer:**

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x140631750"], "DECOMP_FOCUS_TERMS": ["FUN_140633aa0", "FUN_1409211c0", "FUN_140922420"], "__name__": "__main__"})
```

The second command may legitimately report `PARTIAL` if excerpts are capped or no selected term occurs. Never infer successful decompilation from script termination alone. No firmware/GPU/Ghidra DB mutation. The exact Windows Booter location, image/signature record identity, production authorization and safe recovery remain **OPEN**; `can_detach=false`, `can_unlock=false`, `can_flash=false`.

---

# 2026-11-05 — Firmware source-to-reader initialization, GA10X Falcon HS loader, GSP signature-prefix decisions (two Ghidra reports)

## Primary artifacts and identity

- `nvlddmkm-61742-booter-discovery-20261105-105447-498365.txt`: SHA-256 `70b261c69f735587f5dfbfa40eb8b8e6fd82053d5cca9c159b9f83879ed4a550`; targeted entries `0x1400F1310` (truncated, **clipped=True**) and `0x140BF3880` (full, **clipped=False**).
- `nvlddmkm-61742-booter-discovery-20261105-105502-046855.txt`: SHA-256 `1c2c5de076ed6183b611b5d73720c98cac1212d7a4484c1aa2b100a5a1c49dcb`; targeted entries `0x1409211C0`, `0x140922420`, both **clipped=False**.
- Both reports confirm `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512` and Ghidra image base `0x140000000`; no hardware or Ghidra DB mutation. Report status COMPLETE means the targeted decompiler ran; **a clipped=True excerpt is not a complete static analysis of that function**.

## Windows firmware path: stronger proven chain

`FUN_1400F1310` calls `IoQueryFullDriverPath(DAT_1413C8F00,...)`, walks backward to the containing directory separator, and requests firmware buffers via the established `FUN_1400F3350` file reader:

- `FUN_1400F3350(0,cVar3,&uStack_1660,&local_15b8)` at displayed call around `0x1400F1826`: GSP image `gsp_ga10x.bin` or `gsp_tu10x.bin` for the family selected by `cVar3`.
- `FUN_1400F3350(2,cVar3,&uStack_1660,&local_1578)` at displayed call around `0x1400F1847`: UCODES image `ucodes_ga10x.bin` or `ucodes_tu10x.bin`.
- `FUN_1400F3350(1,cVar3,&uStack_1660,&local_1588)` at displayed call around `0x1400F1899`: conditional `gsp_log_ga10x.bin` or `gsp_log_tu10x.bin`.
- For the initial two reads, the shown function checks that both returned pointers are nonzero before following a common path. It also contains fallback/alternate flags, so **the real runtime behavior per GPU remains unverified**.
- The same function reads `EnableGpuFirmware` (shown default `0x12`) and `EnableGpuFirmwareLogs` (shown default `2`), with subsequent masking and helper calls. These are **observed code defaults**, not instructions to modify registry settings.
- A chip/family bucket is computed from `uVar8` and a revision nibble; the switch selects small numeric internal family IDs that ultimately select filenames. **The exact mapping of AD102/GA102 silicon to these IDs has not been verified from this report.**
- **Critical current blocker:** `FUN_1400F1310` decompilation was clipped at the first 14,000 characters. Although the three buffer acquisitions appear, their **later consumers, firmware handoff, Booter source, and per-GPU selection** are not in the visible excerpt. Do not infer they are already established.

## Falcon/SEC2 high-security binary execution implementation confirmed at static code level

`FUN_140BF3880` references `flcnLoadAndExecuteHsBinaryViaDma_GA10X` in six control locations and is **not merely a string-printing function**. It consumes a firmware image/descriptor-like argument `param_3`, conditionally creates/mounts a DMA-capable buffer, handles state/controls, transfers data in 0x100-byte increments through the helper `FUN_1406B6470` with register offsets **0x114, 0x11C, 0x118**, and calls several other Falcon control/execute helpers. The routine prepares and performs a high-security binary load/execute sequence in the *static driver logic*. It **does not prove** the image in `param_3` is the production GSP Booter, a matching signed image, or accepted by hardware.

Known **data** references to its function entry (not directly established callsites): `0x141469320`, `0x140E19A0C`, `0x1417E8E3E`, `0x1417E8E45`. These are potential dispatch table/object provenance anchors. Trace the *producer* of `param_3` before assigning any Booter identity. Never call or run a hardware-affecting helper in Ghidra.

## GSP ELF signature section *name selectors*, not crypto verifiers

- `FUN_1409211C0(param_1)` returns `.fwsignature_` by default, switches to `.fwsignature_cc_` when the pointer at `param_1 + 0x2690` is non-null and the byte at that pointer's `+0x249` is nonzero.
- `FUN_140922420(param_1)` returns `.fwsignature_cc_` if `FUN_14011D9F0()` is nonzero; otherwise returns `.fwsignature_spdm_lite_` when a pointer at `param_1 + 0x2688` is non-null and a byte at its `+0x111` is set; otherwise `.fwsignature_`.
- Both are short string-returning functions; neither excerpt contains cryptographic verification or complete architecture-suffix resolution. Their data XREFs around `0x140632E6E`, `0x140632E75`, `0x140632EB1`, `0x140632EB8` suggest dispatch/table linkage, which is **unproven without consumer analysis**. `FUN_140633AA0` is another owner of `.fwsignature_` and is a practical next decompilation target.
- Keep GSP ELF `.fwsignature_ad10x` and `.fwsignature_ga10x` (each 4,096 bytes in the installed GSP file) **separate** from Booter bundle signature records (768 bytes in the Linux reference containers).

## Focused Ghidra follow-up implementation and strictly bounded commands

The earlier script's flat first-14,000-character clipping concealed later `FUN_1400F1310` buffer uses. The existing read-only discovery script is extended with optional `DECOMP_FOCUS_TERMS` (1–8 short literal terms), which emits line-numbered source-code excerpts around matches from the **complete decompiled C string**, with a 14,000-character output limit, explicit term match counts, and PARTIAL status when requested evidence is absent or excerpt windows are omitted. It makes **no Ghidra project changes**, no new decompilation assumptions, and does **not** constitute complete control-flow proof. Four added host-side tests cover later occurrences, missing terms, bounded repeated matches, and invalid input. Together with existing tests, **16/16 local tests passed**; Ghidra execution of this new mode still pending.

**A — Follow the three file buffers after acquisition, without another full memory scan:**

~~~python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1400f1310"], "DECOMP_FOCUS_TERMS": ["lStack_1688", "lStack_1678", "lStack_1670", "FUN_1400f3350"], "__name__": "__main__"})
~~~

**B — Independent ELF section-consumer and GSP boot-path tracing, existing short-function mode:**

~~~python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x140633aa0", "0x1400ef940"], "__name__": "__main__"})
~~~

The second command addresses a GSP ELF signature-prefix reference owner and the sole existing direct caller of the long firmware initialization function. Their behavior is not established until these reports are reviewed. Do not repeat the large 114 MB scan or the already completed decompilations of `FUN_140BF3880`, `FUN_1409211C0`, or `FUN_140922420` unless subsequent evidence requires it.

**Remaining proof gates:** actual Windows selected Booter image/header/signatures and their binary source, SEC2/ACR handoff provenance, AD102 versus GA102 dynamic dispatch, GSP signature authentication and firmware boot acceptance, passive dual-GPU pre-Stop safety and recovery. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`.

---

# 2026-11-05 — Exact CSV XREF pass and Windows firmware-file reader confirmed

## Primary evidence

User-supplied read-only Ghidra report: `nvlddmkm-61742-booter-discovery-20261105-105008-896070.txt`, local SHA-256 `9cfac4af69a9f2a6a713277a939f2463f7788789ce3c1503f9f27a33dc295ffc`. Program identity `nvlddmkm.sys`, MD5 `3fb9afac9d0e394723e830aa14e60512`, image base `0x140000000`. The report shows `SCAN_STRINGS=SKIPPED_BY_CALLER`, 18/18 exact CSV labels verified in initialized Ghidra memory, 14 pre-existing XREF-owner functions, one requested function successfully decompiled without clipping, `STATUS=COMPLETE` for the bounded investigation. No database writes or hardware operations.

## Newly established loader path

1. `FUN_1400F35F0` (prior evidence): chooses a TU10x or GA10x GSP/log/UCODES filename and constructs a Unicode path; selection parameter semantics remain to be proven at the caller.
2. **`FUN_1400F3350` (new evidence): file-backed loader**. Calls `FUN_1400F35F0` and, on success, uses `ZwCreateFile` (observed `0x80000000` requested access), `ZwQueryInformationFile` to obtain the size, `FUN_1400FF170` for allocation, then `ZwReadFile`. The function has error-path buffer freeing and file-handle closing, and on a successful read returns a buffer-like pointer. Decompiler declared `FUN_1400F3350(void)` but also exposes unknown entry registers/stack parameters (`in_R9`, `in_stack_00000028`), so **actual ABI, input firmware class/architecture parameters and complete output validity are not established**. Do not infer all file reads succeed at runtime or that this routine itself decodes/executes a Booter.
3. Existing caller references to `FUN_1400F3350`: `0x1400F1826`, `0x1400F1847`, `0x1400F1899` (all unconditional calls), plus a data XREF at `0x1413D4F34`. **Next trace should decompile the Ghidra-defined function containing `0x1400F1826`** to distinguish the three file types and downstream byte consumers. All three callsites may be inside the same owner; this has not yet been checked.

**Result scope:** Windows has a concrete external file read path for the GSP/UCODES family named by the helper. It remains **UNKNOWN** whether exact production AD102/GA102 Booter image/header/signature bytes are inside `nvlddmkm.sys`, `ucodes_ga10x.bin`, another package asset, or are retrieved via more than one source. The separately identified `gsp_ga10x.bin` ELF 4096-byte signature sections are **not** interchangeable with the reference Booter bundles' 768-byte signature data.

## Refined cross-reference ownership from 18-address CSV pass

| Ghidra function entry | XREF evidence in supplied report | Current disposition |
|---|---|---|
| `0x140BF3880` | Six XREFs to `flcnLoadAndExecuteHsBinaryViaDma_GA10X`, string VA `0x140D2EAE0` | High-value SEC2/Falcon HS execution lead; next targeted decompilation to establish whether it handles production Booter data, not assumed. |
| `0x1409211C0` | `.fwsignature_` and `.fwsignature_cc_` | Candidate GSP ELF signature-section selection; inspect inputs and ELF linkage. |
| `0x140922420` | `.fwsignature_`, `.fwsignature_cc_`, `.fwsignature_spdm_lite_` | Candidate ELF signature variant selector; do not presume authentication. |
| `0x140633AA0` | `.fwsignature_` | Lower-specificity extra section-string owner, retained. |
| `0x140AF28A0` | `RMAcrExecuteOnSec2`, `RMEnableAcrRiscv`, `RmBootFromHs` | Config/SEC2 lead, pending actual code review. |
| `0x140336020`, `0x140577EC0` | `RmBootFromHs` and disable-load registry labels | Config lookup leads, not verified bypass mechanisms. |
| data `0x1411A7298`, `0x1411A72A0` | `GSP_LOAD_EXEC_GENERIC_BOOTLOADER`, `GSP_LOAD_EXEC_HS_BINARY` | Only data references, owner UNKNOWN; should trace associated table *only after* concrete loader leads. |

The dedicated CSV pass did not discover a known owning function for `Invalid Bindata Access` (`0x1411A66F8` data XREF). A data XREF without function ownership does not prove the driver embeds any named Booter archive.

## Next Ghidra commands (existing script, no full memory scan)

First: follow the three known file-read callsites via one inside-function address, and inspect the GA10x HS loader lead:

~~~python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1400f1826", "0x140bf3880"], "__name__": "__main__"})
~~~

Second, after interpreting the first: inspect the two GSP ELF signature-section owners as a *separate* investigation:

~~~python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1409211c0", "0x140922420"], "__name__": "__main__"})
~~~

Execution uses only existing Ghidra functions, caps each decompilation at 12 seconds and output at 14,000 characters. If clipped, the report's `clipped=True` marks incomplete visible decompiler evidence even if a script status otherwise says COMPLETE. Preserve report paths and original output. No EFI/driver mutation or firmware execution. `can_detach=false`, `can_unlock=false`, `can_flash=false`.

---

# 2026-11-05 — Full 617.42 Ghidra string-inventory review and corrected function classification

## Exact inputs and parsing scope

- User-uploaded Ghidra Defined Strings export: `nvlddmkm-strings.csv`, 1,664,655 bytes, SHA-256 `74334659126c3f5fea4372590f1d50d238a4b44b9728afa4a622768d1075ded1`; **14,419 CSV records**. Use Python `csv.DictReader(..., escapechar='\\')` because this Ghidra CSV escapes quotes with backslashes, not conventional doubled quotes. The export contains **25 anomalous field parses** (mostly data-looking short strings); those rows should not be promoted without reinspection. The 18 selected ASCII labels and VAs below were individually verified as exact CSV pairs, **18/18**.
- User-uploaded targeted Ghidra decompilation: `nvlddmkm-61742-booter-discovery-20261105-103527-173279.txt`, SHA-256 `3bee4f00ed92a5781f7a4b5a1e7b1e8f1edc9b0f5c34efe8549c8bd2ec074122`; the report completed its two requested decompilations, but the second was output-capped and carried dead-code/restart warnings.
- Program identity remains Windows 617.42 `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, Ghidra base `0x140000000`. CSV addresses are loaded-image **virtual addresses**, not raw PE file offsets.
- Defined Strings export is not a completeness proof over compressed blobs, unrecognized binary archive data, or string types Ghidra did not define.

## Corrected classification from actual decompiler output

1. **`FUN_1400F35F0` = firmware filename/path-construction helper**, not yet a Booter-image loader. For family selector `param_2=1..3`, `param_1=0,1,2` chooses `gsp_tu10x.bin`, `gsp_log_tu10x.bin`, or `ucodes_tu10x.bin`. For `param_2=4,5,6,8,9,10,11,12`, it chooses `gsp_ga10x.bin`, `gsp_log_ga10x.bin`, or `ucodes_ga10x.bin`. The function converts the selected filename to Unicode, allocates a destination and appends it to an input base path. This verifies family-to-filename behavior, but the semantics of the numeric selector, exact GPU type and actual file reads remain unverified. **First callsite to inspect: `0x1400F338E`**, an existing unconditional caller inside its owning function, then trace the output path consumer.
2. **`FUN_1415A8FB0` is a display-manager diagnostic serialization routine** (high confidence for the visible portion), not evidence of GSP/Booter dispatch. Its `CDisplayMgrInfo`, `CDisplayMgrDataPart_*`, `m_pDispDbg->pDispGA102`, `m_pDispDbg->pDispAD102`, `CNvDisplay_Ampere_GA102`, and `CNvDisplay_Ada_AD102` strings are selected while building display diagnostic data. The output is clipped and decompiler reports warnings, so do not assert the function could never touch firmware in unseen code; **deprioritize for production Booter provenance**.
3. Generic `SEC2`, `FALCON`, `FWSEC` and `GSP-RM` references remain leads requiring data-flow attribution, not identified loaders.

## New high-signal string anchors from the 14,419-record inventory

| VA | Exact exported string | Investigative scope / caution |
|---|---|---|
| `0x140D2EAE0` | `flcnLoadAndExecuteHsBinaryViaDma_GA10X` | High-priority named Falcon/HS-binary execution diagnostic. Only a literal until code XREF is found. |
| `0x140D09070` | `GSP_LOAD_EXEC_GENERIC_BOOTLOADER` | GSP load-execution operation name; could be an RPC enum name, not host loader code. |
| `0x140D090A0` | `GSP_LOAD_EXEC_HS_BINARY` | Second GSP-load-execution operation name; seek XREF owner. |
| `0x140D150B0` | `.fwsignature_` | Generic GSP ELF signature-section selection pattern; distinct from Booter bundle's 768-byte signatures. |
| `0x140D1D760` | `.fwsignature_cc_` | Confidential-computing GSP ELF signature-prefix variant. |
| `0x140D1D780` | `.fwsignature_spdm_lite_` | Additional GSP ELF signature-prefix variant. |
| `0x140D1D740` | `RmBootGspRmWithBoostClocks` | Registry/configuration label related to GSP boot; not itself a boot call. |
| `0x140D2C4C0` | `RMAcrExecuteOnSec2` | SEC2/ACR execution configuration or diagnostic clue. |
| `0x140D06B60` | `RMExecuteFwsecOnSec2` | FWSEC-on-SEC2 execution configuration/diagnostic clue. |
| `0x140D0CE10` | `RmBootFromHs` | Boot-mode registry/configuration clue. |
| `0x140D2C520` | `RMEnableAcrRiscv` | ACR/RISC-V configuration string. |
| `0x140D12550` | `RmDisableGspLoad` | Configuration string; does not establish bypass. |
| `0x140D0CD10` | `RmDisableSec2Load` | Configuration string; does not establish bypass. |
| `0x140E557F8` | `Invalid Bindata Access` | Generic error-string lead; does not prove location of Booter archive. |
| `0x140D17030` | `flcnLoadUcode_GM107` | Older generation code symbol string, lower priority for GA102/AD102. |
| `0x140D09BB0` | `RmGspBootRetryAttempts` | GSP boot retry configuration; interpretation requires caller. |
| `0x140D04330` | `gsp_ga10x.bin` | Already-proven filename builder `FUN_1400F35F0`. |
| `0x140D04360` | `ucodes_ga10x.bin` | Already-proven filename builder `FUN_1400F35F0`. |

Additional contextual labels include `GSP firmware fault detected`, `RmDisableGsp`, `RmGspBootInitialShift`, `SEC2-RISCV`, `lsfmFalconReset_IMPL`, and `RMGspLoad*`-adjacent status names; these do not override the ranking above. **No defined CSV string contains `booter` or `NVUCODES`**, and no exact `kgspGetBinArchiveBooterLoadUcode` name was found in this CSV. This **does not** prove their compiled implementation or binary data is absent.

## Next read-only Ghidra pass

The existing `research/ghidra/nvlddmkm_booter_discovery.py` has an opt-in `SCAN_CSV_LEADS=True` mode. It checks the *exact ASCII bytes* at all 18 fixed CSV virtual addresses under the driver MD5/base identity gate, reuses the already-bounded Ghidra XREF/function-owner reporter, and does **not** rescan 114 MB or create code/data. An unexpected string or uninitialized block refuses with `STATUS=ERROR`. The script has four newly added host-only tests (4/4 pass), local syntax compilation, and 18/18 exact exported CSV address/literal validation. Ghidra execution pending.

Ghidra Python 3 console command, after updating fork main:

~~~python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "SCAN_CSV_LEADS": True, "TARGET_FUNCTIONS": ["0x1400f338e"], "__name__": "__main__"})
~~~

The caller address `0x1400F338E` is supplied as an **inside-function address**; the existing Ghidra function manager will resolve its owner. If it is undefined or cannot be decompiled, status must be PARTIAL, never a fabricated completion. The exact CSV anchor XREFs are printed to a timestamped report, not automatically declared proven. Use that report to choose further narrow decompilations, particularly code owners for the Falcon/HS and GSP execution strings. No Windows production Booter bytes, algorithm, signature acceptance, EFI safety or hardware recovery are established. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`.

---

# 2026-11-05 — Two uploaded reports reviewed; Windows Booter candidate triage

## Exact input evidence

- Full scan: nvlddmkm-61742-booter-discovery-20261105-100845-857761.txt; SHA-256 16a125aef649df811adb2af831234ddd1cb0b72ee63972e9cc8dda400ac3f778.
- Targeted attempt: nvlddmkm-61742-booter-discovery-20261105-101049-266126.txt; SHA-256 b652ed8ccdbbcbb6342781ab9e6a4139f4c086f8f75069f3574994a7b4d5d2a0.
- Exact Windows binary identity: nvlddmkm.sys 617.42, MD5 3fb9afac9d0e394723e830aa14e60512, Ghidra image base 0x140000000.
- Complete read-only scan: 33 initialized blocks out of 34; 114,516,048 bytes scanned; 38 bounded string hits recorded; 28 existing function owners. Counts: SEC2 37, FALCON 12, GA102 3, GSP-RM 2, FWSEC 2, AD102 2, bindata 1, and one each for gsp_ga10x.bin, ucodes_ga10x.bin, gsp_tu10x.bin, ucodes_tu10x.bin.
- No raw matches for literal BooterLoadUcode, kgspGetBinArchiveBooterLoadUcode, GspRmBoot, BINDATA_LABEL_IMAGE_PROD or BINDATA_LABEL_SIG_PROD. Absence does not prove that compiled or compressed Booter data is missing.

## Ranked candidate functions

| Rank | Entry VA (Ghidra) | Grounded string/XREF evidence | Investigation hypothesis, not proof |
|---|---|---|---|
| 1 | 0x1400F35F0 | Four DATA references: gsp_ga10x.bin at 0x1400F3668, ucodes_ga10x.bin at 0x1400F3656, gsp_tu10x.bin at 0x1400F3694, ucodes_tu10x.bin at 0x1400F3682 | Firmware-file selection/inventory/open helper. Establish whether it obtains bytes or merely logs filenames. |
| 2 | 0x1415A8FB0 | GA102 string XREFs 0x1415A9836 / 0x1415A984F; AD102 XREFs 0x1415A9A6C / 0x1415A9A85; underlying strings in PAGE_DD | Cross-architecture lead; may be actual dispatch, a diagnostic, or static enumeration. |
| 3 | 0x1401858E0 | FWSEC/SEC2 XREFs 0x140185CE6 / 0x140185D2E | Secure firmware/SEC2 lead, not automatically GSP Booter. |
| 4 | 0x140BF4F00 | Five XREFs to GA102 string at 0x140D2EAD9 | GA102-specific lead; AD102 counterpart unknown. |
| Reserve | 0x1400FFAB0, 0x1401AAA20, 0x14027A2F0, other SEC2/FALCON candidates | Lower-specificity generic GSP-RM, SEC2, FALCON matches | Deprioritize until caller or data-flow evidence justifies them. |

The bindata string VA 0x140E55800 has DATA reference 0x1411A66F8 with function owner UNKNOWN; no Booter archive is proven. Some literal strings reside inside sections called .text; their VA is not a function address.

## Second report status and corrective implementation

Targeted attempt supplied 0x140D0C790, not one of the 28 candidate function entries. Ghidra reported TARGET_NOT_DEFINED VA=140d0c790, so no function was decompiled. Original STATUS=COMPLETE misleadingly represented successful script termination rather than successful targeted analysis. New common script returns PARTIAL if any requested target has no existing Ghidra function or its decompilation fails, and logs TARGETS_COMPLETE=FALSE. This is a reporting fix; the earlier full-scan coverage result remains COMPLETE. Eight host-side synthetic tests passed, including the regression and a no-target control; real corrected PyGhidra run remains pending.

## Next execution — start with only two concrete addresses

With the verified driver open in Ghidra Python 3, run this single console command (no full rescan):

~~~python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1400f35f0", "0x1415a8fb0"], "__name__": "__main__"})
~~~

After reading that report, if needed, separately inspect 0x1401858e0 and 0x140bf4f00. Each decompilation is capped at 12 seconds and 14,000 characters; existing functions only, no analysis/disassembly/database mutations.

Evidence needed next: defined functions, incoming callers, file I/O API resolution, data-source and firmware-container provenance, per-architecture selector branch, and actual selected production Booter image/header/signature bytes before any independently hashed comparison. Matching filenames or Linux reference hashes do not establish runtime selection or firmware signature acceptance. Active unlock, detachment, flashing, GSP/SEC2 execution and EFI changes are blocked.

---

# 2026-11-05 — First Windows 617.42 Ghidra scan completed; console cleanup defect isolated

**Evidence supplied by user (Ghidra Python 3 console):** current program `nvlddmkm.sys`, MD5 `3fb9afac9d0e394723e830aa14e60512`, base `0x140000000` matched the original investigation identity gate. The first read-only discovery run scanned **114,516,048 bytes** with `SCAN_COMPLETE=True`, recorded **38** bounded string matches, and identified **28** candidate function owners. A timestamped report was successfully written to `D:\Projects\gpu-unlock\ghidra\nvlddmkm-61742-booter-discovery-20261105-100845-857761.txt`; the user's transcript shows `STATUS=COMPLETE` and the report path.

**Post-run defect (script-only):** immediately after final status reporting, `sys.stdout.flush()` raised `AttributeError: 'proxy.PyConsole' object has no attribute 'flush'`. This does **not** invalidate the already-completed scan or prove any Ghidra data corruption. The shared script was corrected by deleting the unnecessary flush and unused `sys` import. A console-stub regression test was shown failing against the old script because of the exact missing method, then passed after correction; **6/6** local tests and Python compilation pass. Windows/Ghidra verification of the corrected script is still pending. No hardware or Ghidra database modifications.

**Candidate status:** 38 recorded matches are bounded hits, not verified production Booter artifacts; 28 candidate function owners are string-XREF leads, not confirmed loader functions. The full report has not been supplied, so exact `TERM_COUNT`, `STRING_MATCH`, `XREF` and `CANDIDATE_FUNCTION` rows cannot yet be reviewed or promoted. **Next action:** preserve and upload the existing report (do not rerun just to address the flush traceback), then rank candidates using source and cross-reference provenance and decompile at most four justified targets in targeted read-only mode. Windows production Booter origin, architecture selector and signature acceptance remain **unverified**; `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`.

---

# Windows 617.42 production Booter provenance — Ghidra investigation

**Started:** 2026-11-05  
**Scope:** Read-only analysis of stock Windows `nvlddmkm.sys` 617.42, with follow-up to `ucodes_ga10x.bin` if the driver obtains Booter content externally.  
**Primary target:** RTX 4090 AD102 (`01:00.0`) and RTX 3080 12 GB GA102 (`04:00.0`).  
**Status:** `FIRST_PASS_GHIDRA_REPORT_PENDING`. No exact Windows production Booter address, selection function, embedded image, or comparison hash has yet been established.

This document is the **detailed, turn-by-turn investigation ledger** for the Windows Booter reverse engineering workstream. Prepend new concrete evidence here as reports arrive; retain prior entries as history. The cumulative `nvidia-tensor-core-unlock-investigation-*.md` records only the high-level finding, state, and link to this ledger. The authoritative `nvidia_unlock_evidence_to_execution_map_*.md` records any change to the implementation gates. Do not modify the immutable `windows_gpu_unlock_process_and_recovery_audit_2026-11-04.md` absent a genuine factual error.

## 1. Precise questions and acceptance criteria

| Question | Evidence required to close it | Current state |
|---|---|---|
| **Source of Windows production Booter data** | Follow a specific 617.42 data provider or `nvlddmkm.sys` address to an embedded PE range **or** a proved external package-file read and identify which file and offsets supply the bytes | OPEN |
| **Which path handles AD102 versus GA102** | Bounded Ghidra caller-to-callee trace identifying architecture/device selection and the two effective data/archive pointers; indirect calls require resolved function-pointer provenance | OPEN |
| **Production versus debug choice** | Specific conditional input, selected image, header, signature data, and evidence of the selected branch; do not infer from a string or upstream Linux source | OPEN |
| **Exact production bytes** | Reconstruct a bounded, unmodified image (and header/signature/patch metadata separately), retain offsets and independent SHA-256s for each architecture | OPEN |
| **Comparison to published reference assets** | Compare the recovered *same component* against pinned 610.43.03 and 615.78.08 reference hashes; if neither matches, report both false and keep exact Windows identity unresolved | OPEN |
| **Actual Windows runtime execution / signature acceptance** | Separate driver trace/hardware evidence, not static Ghidra presence or source-level analogy | OPEN / outside static phase |

A raw literal, string match, `Ghidra` symbol, section size, or PE address is **discovery evidence only**. It does not close the loader-selection, firmware authentication, or runtime branch gates.

## 2. Pinned starting evidence

- **Ghidra target:** previously analyzed `nvlddmkm.sys`, `MD5=3fb9afac9d0e394723e830aa14e60512`, image base `0x140000000` (loaded-image virtual addresses). This identification comes from earlier project Ghidra reports. Verify both on every run. Do not import a different `nvlddmkm.sys` and silently use this program's addresses.
- **Stock installer:** NVIDIA Windows 617.42 signed package SHA-256 `f115c92760f1d677ae88f7ee114be20c10ef28a9e725736821a08218054867ca`; its `Display.Driver/nvlddmkm.sys` member has size 113,971,432 bytes. The installed and extracted GSP/UCODES files were shown byte-identical; this alone does **not** show that the Ghidra-imported `nvlddmkm.sys` is byte-identical to the installer member. MD5 verification in Ghidra is the current imported-image identity.
- **Installed GSP:** `gsp_ga10x.bin`, 27,043,992 bytes, SHA-256 `f89d8f615e6146ed2808df974b7af7f1aabda876596391b0aabcc32ba293c34f`; ELF `.fwversion=615.78.05` matches both GPUs' reported GSP firmware. The GSP ELF contains **4,096-byte** `.fwsignature_ad10x` and `.fwsignature_ga10x` sections, which are **not** the production Booter bundle's **768-byte** signature records.
- **Installed UCODES:** `ucodes_ga10x.bin`, 58,215,936 bytes, SHA-256 `eed53d76248582d71c629e8b6230aee48ce673c91d782301c94e98ac6a6db7aa`; `NVUCODES` v1, 1,293 bindata indices, fingerprint `0x2d38befecdb703a6`. An automated Windows report found the same eight fingerprint bytes **once** within GSP `.fwimage` at absolute file offset 17,492,248. This is static pairing evidence, **not** runtime firmware acceptance.
- **Published reference source:** NVIDIA Linux `NVIDIA-kernel-module-source-615.78.08.tar.xz`, independently verified archive SHA-256 `17b4f3d195a5ab1fad9aa1f195c9d3a4ad03aceda18bb9fb68a8bd33d7a000f6`. The exact **Windows GSP 615.78.05 Booter identity is unknown**. Never relabel the Linux reference as installed Windows firmware.
- **Reference component comparison, user-executed on Windows, 15/15 synthetic tests and real `STATUS=COMPLETE`:** Between pinned 610.43.03 and Linux 615.78.08, both AD102 and GA102 production Booter **image**, 72-byte research metadata **wrapper**, and appended 768-byte **signatures** differ by SHA-256. Both GSP boot images and both 84-byte GSP boot descriptors match byte-for-byte between those *two Linux releases*. Earlier reports are retained at `D:\Projects\gpu-unlock\boot-assets-610-vs-615-reference-v2.json`.

### Relevant pinned reference hashes

| Component | 610.43.03 | Linux 615.78.08 |
|---|---|---|
| AD102 Booter **image** SHA-256 | `83e06ccd394eb73ab9e599a6db23be01e0df307d3ec4cfd64fa9499837a402da` (56,832 bytes) | `a41100ea9b3b5319a79bdb57a2ed87e1619a2f36fa665cebc6e80552a53c9697` (57,600 bytes) |
| AD102 Booter **signature records** | `11d6c63d7cbcf60f9d2d3cf1a1ea3f248b718fc99882d11fb0d6396cb58fc516` | `140098e194272cf85008b66774ce2cb6674e8a606d4f9ccdc0d7fe9b6e24e06a` |
| GA102 Booter **image** SHA-256 | `6803188fef6bd352f7ab47b2cf13e18175ac3f12243fa6afae7c4e2872f246f0` (60,416 bytes) | `06f381257dec9e230dc03f658f1546c695ad2e41de2448223618d00b1197f5cd` (60,928 bytes) |
| GA102 Booter **signature records** | `4db5a10949e475df7ecc011e34229895b296653cd401f6d88396ae00412cf0ea` | `0f931210e7c19aeb52aee29ff04cee0f96b81a60f18124a4216802bccc9d2272` |
| AD102 GSP boot image | `45d6335a8185d6ff13e8d1484cea73f68d3d13aa1c19dc080ed1c3482dd5bac0` | Identical |
| GA102 GSP boot image | `3df651acb174fd5f5561a1996965b192f50c5d763168446ed0d4ead19d895768` | Identical |

Be precise when comparing: a research `booter_load_*.bin` **bundle** is 72-byte wrapper + image + signatures. Its SHA-256 is not the SHA-256 of the bare production image or a compressed bindata array in the PE.

## 3. Source-code reference call chain (Linux 615.78.08, **not** Windows proof)

The public OS-agnostic NVIDIA source provides a targeted vocabulary for searching stripped Windows code:

1. `src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c`: `kgspAllocateBooterLoadUcodeImage(...)` allocates `pBooterLoadUcode` when needed. Public source near line 5622.
2. `src/nvidia/src/kernel/gpu/gsp/kernel_gsp_booter.c`: `kgspAllocateBooterLoadUcodeImage_IMPL` obtains `kgspGetBinArchiveBooterLoadUcode_HAL(pKernelGsp)` and passes the archive into `s_allocateUcodeFromBinArchive`; source near lines 437–452.
3. The shared loader in `kernel_gsp_booter.c` checks `kgspIsDebugModeEnabled_HAL` and selects `BINDATA_LABEL_IMAGE_PROD`, `HEADER_PROD`, and `SIG_PROD` in the non-debug branch. Additional patch signature/location/metadata and number-of-signatures entries are separately retrieved. The production choice and signature patching must be established independently in the Windows implementation.
4. **Separate path:** `src/nvidia/src/kernel/gpu/gsp/arch/ampere/kernel_gsp_ga102.c` selects `GspRmBoot` image + descriptor labels. Do **not** confuse this GSP bootloader path with the SEC2 Booter *load* archive.
5. `src/nvidia/generated/g_bindata_kgspGetBinArchiveBooterLoadUcode_{AD102,GA102}.c` contains the published architecture-specific bindata. In 615.78.08 the compressed arrays use `NvU64` words (little endian). The source label names may be stripped from Windows `nvlddmkm.sys`; absence of text does not prove absence of firmware data.

Source links:

- https://github.com/NVIDIA/open-gpu-kernel-modules/blob/615.78.08/src/nvidia/src/kernel/gpu/gsp/kernel_gsp_booter.c
- https://github.com/NVIDIA/open-gpu-kernel-modules/blob/615.78.08/src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c
- https://github.com/NVIDIA/open-gpu-kernel-modules/blob/615.78.08/src/nvidia/src/kernel/gpu/gsp/arch/ampere/kernel_gsp_ga102.c
- https://github.com/NVIDIA/open-gpu-kernel-modules/blob/615.78.08/src/nvidia/src/kernel/core/bin_data_pvt.h

## 4. Investigation procedure

**First run — bounded passive discovery:** Open the previously analyzed 617.42 `nvlddmkm.sys` in Ghidra 12.x Python 3/PyGhidra. Do **not** open `IMG00.BIN` or `IMG01.BIN`; the example GOP script is used only as a model for read-only status reporting. In the Ghidra Python console, execute:

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "__name__": "__main__"})
```

The script checks expected MD5 and loaded image base, enumerates existing memory blocks, scans initialized blocks for bounded ASCII/UTF-16 Booter/GSP indicators (including strings not yet defined by analysis), lists existing Ghidra XREFs and containing functions, and writes a report like `D:\Projects\gpu-unlock\ghidra\nvlddmkm-61742-booter-discovery-YYYYMMDD-HHMMSS-ffffff.txt`. No database changes, disassembly creation, decompilation by default, driver execution, or GPU I/O. Work is capped by bytes/time and per-string hits. The last console line always reports `STATUS=COMPLETE`, `PARTIAL`, or `ERROR`, with `REPORT=...`. `COMPLETE` means the bounded script completed its configured scan **not** that any loader path was proven.

**Validate loaded binary identity before or after the scan:**

```python
p=state.getCurrentProgram(); print('NAME=%s MD5=%s IMAGE_BASE=%s' % (p.getName(), p.getExecutableMD5(), p.getImageBase()))
```

**Targeted second run — only after examining the initial report:** Identify a candidate `CANDIDATE_FUNCTION entry=...` supported by an XREF, navigate to it in Listing, and place the cursor inside that function. Then execute (no new disassembly/functions):

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": [hex(state.getCurrentAddress().getOffset())], "__name__": "__main__"})
```

Or pass up to four **verified** function virtual addresses explicitly as `TARGET_FUNCTIONS: ["0x140...", ...]`. The targeted mode prints capped incoming references and bounded decompilation (12 seconds per function). A function that is not already defined in Ghidra is reported as unavailable; no function is created.

**Interpretation of missing labels:** NVIDIA may strip names, compress archives, or store larger assets in `ucodes_ga10x.bin`. If the report lacks positive Booter XREFs, do not declare `nvlddmkm.sys` free of Booter data. Next examine actual package-loader references and compare bounded compressed-blob anchors against the verified 615.78.08 generated arrays, then investigate the separate `NVUCODES` container by its published header and observed index/fingerprint as appropriate. These are future tasks, **not performed** by this first script.

**After the first report:** retain the raw report, record `PROGRAM MD5`, `IMAGE_BASE`, scan-coverage status, every promising VA/XREF with block and function owner, which labels were absent and any indirect-call uncertainty. Follow one source-to-selection-to-image path at a time. Do not guess a Windows function address from a Linux source line or from unrelated older Ghidra selector-trace reports.

## 5. Evidence progression and strict limitations

| Stage | Required observation | Status |
|---|---|---|
| Program identity / memory section inventory | MD5 + base gate, existing sections with scan coverage | SCRIPT IMPLEMENTED, Ghidra execution PENDING |
| Relevant strings / XREFs / candidate owners | Actual addresses from 617.42 Ghidra report, with confidence limits | PENDING |
| Bounded decompilation of one candidate | Function entry, incoming call sites, high-level arguments and data references; preserve pointer ambiguity | PENDING |
| Production/debug branch and GPU architecture resolution | Independent path for AD102/GA102, selected archive and byte-provider provenance | PENDING |
| Internal image and signatures byte-comparison | Independently recovered Windows bytes, isolated components, SHA-256 comparisons | PENDING |
| Static versus hardware status | No hardware use, no signature acceptance proof or recovery proof | BLOCKED / NONE |

Do not alter the existing passive dual-GPU EFI probe, disconnect preboot GOP, issue MMIO writes, load substituted Booter/GSP images, patch `nvlddmkm.sys`, or flash either GPU as part of this investigation. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`.

## 6. First-turn artifact and verification ledger

- `research/ghidra/nvlddmkm_booter_discovery.py` — new self-contained bounded PyGhidra analysis script; runs only against the pinned imported Windows driver MD5 + base. No hardware or Ghidra DB writes.
- `research/ghidra/test_nvlddmkm_booter_discovery.py` — five independent synthetic tests for ASCII/UTF-16 marker matching and cross-chunk de-duplication. **5/5 passed locally**. This does **not** validate Java API invocation inside the user's Ghidra console.
- `python -m py_compile` of the investigation script — **passed locally**.
- Actual Ghidra report, Windows candidate function, Booter image extraction, and hardware execution — **not performed** at document creation.

**Next awaited evidence:** the first Ghidra `nvlddmkm-61742-booter-discovery-*.txt` report. Do not mark any unknown field complete until its evidence is present.
