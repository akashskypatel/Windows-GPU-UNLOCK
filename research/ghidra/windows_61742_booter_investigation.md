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
