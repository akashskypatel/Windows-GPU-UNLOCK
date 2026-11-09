# 2026-11-09 — Supplied defined strings reviewed against existing Booter evidence (STATIC TRIAGE)

New exact labels `0x140D2F950` FSP boot poll failure, `0x141806480` FSP boot completion and `0x140EFB958` generic `NV_ERR_SECURE_BOOT_FAILED` are **not yet associated with an original driver function owner**; architecture/relevance to AD102 or GA102 unknown. Prior complete original-file path `FUN_1400F35F0 → FUN_1400F3350 → FUN_1401AB740 → FUN_1401B2C10`, HS loader `FUN_140BF3880`, signature overlay callback `FUN_140BF2740`, reset callback `FUN_140BF4F00`, and exact GSP load-ops DATA/table refs should NOT be recycled into an unproved signed-Booter producer. Existing Ghidra script now accepts three caller-selected `CSV_LEADS` in validated `SCAN_CSV_LEADS`; see current cumulative ledger for exact command and per-string disposition. Status is **SOURCE TRIAGE ONLY**, no new original-Ghidra run, active hardware or firmware authentication. `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`.

---

# 2026-11-09 — Adjacent real-loader callbacks selected from exact original Falcon initializer (STATIC SOURCE-ROOTED TASK, NOT YET EXECUTED)

**Why this is the next original-driver discriminator, rather than another generic scan:** Re-examined actual mounted original Ghidra report `nvlddmkm-61742-booter-discovery-20261109-124151-366226.txt`, **SHA-256 `dcd95658583a74c11c2e82d759a62b7be988a305cf1268a71bda6eae325e17fc`**, pinned original Windows 617.42 `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, `DECOMPILER_BEGIN entry=1417e8550 clipped=False total_chars=22282`, `STATUS=COMPLETE`. In the *known Falcon 0x9B0 callback initializer itself*, code under `LAB_1417e8e3e` installs `FUN_140BF3880` at `[param_1+0x170]`; following shown branch (excluding special `0x20` index 5–10 cases) assigns `FUN_140BF4D10` at `[param_1+0x178]` and `FUN_140BF37B0` at `[param_1+0x180]`. Other branches assign `FUN_140092D80` to `+0x170` and `FUN_1400061B0` to `+0x178` and `+0x180`. These are conditional *constructor registrations*, NOT actual runtime execution or firmware authenticity. A prior exact original machine instruction at `0x1417E8F05` loads `FUN_140BF4D10` for the `+0x178` slot; `0x1417E8E3E` is the real `+0x170` registration code. The later `FUN_1402D4710` same-numeric-offset interface is classified **CLOSED as affirmative Falcon instance evidence** due to its callable `+0x4B0` and 32-bit R8 ABI mismatch; do not reuse it.

**New agent-only conclusion:** The existing cumulative research contains no completed decompilation/classification of `FUN_140BF4D10` or `FUN_140BF37B0`; the former was explicitly listed as a lower-priority `+0x178` callback and the latter not yet entered in the record. The pinned current source and complete C now make them **two exact, same-initializer target functions** to classify before any further pointer-alias or signed-image theories. They may be unrelated register, lifecycle or transport operations; **do not infer** that they manufacture, verify or accept signed Booter data merely from adjacency. Their actual role is **OPEN** until complete original Windows function bodies and call windows are supplied. No new script or broad scan is necessary because the committed read-only MD5-pinned `nvlddmkm_booter_discovery.py` already supports two exact `TARGET_FUNCTIONS` and two exact `TRACE_INSTRUCTION_SITES`.

**One optional original machine read-only PyGhidra Python 3 call (single paste):**

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x140bf4d10", "0x140bf37b0"], "TRACE_INSTRUCTION_SITES": ["0x1417e8e3e", "0x1417e8f05"], "FULL_DECOMP_MAX_CHARS": 131072, "__name__": "__main__"})
```

**Acceptance for owner report:** Require terminal `STATUS=COMPLETE` and `REPORT=...`, original MD5/base, `DECOMPILER_BEGIN` with **`clipped=False` for both target function bodies**, the two registration windows and `HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE`. If any target body clips or is undefined, retain `STATUS=PARTIAL` and resolve only its missing bounded source evidence. Classify direct source/file/buffer/descriptor writes, whether either calls `FUN_140BF3880`, and whether actual `nested+0x170` invocation or argument-three producer is connected by object identity; if not, close these two candidates as direct producers without another offset-wide search. Distinguish Ghidra record references from actual runtime invocation and Linux 615.78.08 labels from stock signed Windows 617.42 source. **This task has NOT been executed against original binary here**: the original NVIDIA driver and live Ghidra project are not available to agent, and these function semantics remain UNKNOWN.

**Owner/agent and safety:** AGENT DONE—reconcile complete original initializer report and find previously unclassified adjacent genuine HS callback registrations, select existing source-specific bounded probe, update current authoritative queue. AGENT NEXT—classify the returned two function bodies, then continue independently grounded stock Windows signed Booter IMAGE/HEADER/SIG/PATCH and loader third-argument provenance without assuming external `ucodes_ga10x.bin` is the Booter record producer. OWNER NEXT—preserve original MD5-pinned Ghidra and DriverStore; optionally run the single read-only command and attach raw report; no hardware intervention. Stage 3 `CONFLICT`, Stage 4 `PARTIAL`, `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`. Immutable process/recovery audit unchanged. No tests or implementation code changed.

---

# 2026-11-09 13:50 PST — Original Windows Falcon-like scalar reader fails semantic alias checks (STATIC COMPLETE)

**Evidence:** Original owner-run Ghidra report `nvlddmkm-61742-booter-discovery-20261109-134945-982118.txt`, 4,084 bytes, 79 lines, SHA-256 `fbd93e7a1e42449b8fec08c9bd38b5e9a52bdfa3d8d71dadafaa21e186f7727b`, pinned Windows 617.42 `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, image base `0x140000000`. This was the exact four-site `TRACE_INSTRUCTION_SITES` run on `FUN_1402D4710` chosen in the prior turn. `STATUS=COMPLETE`, elapsed `0.021` seconds, `HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE`; deliberately `DECOMPILATION=SKIPPED` (the prior full-function 34,388-character decomp already completed). The latest report's `+4` instruction lookahead ends at `0x1402D65D7`; therefore it does not itself list the final shared-tail call opcode.

## Exact original-driver instruction semantics and correction

- **Selector derivation:** `MOV EAX,R14D; SUB EAX,0x20803125; JZ 0x1402D4E4C` selects `[RDI+0x170]` for `R14D=0x20803125`. The following subtractions `0x3DC`, `1`, `2` and `CMP EAX,0xFF` yield `R14D=0x20803502` for `[RDI+0x418]`, `0x20803504` for `[RDI+0x180]`, and `0x20803603` for `[RDI+0x4B0]`. Earlier complete `FUN_1402D4710` C independently contains corresponding `param_5` cases. The branches are alternatives, not sequential callback loads.
- **Crucial `+0x4B0` type mismatch:** On the `0x20803603` selector, `0x1402D4E19 MOV RAX,qword ptr [RDI+0x4B0]`, followed by `R8=RBX,RDX=RDI,RCX=RSI`, then `0x1402D4E29 CALL qword ptr [0x140E02AA8]`. The CFG indirect-dispatch target is the value loaded into RAX. Thus `+0x4B0` is **callable in this interface's selected branch**. By contrast, the independently established **nested Falcon 0x9B0 instance has `+0x4B0` = embedded-owner *data back-pointer***. Therefore the previous note that three matching offsets strengthen *object identity* was overstated; the exact field use is inconsistent with treating this entire interface as the established Falcon callback object. This is not a universal no-alias proof, since only selected case paths are examined.
- **`+0x170` ABI mismatch:** `0x1402D4E4C MOV RAX,[RDI+0x170]; 0x1402D4E53 JMP 0x1402D65C9`; the shared tail sets `R9D=R12D`, fifth stack argument `[RSP+0x20]=RBX`, **`R8D=R15D`**, `RDX=RDI`, `RCX=RSI`. Writing R8D zero-extends R8, so this does **not visibly pass an intact 64-bit signed-image descriptor pointer** in parameter 3 as expected by the independently completed `FUN_140BF3880` loader contract. Prior complete C renders a CFG guarded indirect call in the shared tail; the exact final CALL opcode is *not* in this latest four-instruction lookahead. A low-32-bit value is not logically impossible as an address in every context, so treat this as **strong adverse ABI evidence**, not absolute nonidentity.
- **`+0x250`** remains a **separate** branch `0x1402D4E58 MOV RAX,[RDI+0x250]`, `R8=RBX,RDX=RDI,RCX=RSI`, guarded call `0x1402D4E68`. The function entry four-instruction window has pushes only, so the RDI assignment/origin was not recovered from this report. Previous complete decomp shows a broad `param_5` control/command dispatcher rather than a signed Booter IMAGE/HEADER/SIG/PATCH blob producer.

**Disposition:** **CLOSE** the `FUN_1402D4710` numeric three-field overlap as *affirmative evidence* that its receiver is the original Falcon instance or that it invokes `FUN_140BF3880`. The earlier positive shape-match inference is explicitly corrected. RDI's underlying allocation, non-exercised variants, dynamic target and genuine other loader invokers remain unknown; do not claim a globally proved no-alias result. No repeat global `+0x170/+0x250/+0x4B0` scans or re-decompilation of this function; reopen it only with independent receiver/target identity evidence. The next independent investigation gate remains genuine stock Windows 617.42 **signed production Booter IMAGE/HEADER/SIG/PATCH producer and `FUN_140BF3880` third-argument descriptor/callsite**; external host `ucodes_ga10x.bin` to GSP `bindataArgs` is a different known source chain. No active firmware/driver/EFI/GPU work or new test run; original process/recovery audit immutable. `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`.

**Owner / agent current next steps:** AGENT DONE — classify this exact original driver report, recover selector/slot/ABI semantics, retract incorrect three-field identity confidence and reconcile both repositories. AGENT NEXT — original-driver image/header/signature/patch producer and independently grounded same-instance Falcon receiver plus R8 descriptor, without a generic offset search. OWNER NEXT — preserve MD5-pinned original Ghidra and DriverStore; no further run for this candidate is warranted; supply only newly grounded authentic signed-image or Falcon descriptor/callsite evidence. OWNER + AGENT HARDWARE — maintain active refusal until signed firmware authenticity, console ownership release and cold recovery are independently established.

---

# 2026-11-09 13:40 PST — Genuine Windows 617.42 two-slot candidate classified: mutually exclusive branches; parent +0x4B0 field strengthens interface-shape hypothesis (STATIC COMPLETE)

Original owner-run pinned report `nvlddmkm-61742-booter-discovery-20261109-134036-729750.txt`, **39,789 bytes**, SHA-256 `0083198a603d427707b4fe5730564f62f13b2853adcb39a4fda6a58f71b4c99b`, original stock `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, base VA `0x140000000`. Script `SCAN_STRINGS=False`, `TARGET_FUNCTIONS=["0x1402d4710"]`, `TRACE_INSTRUCTION_SITES=["0x1402d4e4f","0x1402d4e58"]`, `FULL_DECOMP_MAX_CHARS=131072`; **STATUS=COMPLETE**, `DECOMPILER_BEGIN clipped=False total_chars=34388`, elapsed `0.525s`, no driver/Ghidra/GPU mutations. `TARGET_INCOMING_REFS_TRUNCATED=true` is the 24-reference caller-list cap, **not** decompilation incompleteness. The candidate is a large `param_5`-keyed control/operation dispatch with many guarded indirect calls and scalar/buffer paths, not a demonstrated direct Booter IMAGE/HEADER/SIG/PATCH producer.

**Exact machine-level branch correction (disproves sequential-execution premise of prior adjacency heuristic):**

```asm
0x1402D4E19 MOV RAX,qword ptr [RDI+0x4B0]
0x1402D4E20 MOV R8,RBX
0x1402D4E23 MOV RDX,RDI
0x1402D4E26 MOV RCX,RSI
0x1402D4E29 CALL qword ptr [0x140E02AA8] ; CFG guard
0x1402D4E2F JMP 0x1402D65E0
...
0x1402D4E4C MOV RAX,qword ptr [RDI+0x170] ; CSV match VA 0x1402D4E4F was displacement bytes
0x1402D4E53 JMP 0x1402D65C9         ; NO fallthrough into +0x250
0x1402D4E58 MOV RAX,qword ptr [RDI+0x250]
0x1402D4E5F MOV R8,RBX
0x1402D4E62 MOV RDX,RDI
0x1402D4E65 MOV RCX,RSI
0x1402D4E68 CALL qword ptr [0x140E02AA8] ; separate guarded call
```

**New positive static discrimination:** Three distinct fields `RDI+0x4B0`, `RDI+0x170`, and `RDI+0x250` are read within the same defined `FUN_1402D4710` function, a stronger object-interface *shape match* than the previous two-field offset-only CSV pairing. Independently established Falcon 0x9B0 nested instance also uses back-pointer `+0x4B0`, HS loader callback `+0x170` and signature transformer callback `+0x250` (in conditional configurations). **This is a testable hypothesis, not proof of shared instance identity.** No instruction in this report establishes RDI's definition, object allocation provenance, `outer+0x108` equality, whether each guarded call reaches the registered Falcon callback, or the argument-three binary descriptor from the genuine loader branch. The unconditional `JMP` after `+0x170` **refutes two consecutive callback reads on one straight-line path**; the two branches remain alternative selector cases. Do not incorrectly mark the *entire* same-instance candidate negative because of the jump. Nor equate `R8=RBX` at the +0x250 branch to `FUN_140BF3880` argument-three without proving the loader target (the +0x250 slot is the distinct signature callback).

**Next smallest read-only original-driver evidence:** Existing committed tool provides `TRACE_INSTRUCTION_SITES` (max four, preceding 12 / following four instructions), so use **only** entry, +0x4B0 branch, the shared +0x170 transfer tail, and the separate +0x250 CFG call; no repeat of 34,388-character full decompilation and no broad displacement scan:

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TRACE_INSTRUCTION_SITES": ["0x1402d4710", "0x1402d4e19", "0x1402d65c9", "0x1402d4e68"], "__name__": "__main__"})
```

**Acceptance criteria:** (1) identify where RDI is assigned and whether object bases at these different selector cases are truly one class; (2) at `0x1402D65C9` determine whether `RAX=[RDI+0x170]` survives to the CFG-guarded call, and which `RCX/RDX/R8` values it receives; (3) only if the receiver can be independently linked to `outer+0x108` follow the live class-specific `FUN_140BF3880` third-argument descriptor and signed IMAGE/HEADER/SIG/PATCH producer. The 12+4 bounded windows might not capture an earlier RDI definition, so report that as **OPEN** rather than inferring identity. **OWNER NEXT:** preserve the MD5-pinned Ghidra/DriverStore; optional one bounded read-only four-site report, or new source-grounded Booter record evidence. **AGENT NEXT:** classify receiver lineage and shared guarded tail on received evidence, and continue the independent signed-source investigation without numerical offset broadening. **No hardware change:** Stage 3 `CONFLICT`, Stage 4 `PARTIAL`, `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`.

---

# 2026-11-09 — Newly re-accessible original manual CSV bytes isolate one two-slot RDI candidate (STATIC EXPORT CORRELATION)

**Correction to immediately preceding archival note:** The previous report truthfully said raw materialization was unavailable **in that session**. The three actual raw files are now present and readable in the active container at `/mnt/data/0x170.csv`, `/mnt/data/0x170(1).csv` and `/mnt/data/0x250-scalar`; byte-level SHA-256 was computed over the files, not inferred from metadata. `0x170.csv` (172,500 bytes; 2,586 CSV data rows) and `0x170(1).csv` (172,500 bytes; 2,586 rows) are **byte-for-byte identical**, both SHA-256 `70e6d8c2529071f169a80d588581732d32ad4ad4673227261a010b242159c50e`. `0x250-scalar` (96,900 bytes; 1,247 data rows), SHA-256 `8de92134a1cfed954e6e2f838c4d7454648dae6adc583904c82dbf08ef56e071`. This resolves the earlier **unverified file-equality** question. The original driver MD5 was pinned in the accompanying Ghidra investigations; standalone CSVs do not themselves contain a driver MD5 header.

**New exact two-slot overlap:** Filtering the `0x170` raw byte matches and `0x250-scalar` Ghidra scalar search entries to **`MOV RAX,qword ptr [BASE+0x170]` and `MOV RAX,qword ptr [SAME BASE+0x250]` within `0x20` bytes of the reported match locations** produces exactly **one** pair across these two files:

- `0x170.csv` `Location=1402d4e4f`, `Label=LAB_1402d4e4c`, `Code Unit=MOV RAX,qword ptr [RDI + 0x170]`. Its memory-search `Location` points to matched displacement bytes; the containing opcode begins at `0x1402D4E4C` as identified by the label.
- `0x250-scalar` `Location=1402d4e58`, `Function Name=FUN_1402d4710`, `Preview=MOV RAX,qword ptr [RDI + 0x250]`. These exported locations differ by `0x9`; the first instruction's known start and second entry differ by `0xC`. Neither CSV establishes in-between instructions or reachable control flow.
- This is **previously unclassified in the authoritative Windows map and Ghidra ledger**, based on a literal repository-document search; it is a single plausible **same register** two-slot *read* correlation, not merely the 66-slot constructor writes. **BUT** it does not prove RDI's originating object, pointer stability between the two reads, the published `outer+0x108` 0x9B0 instance alias, actual indirect CALL/JMP, `FUN_140BF3880` or `FUN_140BF2740` as runtime target, Booter R8 argument-three descriptor producer, signed Windows firmware record or crypto acceptance. It might be a different interface reusing these offsets. The `0x20`/same-RAX filter deliberately excludes other registers, data flow and wider-distance paths, so the count is not a whole-driver absence claim.

**Single next original-driver discriminating investigation:** Reuse existing MD5-pinned read-only Ghidra code; target **only** `FUN_1402D4710` and two exact instruction windows with `getInstructionContaining`, not a new generic scan:

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1402d4710"], "TRACE_INSTRUCTION_SITES": ["0x1402d4e4f", "0x1402d4e58"], "FULL_DECOMP_MAX_CHARS": 131072, "__name__": "__main__"})
```

**Acceptance:** Confirm both CSV rows belong to the same actual function and verify `RDI`'s definition and any mutation/CFG merge between them. Trace caller argument/receiver back to `outer+0xF0→embedded+0x18=outer+0x108` only if actual machine-level source evidence permits; inspect whether loaded values are called, and reconstruct `R8` only for a genuine same-instance loader call. If unrelated interface or no call, classify this exact candidate **CLOSED NEGATIVE (STATIC)** and return to original Windows signed Booter IMAGE/HEADER/SIG/PATCH source evidence without additional broad offset scans. `STATUS=COMPLETE/PARTIAL/ERROR` and `REPORT` must be printed by existing script, which changes neither Ghidra DB nor GPU. **The agent did not run original Ghidra or source code execution; no new code, tests or hardware action.** `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`.

---

# 2026-11-09 — Direct published-pointer receiver scan timed out; manual +0x170/+0x250 export triage is already recorded (STATIC PARTIAL)

**Latest original-driver report:** `nvlddmkm-61742-booter-discovery-20261109-132143-476530.txt` (1,535 bytes, SHA-256 `2480ecbb29d5f09c50b6d0d3a90261c7541bf990e934c9fdaa29ecbbc0b3319d`; `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, image base `0x140000000`). Owner ran existing `TRACE_NESTED_RECEIVER_CANDIDATES=True`, `SCAN_STRINGS=False` read-only on original Ghidra; `SCAN_NESTED_RECEIVER_END examined_instructions=2358272 seeds=431 matched_fields=0 recorded=0 capped=False timed_out=True scan_complete=False`, `ELAPSED_SECONDS=40.035`, terminal `STATUS=PARTIAL`, `HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE`. This is **NO MATCH IN A TIME-LIMITED, INCOMPLETE LINEAR REGISTER-COPY HEURISTIC**, not a negative driver-wide alias/callsite finding. The tool misses `outer+0xF0 → embedded owner+0x18` paths, cross-function and computed-pointer flows. Neither the absence of logged candidates nor 431 seeds verifies the actual nested 0x9B0 receiver, a signed descriptor, Booter record or real loader execution. No re-run at a larger time limit or unfiltered offset scan is justified by this evidence alone.

**User-requested retrospective export comparison:** The user refers to ChatGPT Library `/gpu-unlock/0x250-scalar` (96,900 B), `/gpu-unlock/0x170.csv` (172,500 B), and `/gpu-unlock/0x170(1).csv` (172,500 B). The Library lists their metadata, but **raw-byte materialization and direct read both failed** with an unavailable authorized backing-path error in this assistant environment. Thus we **did not reopen, rehash, or newly parse these three raw CSVs**; size equality does not prove `0x170.csv` and `0x170(1).csv` identical. We instead cross-checked the previously verified direct CSV parsing preserved in chronological research: `0x170(1).csv` SHA-256 `70e6d8c2529071f169a80d588581732d32ad4ad4673227261a010b242159c50e`, 2,586 raw matches, 1,503 literal `+0x170` memory operands and 331 QWORD stores (181 annotated `=>FUN_*`); the observed nested HS-loader store `FUN_140BF3880` matches byte displacement `0x1417E8E48` (real instruction `0x1417E8E45`), and its `FUN_140092D80` fallback appears at displacement `0x1417E8EFC`. Other callers/owners reuse `+0x170`—numeric equality is **NOT object identity**. `0x250-scalar` SHA-256 previously `8de92134a1cfed954e6e2f838c4d7454648dae6adc583904c82dbf08ef56e071`, 1,247 Ghidra scalar results, 1,051 generic `[base+0x250]` categorizations. The real registration `0x1417E983C MOV [R9+0x250],RAX=>FUN_140BF2740` and fallback `0x1417E985A → FUN_140006190` are already known (raw matched displacement bytes `0x1417E983F`/`0x1417E985D`). Previous 118 QWORD stores across 44 owner functions inside `0x141700000..0x1417FFFFF` further show the offset's ambiguity. These are **historical verified results, not newly verified raw file contents**.

**Resulting execution decision:** The manual exports **corroborate callback registration only**; they do not repair the incomplete `outer+0x108` → same-instance `nested+0x170/+0x250` call chain, establish `FUN_140BF3880` R8/argument-three binary descriptor provenance, identify original Windows 617.42 signed Booter `IMAGE/HEADER/SIG/PATCH` producer or demonstrate cryptographic acceptance. Close the task to compare these old exports and stop requesting the same timeout-prone whole-program heuristic, scalar search or generic displacement scan. **AGENT NEXT:** continue only when a genuine original-driver source-specific producer or validated published-instance callsite is available; prioritize authentic signed Windows IMAGE/HEADER/SIG/PATCH source and independent third-argument producer, retaining the GSP `bindataArgs` handoff as a separate chain. **OWNER NEXT:** preserve original MD5-pinned Ghidra/DriverStore; no repeat scan or hardware action; provide *new source-specific* original-driver data rather than previously classified offset lists. If independent raw CSV byte verification is needed, their contents must be freshly supplied with an authorized attachment; old derived notes remain usable with provenance caveat. All active holds remain: `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`. No code, firmware, Ghidra DB or GPU changes; no tests run.

---

# 2026-11-09 — Original-driver Booter provenance: host/GSP boundary clarified; existing published-pointer receiver probe selected (NO NEW WINDOWS EXECUTION)

**Source review (static evidence and explicit limits):** Rechecked the pinned original Windows 617.42 cumulative and Ghidra ledgers against the authoritative execution map. Exact previous host chain: `FUN_1400F35F0` selects `ucodes_ga10x.bin`, `FUN_1400F3350` reads it, `FUN_1401AB740` stages it, and `FUN_1401B2C10` populates `GSP_ARGUMENTS_CACHED.bindataArgs`. That establishes a handoff of the archive, **not** a host-side signed Booter IMAGE/HEADER/SIG/PATCH record producer, not the archive index consumer, and not `FUN_140BF3880` third-argument provenance. NVIDIA Linux **615.78.08** `src/nvidia/src/kernel/core/bin_data_pvt.h` was independently reread: its 24-byte `BINDATA_UCODES_BIN_HEADER` carries `NVUCODES` magic, v1, a **number of possible files/indices**, and a GSP pairing fingerprint. It **does not** declare a serialized record table or prove a Windows 617.42 Booter record. The independently checked Linux `bin_data.c` `bindataArchiveGetStorage` iterates an in-memory `BINDATA_ARCHIVE` by `BINDATA_LABEL`, not the 24-byte Windows archive file header. Do not invent a file parser from the header or equate Linux labels/payloads with Windows. Existing original Windows GSP/UCODES fingerprint pairing observation remains STATIC PARTIAL.

**Next executable discriminator selected without implementing a new scan:** Existing committed `research/ghidra/nvlddmkm_booter_discovery.py` already supports opt-in `TRACE_NESTED_RECEIVER_CANDIDATES=True`, `SCAN_STRINGS=False`; verified the current source and existing regression cases in `test_nvlddmkm_booter_discovery.py` by code inspection. This bounded read-only heuristic looks for **a direct `[base+0x108]` pointer load followed by a register-copy-tracked `[pointer+0x170]` or `+0x250` access within 36 instructions of the same Ghidra-defined function**. It reports CFG CALL/JMP proximity and explicit `potential_alias_only=True`; time budget 40 seconds, report cap 48, partial status if cap/time budget hit. This is *not* a repeat of the generic unfiltered `+0x170` displacement scan. It **misses** indirect aliases, interprocedural flows and `outer+0xF0 → owner+0x18` paths, and has no proof of physical instance equality, CALL target, descriptor, signature selection or reachability. A zero candidate report is not a negative whole-driver finding.

**Single optional owner-machine action (only original MD5-pinned Ghidra, no device use):**

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TRACE_NESTED_RECEIVER_CANDIDATES": True, "__name__": "__main__"})
```

Require final `STATUS=COMPLETE/PARTIAL/ERROR REPORT=...` and original program MD5 `3fb9afac9d0e394723e830aa14e60512`; attach raw report. **AGENT next** triages only grounded direct publication→callback-read pairs and checks real RCX/RDX/R8 descriptor/target instance; if none, return to **authentic stock Windows production signed Booter IMAGE/HEADER/SIG/PATCH source**, not another numeric scan. **OWNER next** preserve original DriverStore/Ghidra; no repeat completed `FUN_140296090`, `FUN_141750C80`, `FUN_1417E8550` or closed cleanup wrappers. All active hardware actions remain blocked: `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`. No Windows Ghidra run, full repository test execution, driver download, code change, or hardware test was performed in this source-review turn.

---

# 2026-11-09 13:00 PST — Post-registration subobject helper is zero stub; speculative +0x2C0 helper path closed (STATIC)

Original owner-run pinned `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512` PyGhidra report `nvlddmkm-61742-booter-discovery-20261109-125859-952151.txt` (2,608 bytes; SHA-256 `e0d00ca172ec3b774304aeea0a5136a663748f2340ce8a51c61d0d81fa455d6e`; `SCAN_STRINGS=SKIPPED_BY_CALLER`, `clipped=False total_chars=57`, `STATUS=COMPLETE`, `HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE`).

`FUN_140296090(void)` is `return 0;` only. It has **no visible loads/stores, pointer derivation, allocation, decryption, or nested invocation**, so the proposed direct `nested+0x08` subobject-helper → relative `+0x2B8` → nested `+0x2C0` metadata-pointer write is **REJECTED for this implementation (STATIC)**. The report lists the established constructor's incoming call at `0x1417E9BC0` plus other CALL XREFs; `TARGET_INCOMING_REFS_TRUNCATED=true` after 24 printed references, so it is NOT an exhaustive caller inventory and no conclusion about callers follows. The previously examined adjacent `FUN_141750C80` is also a zero-return stub. Combined with complete `FUN_1417E8550` 66-slot callback initializer, constructor object zeroing, `FUN_1406B3FD0` defaults and `FUN_1417E83E0` capability setup, none of these **reviewed direct bodies** establishes a nested `+0x2C0` metadata pointer producer. This is **not** proof that the pointer is never populated by other routines, DMA/copies, or runtime setup, nor that the consumer's `param_2` aliases this instance.

Genuine original stock Windows 617.42 signed Booter IMAGE/HEADER/SIG/PATCH byte and metadata producer, `FUN_140BF3880` third-argument descriptor, the **actual same-instance** `outer+0x108 → nested+0x170` callback invocation, physical GA102/AD102 runtime selector, cryptographic acceptance, shared-console release and cold recovery remain **OPEN/BLOCKED**. Do not run another `FUN_140296090` or `FUN_141750C80` decompilation, widen prior clipped XREF/callback-displacement scans, or promote an offset-only match to object identity. With no novel source-anchored post-construction writer, the speculative `+0x2C0` direct-helper branch is **PAUSED** and investigation returns to the independently required authentic signed Windows Booter provenance and actual loader invocation/arg3 producer. No original 114 MB driver bytes or Ghidra execution available to agent here; this turn only assesses the uploaded result and updates documentation. `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`.

**Evidence ownership:** Windows execution map retains the sole owner/agent action queue. No code change or physical test.

---

# 2026-11-09 12:43 PST — Full Falcon callback-table initializer classified; no direct nested +0x2C0 metadata setter (STATIC COMPLETE)

Owner-run pinned original Windows 617.42 Ghidra report `nvlddmkm-61742-booter-discovery-20261109-124151-366226.txt` (24,116 bytes, 1,243 physical lines, SHA-256 `dcd95658583a74c11c2e82d759a62b7be988a305cf1268a71bda6eae325e17fc`, driver MD5 `3fb9afac9d0e394723e830aa14e60512`), `STATUS=COMPLETE`, `clipped=False total_chars=22282 output_limit=131072`, read-only / no Ghidra DB or hardware changes.

`FUN_1417E8550(param_1,param_2)` reads the 16-bit selector at `param_2+0x10`, with high family `selector >> 5` and low index `selector & 0x1F`. Its entire visible direct output is **66 contiguous QWORD callback slots at `param_1+0x68` through `param_1+0x270` in 8-byte increments**. No `param_1+0x2C0` store occurs anywhere in this complete body. **Family `0x20`, indices 5–10:** `+0xB0=FUN_1406B8E10` and `+0x170=FUN_140092D80`. **Other visible selector paths:** `+0xB0=FUN_140BF1390` and `+0x170=FUN_140BF3880`. **Signature callback `+0x250=FUN_140BF2740`** is selected only for family `0x20` with low indices 11–15 or 20–24 (literal mask `0x01F0F800`); other visible paths select `FUN_140006190`. These are conditional callback registrations, not an observed runtime selector, not an AD102/GA102 classification, and not evidence that `FUN_140BF3880` was called on the published `outer+0x108` instance.

The previously complete `FUN_1417E99B0` 0x9B0-byte constructor zeroes `+0x2C0`; complete defaults `FUN_1406B3FD0` and capability setup `FUN_1417E83E0` also have no direct setter. `FUN_140BF1390` consumes `*(param_2+0x2C0)` when non-null and its count is at least three, but that consumption does not identify an actual metadata-pointer producer, establish that its `param_2` aliases the constructed object, or establish signed Windows Booter IMAGE/HEADER/SIG/PATCH bytes. The **direct constructor-initializer setter hypothesis is CLOSED (STATIC)**; indirect/post-construction writes remain OPEN. Independent original-driver signed image producer, actual same-instance nested `+0x170` invocation, `FUN_140BF3880` argument-three descriptor source and guarded `outer+0x3E8` region contents remain OPEN. No active firmware/EFI/driver/Stop/DMA/FLR test is authorized or verified.

**Trace continuation:** Keep any follow-up anchored to an actual post-construction writer or same-instance pointer def-use; do not repeat the completed initializer or broad offset-only scans. The single authoritative owner/agent action queue is updated in `research/nvidia_unlock_evidence_to_execution_map.md`. `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`.

---

# 2026-11-09 12:29 PST — Source-anchored nested Falcon +0x2C0 metadata pointer producer still open; clipped initializer tail isolated

Re-read original complete `FUN_140BF1390` (`...20261106-162523-880517.txt`): it consumes `*(nested+0x2C0)` as metadata pointer and tests non-null and first DWORD count >=3; callback registration `FUN_1417E8550:0x1417E8861` puts it at nested `+0xB0`. The complete 0x9B0-byte `FUN_1417E99B0` ctor zeroes that field before setup, while complete `FUN_1406B3FD0` default config and `FUN_1417E83E0` flags initializer contain no direct `+0x2C0` setter. `FUN_1417E8550` code is **not completely printed** in the prior 20K-clipped C report (separate focused run says 22,282 chars). The next single justified original-driver result is full output of this exact function with cap 131,072 and `STATUS=COMPLETE`, to determine whether constructor-time callback table initialization writes a metadata pointer or function at `+0x2C0`. Do not equate callback registration to runtime invocation or conclude producer absence if no direct write. Source, signed Booter byte provenance and `FUN_140BF3880` loader arg3 remain OPEN; all hardware gates false. Authoritative owner/agent steps are kept only in the execution map.

---

# 2026-11-09 12:05 PST — Exact Windows 617.42 getter-return → R14 pointer register dataflow completed

Original owner-run machine-window report `nvlddmkm-61742-booter-discovery-20261109-120551-287574.txt` **2,933 bytes / 53 CRLF lines / SHA-256 `a0aacb3235af09b2b2244aa33d900d789e7ca89a7b72b00499812c547378c5b1`**, MD5-pinned original Windows 617.42 `nvlddmkm.sys`, two exact windows, `STATUS=COMPLETE`, `DECOMPILATION=SKIPPED`, no mutations. `FUN_1402EA6F0` checks CFG getter `RAX !=0`, then `0x1402EA7EF LEA R14,[RAX+8]`; when `[context+0x584C] !=4` and DWORD `[R14+8]==0`, `0x1402EA802` stores literal `0x2000` into `[R14+8]` = `getter+0x10`. Even context flag 4 constructs R14 but skips size default and joins resource-transfer path. Previously verified `0x1402EA872` passes R14 to parent vtable +0x158 CFG callback as fifth output parameter and separately classified class-dependent address encoders may populate `getter+8`. Only with retained 0x3550 outer root/embedded table and correct instance does getter resolve to `outer+0x3E8`, corresponding to conditional `outer+0x3F0` encoded-address and `outer+0x3F8` size fields. **Machine def-use closed; runtime physical object selection, full region producer, signed Booter image, nested +0x170 invoker, HS-loader arg3 provenance, signature acceptance and recovery still OPEN.** No repeated decompilation, firmware mutation, code or tests; all safety gates false. Authoritative current owner/agent next steps are maintained in the execution map.

---

# 2026-11-09 — Cross-report conditional descriptor-region population: outer+0x3F8 size and outer+0x3F0 encoded address (STATIC PARTIAL)

**Exact sources:** Original 617.42 `FUN_14017AF30` constructor `...20261106-172617-217613.txt` (initial zeroed outer 0x3550, embedded+root vptrs); `FUN_140178DD0` and `FUN_140179130` machine forwarding `...20261106-172232-079805.txt`; full `FUN_1402EA6F0` C `...20261106-162950-226286.txt` (state-gated parent +0x30 getter, `getter+0x10=0x2000` if zero, mapped-resource parent +0x158 with fifth arg `getter+8`); original bounded CALL machine instructions `...20261106-164730-008919.txt` (`0x1402EA7B5` getter, `0x1402EA802` DWORD store, `0x1402EA887` encoder dispatch); three class-selected complete `outer+0x308` encoder functions `...20261106-173559-777188.txt`. The conditional 0x3550 parent+root chain resolves getter `FUN_1405785E0` returning `outer+0x3E8` when guard `outer+0x3518==0`; parent +0x158 forwards to a class-selected region-5 address encoder. Hence conditional field-level writes at `outer+0x3F8` (size default) and `outer+0x3F0` (possible QWORD encoded address), **not** a recovered signed-image header. Machine-level R14 getter-result def-use has not been fully captured; next exact original Ghidra site windows `0x1402EA7E3` and `0x1402EA802`, no decompilation. Runtime object identity, complete region contents, real `FUN_140BF3880` arg3 source, nested +0x170 invocation, Windows signed Booter asset and crypto acceptance remain OPEN. No new code, Ghidra run or hardware test, and active gates remain false. Authoritative current next steps are in the execution map only.

---

# 2026-11-09 11:45 PST — Exact outer+0x1D0 original Windows callback classified; direct signed-Booter producer lead CLOSED

**Original exact Ghidra result:** uploaded `nvlddmkm-61742-booter-discovery-20261109-114546-169175.txt` SHA-256 `a493a7eb10a31c626eff9d1b2376714b37433ea934d1834d8c32435d4471c0bf`, 1,501 bytes / 42 physical lines. Loaded `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`; `STATUS=COMPLETE`, `clipped=False total_chars=159`, no GPU/Ghidra mutations. `FUN_1405798E0` calls previously completely decompiled scalar-access helper `FUN_140126650(param_1+0x4410,0,0,0x110ABC,0)`, returns `(result&0x1FF)<<8`. That callback does not directly produce signed Booter bytes, host arg3 descriptor, outer `+0x3E8` region, or nested `+0x170` Falcon DMA loader invocation. Prior `FUN_140179580` registration of `outer+0x1D0` and `FUN_140579FF0` indirect consumer are independent static context; actual runtime receiver/architecture selection unproved. Direct callback-as-Booter-producer hypothesis CLOSED; original Windows production image/source/receiver/descriptor/recovery OPEN. Owner/agent instructions updated solely in the execution map. Do not rerun closed helper/callback or canonical wrapper scan; hardware gates all false.

---

# 2026-11-09 — Existing exact Windows 617.42 initializer report resolves new outer+0x1D0 callback producer; one unreviewed callee remains

Already-complete original 617.42 Ghidra `FUN_140179580` C (28,191 unclipped chars, original report `...20261106-173012-731422.txt`) has two *actual* `outer+0x1D0` assignments: `FUN_1405798E0` on a class-selected path and `FUN_140006190` zero-return fallback on a distinct selector path. Original `FUN_140579FF0:0x14057A0BF` reads `[RDX+0x1D0]` and CFG-calls at `0x14057A0C6`, creating a precise possible producer→consumer bridge. A callback assignment and pointer read do not establish same physical instance, exact branch, nested Falcon `+0x170`, signed producer or argument-three descriptor. The **one unreviewed** concrete callback body is `FUN_1405798E0`, to be inspected with a single read-only targeted decomp; neither original Ghidra database nor hardware is available to the agent. Exact no-wrapper finding in the previous chronological record remains valid. Do not repeat fully examined initializer/consumer bodies; all active gates stay false.

---

# 2026-11-09 11:31 PST — Original Windows 617.42 pinned reference-wrapper scan COMPLETE, zero matching assembled wrappers

**Received physical-host, read-only result:** JSON SHA-256 `8918f4208e1b9cdc78ef57a847a190d1409912a5df54f2ffe63f9975b9ae218f`; all three SHA-pinned `nvlddmkm.sys` / `gsp_ga10x.bin` / `ucodes_ga10x.bin` inputs matched expected hashes and completed without truncation. Raw reference magic/version 8-byte markers were **3 / 0 / 0**; **0 valid fully assembled reference-wrapper candidates in all files**. Only the exact Linux 615.78.08 one-app assembled GA102/AD102 layout hypothesis is negative. Three driver marker positions were not emitted by the report and are not classified as Booter; no producer, image/header/sig/patch, Falcon third-argument descriptor or dynamic receiver established. Do not repeat identical reference-format search. Pursue original stock Windows signed record source and specific nested-instance invocation independently, maintaining `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`. The authoritative execution map is updated in place.

---

# 2026-11-09 — Read-only Linux-reference HS wrapper candidate probe added; original Windows Booter evidence still open

**Artifact:** `research/probe_nvfw_hs_wrapper.py` (host-only, no driver/firmware/EFI writes), `research/firmware/test_probe_nvfw_hs_wrapper.py`; 7 synthetic positive/negative tests and Python compile passed locally. Enforces exact SHA-256 pins for `nvlddmkm.sys`, `gsp_ga10x.bin` and `ucodes_ga10x.bin`, accepts only the NVIDIA public `615.78.08` 384-byte-signature-stride GA102/AD102 **assembled** Booter wrapper shape. Records only candidate offsets/sizes/segment hashes in JSON. Reference exporter rounds *declared* total size to 256; it does **not explicitly write trailing padding**, corrected in current plan. No original Windows 617.42 files available to the agent; no real candidate or true Windows producer reported. Scan completion and zero candidates cannot prove Booter absence, signature acceptance, descriptor provenance, nested Falcon invocation, or hardware readiness. Original `0x9B0` Falcon instance `+0x170` receiver, `FUN_140BF3880` argument three, `outer+0x3E8` producer and production Windows signed IMAGE/HEADER/SIG/PATCH source remain OPEN. Preserve prior cleanup-wrapper correction. Owner optional next: independently run the host-only probe on preserved original DriverStore inputs. Active gating unchanged: `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`.

---

# 2026-11-09 10:56 PST — Exact two Ghidra CALL-site function owners CORRECTED: separate cleanup wrappers, NOT outer constructor

**Original read-only report:** `nvlddmkm-61742-booter-discovery-20261109-105642-560073.txt` 2,043 bytes / 36 physical lines, SHA-256 `0cf605fdd0a1b19ac42e2014432f2f15898bbe80c4d1feeb40dc1b175ae79183`, loaded Windows 617.42 `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`; final `STATUS=COMPLETE` for two instruction sites, `DECOMPILATION=SKIPPED`, `HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE`, elapsed 0.082s.

**Factual correction:** Earlier notes misidentified two `FUN_14059B580` direct-call XREF sites as within `FUN_14017AF30`. Ghidra's defined owner at `0x14017BA49` is **`FUN_14017BA40`**; at `0x14017BA7D` is **`FUN_14017BA70`**. These are not automatically the previously proven 0x3550-byte outer constructor despite numeric proximity. Earlier caller-owner claim was false; it is superseded here, not quietly erased from chronological history.

- `FUN_14017BA40`: saves `RBX=incoming RCX`, calls `FUN_14059B580(incoming RCX)`, then `FUN_1403FCDE0(incoming RCX+8)`, and prepares `RCX=incoming+0x110`. Remainder after bounded window unknown.
- `FUN_14017BA70`: sets `RBX=incoming RCX+8`, passes that to `FUN_14059B580`; then calls `FUN_1403FCDE0(incoming RCX+0x10)`, prepares `RCX=incoming+0x118`; remainder after window unknown.
- With previously completed `FUN_14059B580` and display-channel unbind `FUN_14059C510`, both site sequences support **cleanup-style wrapper** classification, **NOT** actual signed Booter image source, Falcon +0x170 runtime receiver equivalence or loader argument-three descriptor producer. Do not assert an actual destructor role, caller instance type, hidden tail target or negative whole-driver execution from these bounded windows.

**No further work on this cleanup branch needed absent a new exact object-alias or source-specific lead.** Current action queue resides only in `research/nvidia_unlock_evidence_to_execution_map.md`: agent seeks a real signed Windows Booter producer/asset and published Falcon 0x9B0 instance invoker and `outer+0x3E8` writer; owner preserves original Ghidra/DriverStore and does no active tests. `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`.

---

# 2026-11-09 10:44 PST — New full guarded +0x170 caller bodies classify display-channel cleanup and scalar operation dispatch; no signed Booter invoker

**Original owner report:** `nvlddmkm-61742-booter-discovery-20261109-104424-635607.txt` 23,169 bytes / 1,211 lines; SHA-256 `58ab8c33fb06d8e5b9ebbdd2e3d3855e9b4f88a2d0c18befd676030df4c90054`, 617.42 `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`; `STATUS=COMPLETE`, three full unclipped C bodies, elapsed `0.461s`, `HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE`.

- `FUN_14059B580` follows `param_1+0x160→+0xE8→+0x21F0`, obtains receiver `lVar2`, calls `FUN_14059C510(lVar2,param_1)` and then CFG-calls `[lVar2+0x170]`, checks nonzero result. Precursor `FUN_14059C510` uses literal `dispchnUnbindAllCtx_IMPL`, multiple display-channel unbind/context helpers and resource fields. **Strong static display teardown/unbind interpretation**; NOT an identified `FUN_140BF3880` signed-descriptor producer. Two direct incoming call XREFs into `FUN_14059B580` from known outer `FUN_14017AF30` at `0x14017BA49`/`0x14017BA7D`; caller-object alias currently OPEN.
- `FUN_140588AD0` follows `param_1+0x1C0→+0x128→+0x2208→+0x1CE8` and branches on `param_2+4/+0x10` operation selectors, `param_2+0x14` scalar result/writeback; call windows `0x140588DD2` and `0x1405890AC` load `[RDX+0x170]` with neighboring `+0x180` callbacks, returning byte/scalar outcomes. **Strong static operation/query dispatch interpretation**; no authentic production signed Booter asset or actual 0x9B0 nested instance alias established. Indirect callees themselves remain unproven.
- Both prior proposed direct signed Booter invoker leads are **DEPRIORITIZED / NOT PROVEN** rather than declaring negative whole-driver code absence. Original nested Falcon constructor/published `outer+0x108`, real loader nested `+0x170` registration, actual `FUN_140BF3880` arg-3 contract still separately PASS STATIC; actual invocation/descriptor source and GA102/AD102 Windows acceptance remain OPEN.

**Optional bounded owner Ghidra two-direct-call-site read (not another full body decomp):**

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TRACE_INSTRUCTION_SITES": ["0x14017ba49", "0x14017ba7d"], "__name__": "__main__"})
```

**AGENT next:** assess those two caller-source/cleanup branches, stop if no same nested-instance link, then concentrate original signed Windows Booter source/descriptor and unrelated `outer+0x3E8` writer, not further generic +0x170 scans. No physical action, no crypto bypass or readiness gate promotion. `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`.

---

# 2026-11-09 — Agent-side stock 617.42 Booter proof queue: +0x170 invoker/arg3 source still OPEN; two exact unclassified caller families selected

**Evidence provenance:** Four supplied original Nov 9 reports independently byte/hash/line/status verified (MD5-pinned 617.42). Latest `FUN_140579C20` and preceding `FUN_140578C60` complete bodies close only **direct** signed Booter producer hypothesis for those conditional *root* vtable methods. None proves the real nested Falcon dispatch instance executes.

**Rooted nested object** (already established in previous owner-run reports): outer embedded owner `+0xF0`; published nested 0x9B0 object at outer `+0x108` (owner `+0x18`); nested `+0x4B0` points back; nested `+0x170` conditionally `FUN_140BF3880` (HS DMA loader) or `FUN_140092D80` fallback, nested `+0x250` conditionally `FUN_140BF2740` signature word-layout transform. Registration/data XREFs do not establish execution. The full HS loader reads argument-3 binary source/size and +0x40 optional memory descriptor; actual argument producer not linked to a production Windows signed Booter archive.

**Candidate order from existing prior capped +0x170 transfer evidence, not a new scan:**
- `FUN_14059B580:0x14059B970` reads `[R13+0x170]` and CFG CALLs after direct `FUN_14059C510(R13,R12)`; examine full caller and precursor, focusing on R13 instance producer and R8 descriptor pointer. These have no recorded full C decompilation in current cumulative notes.
- `FUN_140588AD0:0x140588DD2/0x1405890AC` reads `[RDX+0x170]`, CFG CALLs and zero extends `AL`, with alternative `+0x180` callbacks on adjacent branches; possible unrelated interface, same-instance alias UNKNOWN. Unclassified full body in current notes.
- Prior `FUN_140124A90` (large GPU context `+0x2160`), `FUN_140175B60`, `FUN_1403235F0` and `FUN_140532110` already inspected without successful 0x9B0 alias; direct recognized `+0x2710` writer sets zero. Do not repeat them or the partial broad scan (246 candidate transfers / 80 reported).

**Single owner-local read-only action:**
```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x14059b580", "0x14059c510", "0x140588ad0"], "FULL_DECOMP_MAX_CHARS": 131072, "TRACE_INSTRUCTION_SITES": ["0x14059b970", "0x140588dd2", "0x1405890ac", "0x14059c510"], "__name__": "__main__"})
```

**Agent acceptance after returned report:** (1) exact pointer value/alias `outer+0x108 = nested` or fail; (2) actual callback `[nested+0x170]` selected as real `FUN_140BF3880` not fallback, *on the same class instance*; (3) original callsite R8 addresses the real arg3 descriptor with image source `+0`, size `+8`, optional memory descriptor `+0x40`; (4) its producer retrieves authenticated Windows 617.42 GA102/AD102 production image/header/signature and patch metadata. If any missing, record `PARTIAL/OPEN`, not hardware success. Do not assume Linux source equivalence.

**Independent Linux 615.78.08 source checked through connected GitHub:** `src/nvidia/src/kernel/gpu/gsp/kernel_gsp_booter.c` blob SHA `db329104eb98aa5abbd18188fc4b00a7f2771bed` supplies distinct `IMAGE_PROD/HEADER_PROD/SIG_PROD/PATCH_SIG/PATCH_LOC/PATCH_META/NUM_SIGS` bindata archive records. It does **not** prove Windows source/byte/crypto acceptance.

**Universal fork source plan reconciled separately:** original MSI Stop and shared physical 0016 graph unchanged; passive `SHARED_CONSOLE_TEXT` capture remains owner-optional and not run; no active owner firmware action.

**Safety:** CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false, physical Stage 3 CONFLICT / Stage 4 PARTIAL, immutable process/recovery audit unchanged.

---

# 2026-11-09 10:21 PST — Parent +0x60 candidate FUN_140579C20 is a nested configuration initializer; direct Booter producer lead closed

**Verified report:** `nvlddmkm-61742-booter-discovery-20261109-102152-704825.txt`, **2,638 original bytes / 98 physical lines**, SHA-256 `205317327f43b00a35c3e1836adcf4b01a6af667397df2d968ca4f15eb09b535`, 617.42 `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, `clipped=False total_chars=956`, `STATUS=COMPLETE`, elapsed 0.249s, no Ghidra or GPU mutation.

- `FUN_140579C20` traverses `param_2+0x190 -> +0x18 -> +0x4E8` for a nested writable block. If nonnull, output `param_3` gets `+0=0` (byte), dwords `+4=0x110000`, `+8=0x111000`, `+0xC=0x110600`. Nested block gets dword `+2=0x08080808`, `+8=0`, and pairs `+0x10/14=0x110C00,8`, `+0x18/1C=0x110C04,8`, `+0x20/24=0x110C80,8`, `+0x28/2C=0x110C84,8`. These are static configuration data; GPU MMIO meaning and downstream effects unknown; no signed image/header/signature construction or direct HS loader call in complete body.
- `FUN_1406B2F10:0x1406B313D` previously passed `R8=RBX+0x41C` into parent `+0x60` and then `CMP [RBX+0x420],0`. The proposed candidate sets output `+4=0x110000` exactly at the compared field **under conditional root/receiver alias**. Previous “status” interpretation is not established. Error-path helper side effects and null preconditions remain unresolved.
- `TARGET_CALLER from=0x14140FA64`, `0x140E0BEA4`, `0x140E76760` are **DATA references**. `0x140E0BEA4` is 32-bit `0x00579C20` in probable PE CFG valid-target table; `0x140E76760` holds a 64-bit function pointer under conditional root-vptr `+0x370` hypothesis, not proven runtime dispatch.
- **CLASSIFICATION:** this specific +0x60 function and earlier +0xE0 record getter are **direct signed Booter producer leads CLOSED (STATIC)**. Still not proven: true 0x3550 root object identity on a physical card, original stock signed Windows GA102/AD102 Booter IMAGE/header/signature, `outer+0x3E8` region producer, actual 0x9B0 Falcon HS invoker and `FUN_140BF3880` arg-3 descriptor producer or hardware recovery.

**Next (owner/agent in execution map):** AGENT first identify an *unreviewed concrete* original-driver source site linking a published nested Falcon loader callback with its exact receiving instance/third-argument provenance; only then supply a bounded read-only Ghidra command to the OWNER. No additional owner run of known +0xE0/+0x60 bodies, firmware/MIMO/MMIO experiments or active stage. `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`.

---

# 2026-11-09 10:12 PST — Parent +0x60 conditional pointer = FUN_140579C20; alternate entry is likely PE Guard CF Function Table

**Uploaded report:** `nvlddmkm-61742-booter-discovery-20261109-101251-279764.txt` 3,558 bytes / 60 physical lines / SHA-256 `5d8b0e972dda0097f8363543c7aac0a2c4e527593d25d793139fcba48fccfc45`; MD5-pinned Windows 617.42 driver; `STATUS=COMPLETE`, 0.015s, no Ghidra or GPU mutation.

- `FUN_140178460` (embedded parent +0x60) adjusts receiver `RDX-=0xF0` and tail CFG-dispatches root `vptr+0x370`. Under the previously observed root `0x140E763F0` **conditional, unproven runtime alias**, `0x140E76760` contains executable function pointer `FUN_140579C20`. Zero direct inbound refs to the slot do not disprove dynamic virtual use; body not yet decompiled.
- `FUN_1406B2F10:0x1406B313D` branches on parent bytes `+0x10!=0`, `+0x11==0`, CFG-calls parent +0x60 with `R8=RBX+0x41C`, then tests `[RBX+0x420]`; callback role and runtime receiver open.
- Prior `DATA` reference `0x140E0BE84` to record getter `FUN_140578C60` is a **32-bit RVA `0x00578C60`**, not a 64-bit vptr. The surrounding 16 entries are increasing 32-bit RVAs, including `0x00579C20` for current function. Defined data root `0x140E02C20` and inbound from PE load-config `0x141002A80` match an **existing 2026-11-05 GuardCFFunctionTable hypothesis**, not proof of a second virtual class table. Formal structure decode still pending.
- **Correction:** earlier `nvlddmkm-61742-booter-discovery-20261109-100251-168740.txt` is **63 physical lines**, not 45, while the recorded 1,977-byte count and SHA-256 were correct. Current source docs corrected.

**Next one bounded owner-local decompilation** of `FUN_140579C20`:

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x140579c20"], "FULL_DECOMP_MAX_CHARS": 131072, "TRACE_INSTRUCTION_SITES": ["0x140579c20"], "__name__": "__main__"})
```

Agent: classify and close this record/management path if unrelated; proceed to actual signed Windows production Booter producer/descriptor, `outer+0x3E8` content source and nested Falcon +0x170 invoker. Maintain `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`; no active hardware test.

---

# 2026-11-09 10:02 PST — FUN_140578C60 is a conditional indexed record getter; owner/producer still unresolved

**Read-only original 617.42 report:** `nvlddmkm-61742-booter-discovery-20261109-100251-168740.txt`, 1,977 bytes / 63 physical lines, SHA-256 `acdf0d107225b9646e3d80b6444d0b67b7db6bc79528baa7b04cecb36d3cb36d`; `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, `STATUS=COMPLETE`, `clipped=False total_chars=355`, 0.249s, no Ghidra database or GPU mutation.

- `FUN_140578C60` reads `param_2+0x190` metadata and indirect record count `[ [ [param_2+0x190] +0x18 ] +0x460]`; on `index<count`, returns `param_2+0x480+0x28*index`, otherwise 0. Caller requirement is non-null/valid metadata despite visible `param_2==0` branch. No signed image/header/signature production, HS loader call, cryptographic acceptance or per-GPU runtime selector in its entire body.
- Earlier `FUN_140579FF0` zeroed `outer+0x480` for `0x2800` bytes and initialized nested count `+0x460=0x100`; `0x2800/0x28=256` records. `FUN_1406BB9A0` uses parent `+0xE0` returned pointer for fields `+0,+4,+8,+0x10,+0x18`. Combined, this is a strong **static** record layout/consumer match, **conditional on matching object identities**.
- Inbound DATA references to getter entry: `0x140E0BE84`, `0x140E76718`. The latter is the hypothetical root `+0x328` slot, not yet an authenticated root-vtable span; embedded parent at `0x140E764A8` intervenes. Getter semantics are now **CLASSIFIED STATIC**; actual root dispatch, vptr provenance, and original Windows Booter producer/descriptor remain OPEN.

**One bounded next owner-local read-only Ghidra command** for conditional parent `+0x60` method `root+0x370=0x140E76760`, alternative table `0x140E0BE84` and original +0x60 caller:

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TRACE_STATIC_BYTES": ["0x140e76760", "0x140e0be70"], "TRACE_DATA_SITES": ["0x140e76760", "0x140e0be84"], "TRACE_INSTRUCTION_SITES": ["0x140178460", "0x1406b313d"], "__name__": "__main__"})
```

The agent should review and stop this side branch if it only leads to record/management access; prioritize `outer+0x3E8` source and nested Falcon `+0x170` invocation plus signed production image provenance. Hardware Stage 3 CONFLICT/Stage 4 PARTIAL and all no-mutation safeguards remain unchanged.

---

# 2026-11-09 09:52 PST — Conditional +0x328 candidate resolves to FUN_140578C60; table/receiver ownership still OPEN

**Read-only original Ghidra evidence:** `nvlddmkm-61742-booter-discovery-20261109-095203-574467.txt`, 4,245 original bytes / 72 physical lines, SHA-256 `4efda188613c7c9f2b8ce4864619b9a3d5d200db604cce626ce60a2332799d0d`. Driver MD5 `3fb9afac9d0e394723e830aa14e60512`, base `0x140000000`. `STATUS=COMPLETE`, 0.018 sec, `DECOMPILATION=SKIPPED`, `HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE`; this is not a physical result.

- At `0x140E76718`, `.rdata` QWORD `0x140578C60`, verified `OUTBOUND kind=DATA function=FUN_140578C60`; zero recorded inbound XREFs to the slot (virtual dispatch can still access it indirectly). The next function-pointer QWORDs are `0x140578C10`, `0x140578CA0`, `0x140578D40`; meaning and table boundary are unknown.
- Previously known `FUN_140178F50` implements `RDX-0xF0 → [root_vptr+0x328] → CFG JMP`, and caller `FUN_1406BB9A0` uses the nested state pointer from `[RDI+0x4B0]` for the parent `+0xE0` dispatch. The constructor-observed embedded-parent table head `0x140E764A8` is just `0xB8` beyond root `0x140E763F0`; the candidate offset does not prove contiguous root-table membership or effective runtime vptr identity.
- **Resolved (STATIC):** candidate QWORD and named executable target exist. **Unresolved:** method role, object/table attribution, real receiver and invocation, any link to Falcon +0x170/+0x250 or signed Windows Booter image+descriptor, cryptographic acceptance and GPU architecture selection.

**Next one bounded owner-local PyGhidra command** (existing script, no new source required):

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x140578c60"], "FULL_DECOMP_MAX_CHARS": 131072, "TRACE_INSTRUCTION_SITES": ["0x140578c60"], "__name__": "__main__"})
```

Analyze `FUN_140578C60` once and test the object-identity hypothesis using existing constructor/caller evidence. Do not repeat `FUN_1406BB9A0` or earlier Falcon string-owner decompilations. If the candidate target is unrelated, close **that** hypothesis rather than claiming there is no Booter loader.

Physical `0016` passive opener graph and original 1A70 MSI static Stop analysis remain PASS; active Stage 3 CONFLICT / Stage 4 PARTIAL, `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`. No live STOP, DMA, FLR, MMIO, firmware or Windows driver modification.

---

# 2026-11-09 09:43 PST — Parent +0xE0 CFG wrapper resolves root-object virtual dispatch +0x328 (source pointer still unverified)

**New uploaded original read-only Ghidra report:** `nvlddmkm-61742-booter-discovery-20261109-094336-040400.txt`, **2,427 bytes / 68 physical lines**, SHA-256 **`7d2677698492e00d20a87981eed7a5e5a0bfdbb597632b4f3b6ecb6287f499c0`** (computed from original upload bytes). `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, image base `0x140000000`; `MODE=PASSIVE READ_ONLY EXISTING_REFERENCE_MAP NO_DATABASE_WRITES`, `SCAN_STRINGS=SKIPPED_BY_CALLER`, `HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE`, `STATUS=COMPLETE`, 0.795 seconds, output `D:\Projects\gpu-unlock\ghidra\nvlddmkm-61742-booter-discovery-20261109-094336-040400.txt`. Report has **two complete unclipped decompiler bodies** (156/102 chars), a bounded instruction window and one exhaustive function CALL-site enumeration. It does **not** attest runtime class, original signed Booter image/header/signatures or cryptographic acceptance.

## Exact new machine evidence

```asm
140178f50 ADD RDX,-0xf0
140178f57 MOV RAX,qword ptr [RDX]
140178f5a MOV RAX,qword ptr [RAX + 0x328]
140178f61 JMP qword ptr [0x140e02aa8]
```

`FUN_140178F50` is the **verified static embedded-parent +0xE0 callback** (table `0x140E764A8+0xE0=0x140E76588`, proven in the prior 18:08 report). The new instructions establish **receiver adjustment by -0xF0**, loading the adjusted receiver's vptr, fetching its virtual **+0x328** method target, and **tail-jumping through a CFG dispatcher**. `FUNCTION_CALLS_END entry=140178f50 recorded=0 capped=False` is fully compatible with the actual `JMP` and **does not** mean the callback is inert. The target stored at `[vptr+0x328]` is **not yet read**; effective code target and runtime receiver identity are **OPEN**.

Previous constructor evidence (2026-11-06, verified machine stores in `FUN_14017AF30`) established `[outer+0x0] = 0x140E763F0` at `0x14017B23B` and `[outer+0xF0] = 0x140E764A8` at `0x14017B22B`. **Conditional alias hypothesis only:** if the callback's incoming RDX is precisely that embedded parent, `RDX-0xF0=outer`; if the outer root vptr remains `0x140E763F0`, the **candidate static pointer site** is `0x140E763F0+0x328=0x140E76718`. However the independently known embedded-parent table starts at **`0x140E764A8`**, just `0xB8` after root's known vptr, and calculated `0x140E76718` lies **`0x270` past that second table head**. **No verified root vtable extent or continuous method-array membership** exists: do not promote `0x140E76718` to a proven callback entry, or assume the dynamically selected vptr is this candidate without checking exact pointer bytes and per-instance constructor/dispatch context.

## Parent +0x50 and +0x60 callback classification

- `FUN_140179070`, static embedded-parent `+0x50` table target, was **completely decompiled**, `clipped=False total_chars=156`; its lifted C makes one CFG-guarded forwarding call with `param_1` and `param_2-0xF0`, then returns. Two inbound references are both `DATA` (`0x140E06588`, `0x140E764F8`). This is **not** a direct signed Booter byte producer, and the actual dispatched method/ABI remains unresolved without machine instructions.
- `FUN_140178460`, static embedded-parent `+0x60` table target, was **completely decompiled**, `clipped=False total_chars=102`; it is a CFG-forwarding stub with no resolved receiver or target in lifted C. Three inbound `DATA` refs (`0x140E06420`, `0x140E75CC8`, `0x140E76508`) are function-pointer/table refs, **not runtime CALL proof**. Avoid attributing signed HS loader execution or the correct AD102/GA102 class to these wrappers.

**Closed this turn:** the previously unknown machine-level forwarding mechanism for embedded-parent `+0xE0` is now a verified **outerward receiver adjustment and virtual +0x328 CFG tail jump**. The two `+0x50/+0x60` bodies are wrappers rather than concrete Booter descriptor implementations. **Not closed:** identity and value of real vptr +0x328, outer-table extent, parent receiver instance at invocation, method-target semantics and any producer/consumer link to `outer+0x3E8` or the Falcon nested `+0x170/+0x250` callbacks.

## Next bounded passive PyGhidra discriminator (no new script implementation required)

In the **owner-local imported MD5-pinned original 617.42 program**, inspect candidate original root-vptr +0x328 and actual machine instructions before decompiling another function. Existing script bounds `TRACE_STATIC_BYTES` to four 64-byte nonexecutable reads, `TRACE_DATA_SITES` to eight addresses and `TRACE_INSTRUCTION_SITES` to four; all diagnostics are read-only and terminal status/report are explicit.

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TRACE_STATIC_BYTES": ["0x140e76718", "0x140e763f0", "0x140e764a8"], "TRACE_DATA_SITES": ["0x140e76718"], "TRACE_INSTRUCTION_SITES": ["0x140179070", "0x140178460", "0x140178f50", "0x1406bba27"], "__name__": "__main__"})
```

Only if `STATIC_QWORD0_LE` at candidate `0x140E76718` is a valid executable address with a verifiable existing Ghidra function and the wrapper receiver/vptr provenance survives comparison may a follow-up targeted `TARGET_FUNCTIONS` decompilation name a potential producer. If the candidate slot is noncode, unresolved or belongs to an adjacent table, record that contradiction and investigate actual runtime vptr assignment rather than treating it as no HS call. The `+0x328` slot and wrapper `+0x50/+0x60` may be separate owners; do not conflate them.

**Absolute hold:** physical Stage 3 `CONFLICT`, Stage 4 `PARTIAL`; `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`. No `Stop`, DMA, MMIO, firmware execution, FLR, flashing, NVRAM changes or signed-image acceptance test.

---

# 2026-11-09 09:24 PST — Three Windows HS string owners independently reconfirmed; earlier full decompilation and callback registration must not be repeated

**New original user-run read-only report:** `nvlddmkm-61742-booter-discovery-20261109-092446-213315.txt`, **2,510 bytes**, **36 physical lines**, SHA-256 **`fced743031b238a7fe22859de4f5ff5a541961824375d95e62084573ef410bd9`**. Actual pinned Windows NVIDIA `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, image base `0x140000000`; `SCAN_STRINGS=SKIPPED_BY_CALLER`; `HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE`; final `STATUS=COMPLETE REPORT=D:\Projects\gpu-unlock\ghidra\nvlddmkm-61742-booter-discovery-20261109-092446-213315.txt`; elapsed 0.100 s. **DECOMPILATION=SKIPPED**; `COMPLETE` means only that requested static data-ref inspection finished.

| Data anchor | Reported exact referring function(s) and instructions | Status vs cumulative 2026-11-06 research |
|---|---|---|
| `flcnCreateHsOvlSigBlob_GA10X` at `0x140D2EB10` | **8/8 uncapped DATA XREFs**, all in `FUN_140BF2740`: `0x140BF2887`, `0x140BF2894`, `0x140BF2968`, `0x140BF297C`, `0x140BF2AAF`, `0x140BF2AB9`, `0x140BF2ADD`, `0x140BF2AE7` | **CONFIRMS PRIOR OWNER**. This function was fully and unclipped decompiled on 2026-11-06 14:01 as an HS overlay-signature word-rearrangement routine. Separate 14:09 physical instruction records show conditional `FUN_1417E8550` assignment to nested dispatch slot **`+0x250`**. Neither transform nor callback registration is proof of actual invocation, cryptographic signing or signed Booter provenance. |
| `flcnLoadAndExecuteHsBinaryViaDma_GA10X` at `0x140D2EAE0` | **6/6 uncapped DATA XREFs** `0x140BF396F`, `0x140BF397C`, `0x140BF3A44`, `0x140BF3A4F`, `0x140BF3A99`, `0x140BF3AA6`, all inside `FUN_140BF3880` | **CONFIRMS PRIOR OWNER**. This loader and nested `+0x170` registration had already been decompiled and established, but effective runtime caller and signed production byte descriptor remain unknown. |
| `RmAllocIsoSysMemFromCarveout` at `0x140D0AD10` | **1/1 uncapped DATA XREF** `0x1402B2DAE` in `FUN_1402B2980` | **CONFIRMS PRIOR OWNER**. Complete 2026-11-06 14:01 decompilation shows RM option read and `param_1+0xA10` bool assignment; this function is **not** a direct HS signed-Booter image/descriptor producer. |

**Evidence classification:** all 15 inbound references are **DATA**, not actual code CALL invocations, and each `INBOUND_ROOT` is uncapped. Report labels each data anchor as `.text` defined, which is Ghidra's mapped-block label; do not assume the bytes are instructions. The report does **not** newly decompile these functions or establish invocation of either Falcon HS loader `+0x170` or overlay signature transform `+0x250`. This resolves an **outdated subtask in the separate Booter ledger**, not the signed production Booter gate.

**Reconciliation with authoritative cumulative notes:** 2026-11-06 **14:01** already completed `FUN_140BF2740` and `FUN_1402B2980`; **14:09** proved `FUN_140BF2740` installed in conditional `+0x250`; **14:16** completed its paired `+0x258` helper and found the `+0x250` transfer scan capped; **16:25** completed `FUN_140BF1390` (preparation `+0xB0`); **18:15** pinned embedded parent `+0x50/+0x60` to `FUN_140179070/FUN_140178460`, proved `+0xE8` no-op and found `+0xE0` `FUN_140178F50` is a CFG forwarding wrapper with **unknown actual target**. Do **not** re-run the now-known string owner decompilations or claim those raw sites supply signed Booter bytes.

**One next bounded, owner-machine PyGhidra read-only command, requiring the pinned original program:**

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x140179070", "0x140178460"], "FULL_DECOMP_MAX_CHARS": 131072, "TRACE_FUNCTION_CALLS": ["0x140178f50"], "TRACE_INSTRUCTION_SITES": ["0x140178f50"], "__name__": "__main__"})
```

The existing script validates driver MD5, image base and name, uses Ghidra's existing function/Listing data without modifying the program, and prints **`STATUS=COMPLETE|PARTIAL|ERROR` and `REPORT=...`** at completion. Decompile the parent slot targets, inspect effective CFG forwarding machine registers and the `outer+0x3E8` descriptor chain. Do not infer a producer from the CFG helper or registration alone. The original driver/Ghidra program is absent from the agent runtime; this new decompilation **has not been run**.

**All active gates unchanged:** `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`, signed Windows production Booter producer, real HS invocation, AD102/GA102 selector, cryptographic acceptance and cold-boot recovery **OPEN**.

---

# 2026-11-06 13:44 PST — HS overlay signature blob string untraced; vtable-head DATA refs and constructor call checked

User-supplied Ghidra strings (two batches) compared against existing investigation and Ghidra ledger, not simply string names. Critical **new UNTRACED string** `flcnCreateHsOvlSigBlob_GA10X` at VA `0x140D2EB10` (no retained exact previous analysis). Secondary untraced `RmAllocIsoSysMemFromCarveout` at `0x140D0AD10`. Other new `HOST9`, `_ORI_ORI compile type=2`, `VESA DMT` and two NOT_DEFINED six-byte candidates have no established Falcon/Booter dataflow. Previously investigated: display GA102/AD102 diagnostic strings through partially clipped `FUN_1415A8FB0`; `flcnLoadAndExecuteHsBinaryViaDma_GA10X` fully decompiled in `FUN_140BF3880`; `flcnWaitForResetToFinish_GA102` fully decompiled `FUN_140BF4F00`; ga100/ga10x/ad10x suffix selection in `FUN_1401AA0E0`; GSP/UCODES/GSP log filenames in `FUN_1400F35F0` selector and `FUN_1400F3350` reader, plus GSP staging; `fwlogging_kernel_*` resource family in complete `FUN_1401AA580` logging initializer. Being investigated != runtime authenticated/used.

New original user Ghidra report `nvlddmkm-61742-booter-discovery-20261106-134412-095150.txt` SHA-256 `5758270902695f785a915d27185c055fe2bd25f0a472cf45ec81b6254aec636f`. Pinned 617.42 nvlddmkm.sys MD5 `3fb9afac9d0e394723e830aa14e60512`; STATUS=COMPLETE, DECOMPILATION=SKIPPED, no Ghidra/driver/GPU mutation. At `0x14179E83A`, `LEA RCX,[RDI+0xF0]`, then `0x14179E841 CALL FUN_141752AA0`, EAX status checked. This is a direct builder call on the embedded context, NOT nested+0x170 HS callback invocation.

Four `.rdata` vtable-like head DATA references: `0x140EDE0D0 -> 0x140EDE068`, `0x140EDE0E8 -> 0x140E9CD80`, `0x140EDE100 -> 0x140E8EC18`, `0x140EDE188 -> 0x140EBF210`. Each root has 3 inbound DATA refs, two from `FUN_14179E530`; no actual indirect invoker established by these heads alone.

Next single bounded passive `TRACE_DATA_SITES=["0x140d2eb10","0x140d2eae0","0x140d0ad10"]` to identify owners of new signature-blob string and memory carveout string against fully classified HS loader string. Only follow real instruction XREF. HS production signed-image descriptor and live nested invoker remain OPEN. Active gates all false; stable notes/plan in place, immutable audit unchanged.

---
# 2026-11-06 13:34 PST — PAGEdBIN and nested HS dispatch co-constructed under the same 0x588 outer

Report nvlddmkm-61742-booter-discovery-20261106-133402-701773.txt, SHA-256 09f119d59eaf7678eeca9574f4a789001b6d0b9f32b661a9a06fbccdd8c9bf05; source 617.42 nvlddmkm.sys MD5 3fb9afac9d0e394723e830aa14e60512, complete unclipped FUN_14179E530, three instruction windows, STATUS=COMPLETE, no database or GPU changes. Expanded headers Pasted text(3).txt SHA-256 806afe7cf2675794575178ea532a6dee00fbcdc5bb9ee2342f0959ba60b6bfcc.

FUN_14179E530 allocates/reuses 0x588-byte outer, reads interfaces 0x74BC71 / 0x34A6D6, calls FUN_141752B20(outer+0xF0), registers PAGEdBIN callback table via FUN_14179DE70(outer,...), calls FUN_14173CE00(outer+0x08), then on success CALLS FUN_141752AA0(outer+0xF0), which previously proved the nested 0x9B0 Falcon HS dispatch builder. Published nested pointer at outer+0x108 (embedded+0x18). PAGEdBIN callback outer+0x148 and nested HS callback nested+0x170 belong to the same outer construction but distinct objects. Outer+0x170 data-pointer callback is NOT nested+0x170 HS loader. Two outer allocation sizes 0x588 and 0x3550 occur on separately decompiled constructor paths. Physical selectors, real callback invoker and signed Booter image/header/signature/patch provenance OPEN.

Exact 0x588 static interface heads: 0x140EDE0D0, 0x140EDE0E8, 0x140EDE100, 0x140EDE188. Next bounded read-only TRACE_DATA_SITES on those four heads and TRACE_INSTRUCTION_SITES at 0x14179E837 / 0x14179E84A; infer no invocation from a constructor call or DATA XREF.

Expanded MZ/DanS/Rich/PE header adds standard build metadata, 32 sections, 0 COFF symbols, debug/load-config directories, but no signed Booter source or private PDB. Large MZ header XREF total is static, not Booter executions. Audit immutable, all active gates false.

---
# 2026-11-06 13:26 PST — PAGEdBIN callback direct-leads closed, PAGErGEN nested index; construction helper overlap found

User report `nvlddmkm-61742-booter-discovery-20261106-132623-568677.txt` SHA-256 `b0b4ad25cad51ec9633ee8604381f683aa48742c6f8b20753ad558f7ec18cdb8`; expanded PE header `Pasted text(2).txt` SHA-256 `388d641ece8594b0cee9db4dcad087a5456524d7cd1be8bf094587d8c6817576`. Windows 617.42 driver MD5 `3fb9afac9d0e394723e830aa14e60512`. Complete `clipped=False` static bodies `FUN_140A75B10`, `FUN_140A74A20`, `FUN_140A74A50`; bounded two 64-byte PAGErGEN samples; `STATUS=COMPLETE`, no Ghidra/GPU/firmware writes.

`FUN_140A75B10` writes `param_3+0x10=0xC` and PAGEdBIN addresses at `+0,+8,+0x18,+0x20,+0x28`; its caller `FUN_140A74FA0` overrides `+0x20/+0x28` after the helper returns. `FUN_140A74A20` and `FUN_140A74A50` select one section-data pointer based on `param_2+0x2DE` and return zero. None directly constructs or invokes production HS Booter load; direct candidate hypothesis CLOSED (STATIC), source/consumer elsewhere not excluded.

`PAGErGEN` `0x141D8C040` continues qword triples (`1,0x27,pointer` / `1,0x14,pointer`). At pointer `0x141D93388`, packed two-dword pairs and in-range pointers `0x144925640`, `0x1448BC8B0`, `0x144894268`, with `9` in neighboring qword fields, suggest two-level structured index. Not confirmed archive/firmware. Expanded PE header x64 PE32+ with 32 sections, COFF symbol pointer/count zero, debug/load-config directories present but not private symbols; `PAGEbMSR` uninitialized raw zero; `INIT` discardable code. No Booter linkage.

**Important shared initializer lead:** `FUN_14179E530` calls `FUN_141752B20` at `0x14179E7E6`, registers `FUN_14179DE70` at `0x14179E820`, then calls `FUN_14173CE00` at `0x14179E828`. Independently established outer 0x3550 object constructor `FUN_14017AF30` calls **both** `FUN_141752B20` and `FUN_14173CE00` alongside HS nested dispatch builder `FUN_141752AA0`. This is a constructor-family/static helper overlap, NOT proof of same allocation/object alias or HS callback invocation. Correct earlier categorical “distinct unaliased table” phrasing; object identity OPEN.

Next bounded `TARGET_FUNCTIONS=["0x14179e530"]`, `TRACE_INSTRUCTION_SITES=["0x14179e7e6","0x14179e820","0x14179e828"]`, `SCAN_STRINGS=False`. Require exact receiver/allocated-object pointer chain. No section-wide scan; all active gates false, immutable recovery audit untouched.

---

# 2026-11-06 13:19 PST — PAGEdBIN callback family and PAGErGEN pointer records classified

User-run report `nvlddmkm-61742-booter-discovery-20261106-131915-948969.txt`, uploaded SHA-256 `6b1eedafbb36f07f80ca7c7c887428692c511e269f30aac1f1ae42761e68b1e1`, original 617.42 driver MD5 `3fb9afac9d0e394723e830aa14e60512`. Exact `TARGET_FUNCTIONS=["0x14179de70","0x140a74ca0","0x140a74fa0"]`, all unclipped `clipped=False`, bounded `TRACE_STATIC_BYTES=0x141D8C000` 64 bytes, final `STATUS=COMPLETE`, `HARDWARE_ACTION=NONE`, `GHIDRA_MUTATION=NONE`.

`FUN_14179DE70` reads 16-bit selector `param_2+0x10`, registers a class-dependent callback table at `param_1+0x130..+0x1B0`. Verified direct incoming CALL `0x14179E820` (other refs DATA). For the group-1 low-bits 8/9 branch it registers `FUN_140A74CA0` at +0x140, `FUN_140A74E50` at +0x148, `FUN_140A74FA0` at +0x150; other branches use alternates and fallbacks. Critically **this separate interface also assigns +0x170** to `FUN_140A74A20`, `FUN_140A74A50`, `FUN_140A75FC0`, `FUN_140A76000`, `FUN_140A76100` or fallback, NOT `FUN_140BF3880`. Matching displacement is no alias to the separately constructed 0x9B0 Falcon HS dispatch instance whose `FUN_1417E8550` installed `+0x170` HS loader.

`FUN_140A74CA0` full body writes PAGEdBIN addresses at output `param_3+0x00,0x18,0x28,0x40`, chooses paired VAs by opaque guard result, and writes additional scalar fields `+0x08..+0x54`. No proven meaning for scalars, no Booter code/signature parser or HS loader call. `FUN_140A74FA0` full body directly calls `FUN_140A75B10`, then publishes PAGEdBIN pointers at output +0x20 and +0x28; callee not yet classified.

PAGErGEN initial 64-byte read yields 64-bit sequence `1,0x27,0x141D933A0,1,0x27,0x141D93388,1,0x27`, suggesting repeated 24-byte records with pointers into same mapped non-executable section. Record format, pointed-to content, size/type semantics and any relation to PAGEdBIN or Booter are not proven. No broad scan authorized by section name/size alone.

Next single bounded read-only Ghidra run: `TARGET_FUNCTIONS=["0x140a75b10","0x140a74a20","0x140a74a50"]`, `TRACE_INSTRUCTION_SITES=["0x14179e820"]`, `TRACE_STATIC_BYTES=["0x141d93388","0x141d8c040"]`. Preserve safe status; original recovery audit immutable; stable notes and plan updated in place, no numbered copies.

---

# 2026-11-06 13:05 PST — PAGEdBIN callback +0x148 registered, PAGErGEN 79.45 MiB PE section lead

User-run file `nvlddmkm-61742-booter-discovery-20261106-130501-043021.txt`, SHA-256 `863dced885466ef8ab2b50cbb6864f9f72199b692626a960a7872257b8b948d9`, four local code instruction sites and four 64-byte initialized non-executable PAGEdBIN samples, driver MD5 `3fb9afac9d0e394723e830aa14e60512`, final `STATUS=COMPLETE`, `DECOMPILATION=SKIPPED`, no DB/GPU changes. `FUN_14179DE70` writes callback `FUN_140A74E50` to `[R8+0x148]` at `0x14179DF28/2F` and `0x14179DFAE/B5` on condition-dependent paths. Adjacent `[R8+0x140]=FUN_140A74CA0` (or fallback `FUN_1400061B0`) and `[R8+0x150]=FUN_140A74FA0` are exposed. The exact selector dataflow, runtime invoker and object alias with separate `FUN_1417E8550` HS dispatch `[R9+0x170]` are unknown. No direct calls established.

PAGEdBIN `0x146D01000`: first four LE qwords each 12, `+0x30` repeats `0xDEADBEEF` four times, `+0x20` opaque bytes; three other 64-byte samples at `0x146D01DE0`, `0x146D046A0`, `0x146D05AA0` apparently high entropy but **no verified format/signature interpretation**.

User pasted PE header sections `Pasted text(1).txt`, SHA-256 `243ea7ef5cfdb0da11616f6463a5b5416185d1450f93386a7a2f4bbae116852f`: **PAGErGEN** is separate large **79.45 MiB** initialized readable non-executable section `0x141D8C000 .. 0x146D00017` (PE raw `0x4F74200`, virtual `0x4F74018`, char `0x40000040`); **PAGEdBIN** virtual `0xFD40`, R/W non-X. Neighbor PE layout is not a proven Booter archive; PAGErGEN loaded block and content not yet verified.

Next one read-only bounded run: `TARGET_FUNCTIONS=["0x14179de70","0x140a74ca0","0x140a74fa0"]`, `TRACE_STATIC_BYTES=["0x141d8c000"]`, `SCAN_STRINGS=False`. Confirm interface role and reject unrelated table paths; do not turn 64-byte sample or physical section size into firmware provenance. Active gate flags all false, recovery unverified; audit unchanged, stable docs in place.

---

# 2026-11-06 13:00 PST — PAGEdBIN fixed/conditional section pointers exposed by FUN_140A74E50

User-run `nvlddmkm-61742-booter-discovery-20261106-130011-003670.txt`, SHA-256 `bf8481618b29cc16182e818a12624e0a980331cb0eb25ac8ac5c29163808699c`, original 617.42 `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`. Full `FUN_140A74E50` decompilation `clipped=False` plus exact `0x140A74EBB` and `0x140A74ECD` machine windows, final `STATUS=COMPLETE`, no driver/DB/GPU writes.

**Proven (static):** output `param_3` gets constant pointers into initialized non-executable mapped `PAGEdBIN`: `+0x20=0x146D01DE0`, `+0x28=0x146D01B30`; guarded-return-dependent pointers `+0x30=0x146D01330/0x146D01430`, `+0x38=0x146D01004/0x146D0100C`, `+0x48=0x146D01000/0x146D01008`, `+0x58=0x146D046A0/0x146D05AA0`, `+0x60=0x146D010E0/0x146D01140`, `+0x70=0x146D010B0/0x146D01110`; `+0x40=4` (dword), `+0x68=0x30` (dword). Machine `0x140A74EC6 MOV [RBX+0x40],4` and `0x140A74ECD MOV [RBX+0x48],RAX`. This is a conditional **table-of-pointers initializer**, **not** demonstrated signed Booter image-header-signature provenance, descriptor to `FUN_140BF3880` or actual execution. Do not conflate its `param_3` struct with loader `param_3` since the `+0x40` field is a scalar here.

**Next grounded source/consumer lead:** reference manager lists DATA references at `0x14179DF28`, `0x14179DF2F`, `0x14179DFAE`, `0x14179DFB5` to function entry, potentially function-pointer installs; not CALLs. Passive exact `TRACE_INSTRUCTION_SITES` on four sites and `TRACE_STATIC_BYTES` on four 64-byte non-executable anchors `0x146D01000`, `0x146D01DE0`, `0x146D046A0`, `0x146D05AA0`. Full driver scan unnecessary. Main HS invoker/production signed descriptor remains OPEN. Immutable audit untouched; four active gates false.

---

# 2026-11-06 12:43 PST — PAGEdBIN mapped data section verified, exact XREF owner identified

User Ghidra PE listing and uploaded `pagedbin-block-metadata.txt`, SHA-256 `7081cd72e8a168a4cc0027adf4cb76fc12a1f69efb52c8cb2e6b2f5e156c43af`. Section header `0x140000670`, name `PAGEdBIN`, PE `VirtualSize=0xFD40`, `SizeOfRawData=0xFE00`, `PointerToRawData=0x06C6A400`, `VirtualAddress=0x06D01000`, `Characteristics=0xC0000040`. Actual mapped Ghidra block `0x146D01000..0x146D10FFF`, size 65536, initialized, readable/writable, **not executable**. PE raw/virtual sizes are distinct from mapped block length; Ghidra instruction text beginning `OR AL,0x0` at section start is not runtime code evidence. This closes mapped-block existence/attributes, not image identity.

One header reference at `0x14000067C` and two same-function XREFs to start `0x146D01000`: `FUN_140A74E50:0x140A74EBB` and `FUN_140A74E50:0x140A74ECD`. **New narrowly grounded read-only lead:** decompile `FUN_140A74E50` and trace these two instructions; classify exact section consumer before further data scans. No proof of embedded signed Booter, descriptor source, actual Falcon callback invocation, physical GA102/AD102 selection or signature acceptance. All hardware gates false; stable docs updated in place; immutable audit untouched.

---

# 2026-11-06 12:43 PST — +0x168 callback pair fully decompiled; exported comments are mostly Ghidra-generated

`nvlddmkm-61742-booter-discovery-20261106-124302-396219.txt`, SHA-256 `6093ba7017d0f4da50786569287101091705d264e8fed7d4e34fb572fca9ca44`, driver MD5 `3fb9afac9d0e394723e830aa14e60512`; both `FUN_140BF5ED0` and `FUN_140BF7E10` have `clipped=False` complete decompilation, `STATUS=COMPLETE`, `ELAPSED_SECONDS=0.264`, no Ghidra/driver/GPU changes. Both call the same register-style backend `FUN_1406B6470(param_1,param_2,0x110,(param_3>>8)&0xFFFFFFFF)` and, when `FUN_1402E8360(param_1,param_2)>0x5F`, write `0x128` with `(param_3>>40)&0x1FFFF` versus `(param_3>>40)&0x1FF`. Direct HS descriptor/producer/callback-invoker lead **CLOSED (STATIC)**. `param_3` is used as a packed integer here, distinct from the *third-argument signed descriptor of `FUN_140BF3880`*. Existing inbound references are DATA, not CALL.

Uploaded `Comments.csv`, SHA-256 `708baea6b89f3223a9ae2b8797a39f5ba9b329623812d82b8339114bbe2a4731`, fully parsed: 1,109 rows (403 Plate, 368 EOL, 338 Pre). Dominated by imported-image thunk/name annotations, unbound-import ordinal labels and CRT library matches; no comments in exact Falcon HS family/dispatch initializer/FWSEC-init VA windows. PE header `0x140000670` annotates section name `PAGEdBIN` — **new bounded section metadata candidate only**, not proof of production Booter archive/data. Pre comments `0x1410F634C wPreRelocCRCCopy`, `0x1411A5570 nvDumpConfig` and `0x141002C38 .NET PDB Info` are low-priority/metadata labels, not direct Booter evidence.

Next inspect only mapped Ghidra memory-block metadata for `PAGEdBIN` (not whole-driver strings/bytes); require start/end, initialized, R/W/X and report status. Focus remaining P0 on actual published nested Falcon invoker and signed HS loader descriptor producer. Both stable research docs updated in place. Active hardware gates false; immutable audit untouched.

---

# 2026-11-06 09:42 PST — Windows Falcon HS fallback and symbol-table inventory

User-run report `nvlddmkm-61742-booter-discovery-20261106-094251-216458.txt`, SHA-256 `51e1db4c88aa8a48e297ff0e869e8740457b2c753801cb1d1fa1aa72dfd8d09f`, Windows 617.42 driver MD5 `3fb9afac9d0e394723e830aa14e60512`: four bounded instruction windows in `FUN_1417E8550`, final `STATUS=COMPLETE`, `DECOMPILATION=SKIPPED`, `HARDWARE_ACTION=NONE`, `GHIDRA_MUTATION=NONE`. On a shown upper-selector group `0x20`, low-five-bit value 5..10, `FUN_140092D80` is registered to `[R9+0x170]` (not-supported fallback). Otherwise visible branches join `FUN_140BF3880` real HS loader registration; full entry reachability and host physical selector unknown. Adjacent `[R9+0x168]` targets `FUN_140BF5ED0` / `FUN_140BF7E10` based on R10D/CL-dependent branch; `[R9+0x178]` can receive `FUN_140BF4D10`. Registration is not actual invocation.

Uploaded `Symbols.csv`, SHA-256 `6bdf1cac942f344f665d4b8569141f3b8521c913445387096122adb9f5fc3c46`, 117,302 Ghidra symbol rows; no descriptive Booter, GSP, SEC2/FWSEC, Falcon/flcn, bindata/ucode, GA102/AD102, PLM or signature names. Mostly autogenerated FUN_ names, 71 user-defined decompiler override instruction labels. Grounded static ref counts: HS loader `FUN_140BF3880` 4; adjacent `FUN_140BF5ED0` 6 and `FUN_140BF7E10` 4; neighboring `FUN_140BF4D10` 4; reset `FUN_140BF4F00` 6; fallback `FUN_140092D80` 5670; constructor thunk `thunk_FUN_1417e99b0` 2. Counts are Ghidra symbols' existing references, NOT run-time call counts; no signature or Booter bytes proven.

Next read-only `TARGET_FUNCTIONS=["0x140bf5ed0","0x140bf7e10"]` with `SCAN_STRINGS=False`; classify only these grounded `+0x168` callbacks, then prioritize actual nested-object caller and production descriptor source. No versioned docs, no active changes, immutable audit untouched.

---

# 2026-11-06 09:39 PST — Exact same R9 callback destination for HS loader +0x170

User attachment `nvlddmkm-61742-booter-discovery-20261106-093943-217331.txt`, SHA-256 `e427cc0811e124ae56aae7e51d5b0118d52ca86a1fbcd39a0651d910535ed494`, correct 617.42 driver MD5 `3fb9afac9d0e394723e830aa14e60512`. Three local instruction sites resolved inside `FUN_1417E8550`, final `STATUS=COMPLETE`, `DECOMPILATION=SKIPPED`, elapsed 0.013 seconds, no Ghidra DB or hardware changes.

**Proven:** `0x1417E8E3E LEA RAX,[0x140BF3880]`, `0x1417E8E45 MOV [R9+0x170],RAX`; same initializer previously directly wrote reset/wait callback `FUN_140BF4F00` or `FUN_1406B8BA0` to `[R9+0x130]`. In the captured direct group-`0x40` branch, low-five-bit selector 1..7 first writes `FUN_140BF5ED0` to `[R9+0x168]`, then `FUN_140BF3880` to `[R9+0x170]`. `0x1417E8EDA JNZ 0x1417E8E3E` also joins the loader registration when the visible predicate's upper group differs from `0x20` *and this specific ingress is reached*. Complete selector coverage and physical GPU mapping are NOT proven. This strengthens shared dispatch initializer register identity; no runtime invocation or source bytes.

Next bounded `TRACE_INSTRUCTION_SITES=["0x1417e8e9c","0x1417e8ee9","0x1417e8eec","0x1417e8f05"]` only if closing selector/fallback conditions; afterward trace actual published nested object consumer and HS loader argument-3 producer. No new versioned docs, no mutation, all active gates false.

---

# 2026-11-06 09:35 PST — Exact Falcon reset/wait registration slot established at +0x130

New user-run read-only instruction report: `nvlddmkm-61742-booter-discovery-20261106-093536-300196.txt`, SHA-256 `0ae8f74d9a4bc08442418f42d65e65a56679ffe0434e5bba3e1e2e046d5aea5d`; driver MD5 `3fb9afac9d0e394723e830aa14e60512`, image base `0x140000000`; final `STATUS=COMPLETE`, `DECOMPILATION=SKIPPED`, `HARDWARE_ACTION=NONE`, `GHIDRA_MUTATION=NONE`, elapsed `0.045` sec. The prior callout "exact registered slot must be checked" is **CLOSED (STATIC)** for this callback only.

Within `FUN_1417E8550`, if `(R8D & 0xFFFFFFE0)==0x20` and `5 <= (R8D & 0x1F) <= 10`: `0x1417E8C5C LEA RAX,[0x1406B8BA0]` then `0x1417E8C63 MOV [R9+0x130],RAX`. Otherwise: `0x1417E8C6C LEA RAX,[0x140BF4F00]` then `0x1417E8C73 MOV [R9+0x130],RAX`. This is **registration**, not invocation; `R9` is the instruction-level destination. `FUN_140BF4F00` is the previously decompiled `flcnWaitForResetToFinish_GA102` reset/wait routine with `param_2+0x4B0` parent read. Physical GPU/runtime `R8D` selection, alternate callback `FUN_1406B8BA0` implementation, exact receiver alias and execution remain unproved.

The **distinct** HS loader callback `FUN_140BF3880` is registered separately at `+0x170` in the same initializer by prior static evidence; do not conflate `+0x130` with `+0x170`. Next smallest review: bounded `TRACE_INSTRUCTION_SITES=["0x1417e8e3e","0x1417e8e45","0x1417e8eda"]` to check exact HS loader slot predicates and receiver in the same function. Production Windows signed Booter descriptor bytes, actual nested-object invoker, two physical GPU class selection and signature acceptance remain OPEN. All hardware modification gates false; immutable audit unchanged. Preserve stable in-place investigation and execution map paths.

---

# 2026-11-06 09:27 PST — SEC2/FWSEC init versus GA102 Falcon reset/wait: bounded original driver evidence

User-run report `nvlddmkm-61742-booter-discovery-20261106-092744-805630.txt`, SHA-256 `6f0594b57ec295a73dc6c4814b9643aa768763ab8047b4ccb2d38c2463df28dd`. Expected Windows 617.42 driver MD5 `3fb9afac9d0e394723e830aa14e60512`, VA base `0x140000000`; two complete unclipped Ghidra decompilations, final `STATUS=COMPLETE` with report path, `HARDWARE_ACTION=NONE`, `GHIDRA_MUTATION=NONE`.

- `FUN_1401858E0`: SEC2/FWSEC/DEVINIT orchestration/configuration; `param_2+0x298` init guard, conditional qword `param_2+0x2A0`, `+0x634` 0x30-byte setup; calls `FUN_140180B50` or `FUN_1405EB540` depending on `+0x2B0`, checks `FUN_1401812C0`; reads `RMExecuteFwsecOnSec2`, `RMDevinitBySecureBoot`, etc. Opaque guarded calls and helper effects are NOT proof of signed Booter source. Incoming CALL at `0x1400F2402`; other incoming refs DATA.
- `FUN_140BF4F00`: `flcnWaitForResetToFinish_GA102` routine reads `param_2+0x4B0` as a parent pointer; polls/reset-controls via `FUN_1406B63F0`/`FUN_1406B6470` offset `0x40` and `FUN_1401148A0(...,FUN_140BF5170,...)`. DATA refs `0x1417E8C6C` and `0x1417E8C73` occur **inside known dispatch initializer `FUN_1417E8550`**, which also conditionally installs `FUN_140BF3880` at `+0x170`. Existing nested dispatch construction writes back-pointer `dispatch+0x4B0=embedded_parent`. Identical field offset plus common initializer is a strong object-family lead but NOT a proven same-instance invocation, exact registration slot, source descriptor or runtime execution.
- Next passive command: `TRACE_INSTRUCTION_SITES=["0x1417e8c6c","0x1417e8c73"]` on the pinned imported Windows driver, with `SCAN_STRINGS=False`, to identify the assigned callback slot. Stop generic `+0x170`/`+0x2710` searches. Production signed Booter image/header/signature/patch provenance, exact `FUN_140BF3880` argument-3 producer, actual nested instance invoker and runtime AD102/GA102 acceptance all remain OPEN.

Documentation policy: update existing stable `research/nvidia-tensor-core-unlock-investigation.md` and `research/nvidia_unlock_evidence_to_execution_map.md` in place; no versioned copies. All active authorizations remain false; no hardware or Ghidra DB writes and immutable process/recovery audit unchanged.

---

# 2026-11-05 18:06 PST — FUN_140AF28A0 is SEC2/ACR option-to-config initializer (not Booter producer)

User-run report `nvlddmkm-61742-booter-discovery-20261105-180605-612650.txt` on original Windows NVIDIA 617.42 `nvlddmkm.sys`, MD5 `3fb9afac9d0e394723e830aa14e60512`, Ghidra VA `0x140AF28A0`: unclipped full decompilation, `STATUS=COMPLETE`, `HARDWARE_ACTION=NONE`, `GHIDRA_MUTATION=NONE`. Incoming references: direct CALL `0x140AF24D9`; DATA `0x14145A068` (not invocation proof).

`FUN_14016AAD0` reads named RM options and the target routine sets configuration bytes: `RmAcrSigningAlgo` +0x289; `RmUseAutoAcr` +0x28A; `RMDisableAcr` +0x28B (and conditionally clears +0x2A0); derived +0x28C; `RMAcrExecuteOnSec2` +0x28F; `RmEnableRiscvLs` +0x291; `RMAcrUseCeForShadowCopy` +0x295; `RmAllowPrivSecDisabled` +0x29C; three 2-bit `RmBootFromHs` settings at +0x29D..+0x29F (01 writes one, 11 writes zero, 00/10 preserve existing bytes); `RmPmuBootstrapMode` and later `RMEnableAcrRiscv` affect +0x2A0; `RmSwapAcrRegions` +0x439. `RmDisableGsp` query return is not visibly used. All claims are static; actual registry values, GPU class mapping and runtime flags are unobserved.

**Disposition:** previous unreviewed XREF owner now **CLOSED (STATIC) as configuration only**. No production signed Booter `IMAGE_PROD`/header/signature bytes, descriptor producer or specific 0x9B0 Falcon dispatch invoker in this function. Do not rerun its decompilation or infer that option flags disable hardware security. Continue read-only stock Windows firmware-byte provenance and confirmed `FUN_140BF3880` third-argument/invoker tracing. Physical/crypto acceptance, AD102+GA102 behavior, detach/unlock/recovery remain OPEN; all active gates false. New cumulative note in `research/nvidia-tensor-core-unlock-investigation.md`; active execution map updated as a snapshot. Immutable audit untouched.

---

# 2026-11-05 17:56 PST — Windows GA10x/TU10x UCODES v1 header inventory complete, Booter source unresolved

**Primary evidence:** user-pasted complete JSON from read-only `python .\research\windows_firmware_provenance.py --root "$env:SystemRoot\System32\DriverStore\FileRepository" --output .\windows-61742-firmware-inventory-v2.json` on Windows, `schema_version=1`, `STATUS=COMPLETE`, no warnings, `files_truncated=false`, `facts.hardware_modified=false`. No new Ghidra run or installed-file access in this assistant environment. The earlier default two-root `STATUS=PARTIAL` was accurate due to absent standalone `System32\drivers\nvlddmkm.sys`; the explicit DriverStore-only scope is complete and must not retroactively rewrite that older report.

**Pinned DriverStore directory** `nv_dispsi.inf_amd64_ccd7fbb71bb72370`: `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, SHA-256 `db407b964c11441642a1642a0922c35990de974c267a08537c3432765365f84b`; `gsp_ga10x.bin` 27,043,992 B, SHA-256 `f89d8f615e6146ed2808df974b7af7f1aabda876596391b0aabcc32ba293c34f`; `ucodes_ga10x.bin` 58,215,936 B, SHA-256 `eed53d76248582d71c629e8b6230aee48ce673c91d782301c94e98ac6a6db7aa`. Also pinned `gsp_tu10x.bin` SHA-256 `35fcaefc3edcc1d288c449b26e62cf069227e283f9cc07d71f1e6a83a0073d9d` and `ucodes_tu10x.bin` SHA-256 `6027ab3736f733b5a06e6e61aaae957d1f990426a263849ebcfa8a49eeb4a5d0`.

**New user-recorded header facts:** `ucodes_ga10x.bin`: `NVUCODES` v1, `numEntries=1293`, fingerprint `0x2d38befecdb703a6`. `ucodes_tu10x.bin`: `NVUCODES` v1, `numEntries=496`, fingerprint `0x8d1990ab6b98ae2b`. NVIDIA Linux source `615.78.08 src/nvidia/src/kernel/core/bin_data_pvt.h` specifies a 24-byte header and defines the count as **build-time possible bindata files**, **not an enumerated record list**. An older user-run report already found the GA10x fingerprint bytes once within installed GSP `.fwimage` at absolute offset 17,492,248. That pairing observation was **not rerun in this turn**; it supports static file association only, not signature acceptance or active Booter loading. GSP `.fwsignature_ad10x` and `.fwsignature_ga10x` ELF sections (4,096 B each) are **not** the production SEC2 Booter signature records.

**Gates:** scoped firmware file+header inventory **PASS (USER-RUN)**. Static GSP/UCODES pairing **PARTIAL (previous observed matching fingerprint)**. Actual Windows production Booter `IMAGE_PROD`/header/signature/patch byte source, `FUN_140BF3880` third-argument image descriptor, *specific nested 0x9B0 instance* indirect invoker, physical GA102/AD102 selection and cryptographic acceptance **OPEN**. Linux 615.78.08 generated AD102/GA102 Booter production `IMAGE_PROD` fields are embedded (`EXTERNAL: NO`); do not infer same Windows packaging.

**Single bounded next Ghidra target:** read-only decompile code containing `0x140AF28A0`, an unreviewed `RMAcrExecuteOnSec2`/`RMEnableAcrRiscv`/`RmBootFromHs` configuration XREF owner. It may only select registry/config values; if so eliminate this branch, not escalate to speculative firmware provenance. No generic callback-offset rescan.

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x140af28a0"], "__name__": "__main__"})
```

**Docs:** cumulative notes `research/nvidia-tensor-core-unlock-investigation-v122.md` prepend new primary findings; authoritative `research/nvidia_unlock_evidence_to_execution_map.md` is updated in place as a status snapshot, not a diary. Immutable process/recovery audit unchanged. `CAN_DETACH=false`; `CAN_UNLOCK=false`; `CAN_FLASH=false`; `RECOVERY_VERIFIED=false`. No firmware or GPU writes.

---

# 2026-11-05 — Installed Windows 617.42 firmware source pinned; Booter supplier remains open

**Evidence type:** user-supplied output of committed `windows_firmware_provenance.py`, read-only local Windows DriverStore file inventory. This **is not a new Ghidra decompilation or GPU runtime trace**. Original `STATUS=PARTIAL` reflects one absent default second root `C:\\WINDOWS\\System32\\drivers\\nvlddmkm.sys`; available DriverStore files were successfully read. The system driver `nvlddmkm.sys` in `nv_dispsi.inf_amd64_ccd7fbb71bb72370` is 113,971,432 bytes and MD5 **`3fb9afac9d0e394723e830aa14e60512`**, exactly matching the pinned Ghidra program. SHA-256 **`db407b964c11441642a1642a0922c35990de974c267a08537c3432765365f84b`**.

**External Windows files:** the same DriverStore package has `gsp_ga10x.bin` 27,043,992 bytes SHA-256 `f89d8f615e6146ed2808df974b7af7f1aabda876596391b0aabcc32ba293c34f` and `ucodes_ga10x.bin` 58,215,936 bytes SHA-256 `eed53d76248582d71c629e8b6230aee48ce673c91d782301c94e98ac6a6db7aa`. GSP ELF64 `.fwsignature_ad10x` and `.fwsignature_ga10x` are each 4,096 bytes; these are **GSP firmware signatures, not proven signed Booter records**. The user also observed matching-directory `gsp_tu10x.bin` and `ucodes_tu10x.bin`, outside the target family.

**Strong Linux comparison, not Windows object proof:** NVIDIA pinned Linux `615.78.08` `src/nvidia/src/kernel/gpu/gsp/kernel_gsp_booter.c` selects production `IMAGE_PROD`, `HEADER_PROD`, `SIG_PROD` from `kgspGetBinArchiveBooterLoadUcode_HAL`; generated `src/nvidia/generated/g_bindata_kgspGetBinArchiveBooterLoadUcode_GA102.c` and `..._AD102.c` explicitly annotate `IMAGE_PROD` as `EXTERNAL: NO`, with respective source sizes 60,928 and 57,600 bytes. These Linux host-side embedded/compiled Booter sources must **not** be equated with the Windows GSP UCODES archive, GSP ELF signatures, or source-compatible signed binaries. NVIDIA pinned `bin_data_pvt.h` separately defines a 24-byte `NVUCODES` file header: LE magic, v1, possible-entry count, fingerprint. Actual installed Windows UCODES header values and GSP-fingerprint match remain UNMEASURED.

**Host implementation:** existing read-only `research/windows_firmware_provenance.py` now records only `ucodes_header` information from a **24-byte bounded read**, no archive extraction or GPU writes. Locally compiled and checked manually against synthetic valid, unknown and truncated headers and CLI inventory. Repo script SHA-1 `d4ea20057e9847d4772d92d0b6e3a613ae26243f`. No actual user firmware bytes have been run through the revised script yet.

**Next grounded acquisition:** user reruns updated inventory with `--root "C:\\Windows\\System32\\DriverStore\\FileRepository"`; inspect reported `ucodes_header` version/count/fingerprint. Separately, prioritize direct Windows `FUN_140BF3880` descriptor producer and the invoker of the independently constructed nested `0x9B0` Falcon dispatch instance; investigate host-supplied Booter bytes instead of assuming a GSP-supplied UCODES payload is suitable for a pre-GSP secure stage. Do not reopen failed `FUN_1400AF170` / `+0x2710` alias or run broad callback-offset scans. No physical execution, crypto acceptance or per-GPU architecture selector proven.

**Authorization unchanged:** `CAN_DETACH=false`; `CAN_UNLOCK=false`; `CAN_FLASH=false`; `RECOVERY_VERIFIED=false`. Immutable process/recovery audit not edited. New detailed evidence was prepended to `research/nvidia-tensor-core-unlock-investigation-v121.md`, stable execution plan was updated **in place**.

---

# 2026-11-05 — Refocus signed Windows Booter provenance: pinned Linux source contract and passive source-file inventory

**Current Windows Ghidra baseline unchanged:** exact `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, image base `0x140000000`, existing 617.42 static analysis. The nested `0x9B0` dispatch object is created by `FUN_1417E99B0` through `FUN_14056C510`, published at outer `+0x108` (embedded owner `+0x18`), and its `+0x170` callback can be set by `FUN_1417E8550` to `FUN_140BF3880` or a non-supported fallback. **The specific runtime invoker, real `FUN_140BF3880` third-argument signed descriptor producer, and Windows source bytes are OPEN.** The v119 `FUN_1400AF170` `+0x2710` writer is **rejected** as an alias because it zeroes a numeric-record field; stop arbitrary `+0x170`/`+0x2710` scans.

**Pinned external Linux 615.78.08 contract, not Windows proof:** `src/nvidia/src/kernel/gpu/gsp/kernel_gsp_booter.c` at https://github.com/NVIDIA/open-gpu-kernel-modules/blob/615.78.08/src/nvidia/src/kernel/gpu/gsp/kernel_gsp_booter.c confirms `kgspAllocateBooterLoadUcodeImage_IMPL -> kgspGetBinArchiveBooterLoadUcode_HAL -> s_allocateUcodeFromBinArchive`, whose non-debug branch selects separate `BINDATA_LABEL_IMAGE_PROD`, `BINDATA_LABEL_HEADER_PROD`, `BINDATA_LABEL_SIG_PROD` plus patch/number records. `nouveau/extract-firmware-nouveau.py` at https://github.com/NVIDIA/open-gpu-kernel-modules/blob/main/nouveau/extract-firmware-nouveau.py treats `ucodes_ga10x.bin` as a separate paired GSP input in r610+, and constructs reference Booter images from generated `g_bindata_kgspGetBinArchiveBooter{Load,Unload}Ucode_*.c`. **No direct equality** between those Linux generated assets and Windows 617.42 UCODES or the loader argument is established.

**Existing Windows source/staging call chain (previously verified, not rerun):** `FUN_1400F35F0` selects the external UCODES path; `FUN_1400F3350` reads the file; `FUN_1401AB740` stages UCODES/GSP; `FUN_1401B2C10` assigns cached UCODES to `GSP_ARGUMENTS_CACHED.bindataArgs`. This supports read-only **source-file provenance capture**, but does not tell us whether the GSP or kernel consumes a particular Booter record or whether `FUN_140BF3880` is invoked through the nested instance.

**New concrete host acquisition tool on `main`:** `research/windows_firmware_provenance.py`, commit `d8259c0bbdcad146097d3796082d26f581bb5fa3`, SHA of Git blob `44e68d6f2c45a25b47128199f918f86f5c2eaf93`. Read-only Windows DriverStore/system-driver inventory, hashes/MD5 pin, supported plain GSP ELF signature-section metadata. Python syntax validation and isolated synthetic ELF/missing-root checks passed **locally only**. It does **not** parse opaque UCODES, authenticate any firmware, or run on the physical Windows host in this turn. A `.fwsignature_ad10x` section is **GSP ELF metadata**, not proven Booter signature. A report `STATUS=COMPLETE` only describes file inventory completion.

**Next one-line Windows host command:**

```powershell
python .\research\windows_firmware_provenance.py --output .\windows-61742-firmware-inventory.json
```

Require actual pinned `nvlddmkm.sys` MD5 match plus paths/hashes of corresponding files before a follow-up Ghidra source-to-descriptor run. If the files are missing, record the absence of **this inventory's evidence**, not an exhaustive absence in the driver. No new Ghidra script/DB mutations, hardware modifications, secure-loader execution or crypto verification performed. `CAN_DETACH=false`; `CAN_UNLOCK=false`; `CAN_FLASH=false`; `RECOVERY_VERIFIED=false`. Cumulative investigation v120 prepended; stable execution map updated in place; immutable recovery audit untouched.

---

# 2026-11-05 17:14 PST — `+0x2710` literal writer is a zero-initialized numeric buffer, not the Falcon dispatch producer

## User-run evidence and completion boundary

Read-only user report `nvlddmkm-61742-booter-discovery-20261105-171448-540235.txt` (11,285 bytes, SHA-256 `cbe8299908fabaa100758e0bfd08dda716d0d1b8dfa705210691d8b25fb6dffb`) from pinned Windows NVIDIA 617.42 `nvlddmkm.sys` (MD5 `3fb9afac9d0e394723e830aa14e60512`, Ghidra base `0x140000000`). `FUN_1400AF170` was fully decompiled: `clipped=False`, roughly 9,511 C characters, `STATUS=COMPLETE`; no strings scan, no Ghidra writes and no hardware actions. The nine incoming references include DATA and direct call refs; none was followed in this report. `STATUS=COMPLETE` applies to the requested bounded decompilation, **not** production Booter provenance or runtime GPU execution.

## Concrete correction: the only recognized direct `+0x2710` writer writes zero

The prior bounded literal-write scan showed one recognized executable store, `0x1400AF749 MOV qword ptr [RDI+0x2710],R8` in `FUN_1400AF170`. Earlier spatial instruction context also showed writes to adjacent `RDI` fields at `+0x26F8`, `+0x2700`, `+0x2708`, `+0x2718` and so on, but a nearby unconditional jump prohibited inferring the writer's source solely from preceding listing lines.

The new **complete C** exposes a different, well-supported classification:

- After a lookup/record-count check, the function calls `FUN_140DD1860(0x200,0x2750,0x764C764E)`, checks for null, zeroes `0x274C` bytes beginning at `puVar3+1`, and fills a `0x25`-element table using `FUN_1400B34A0` plus normalization and a series of numeric constants. The allocation has size **`0x2750`**. This is a numeric/record initialization path; its higher-level application meaning has not been proven.
- Ghidra types `puVar3` as `undefined4 *` (four-byte units). In a later initialization branch it displays `*(undefined8 *)(puVar3+0x9C2)=0`, **`*(undefined8 *)(puVar3+0x9C4)=0`**, and `*(undefined8 *)(puVar3+0x9C6)=0x3FF66F694467381D`, with similar IEEE-754-shaped constants nearby.
- **Exact index conversion:** `0x9C4 * sizeof(undefined4) = 0x9C4 * 4 = 0x2710` bytes. Thus the shown field at base+`0x2710` is **assigned zero in the decompiled writer path**, and is within the `0x2750`-byte allocation (only `0x40` bytes before its end). The previous machine-level store's source register `R8` represents that zero on the decompiled path; this resolves the earlier speculative “R8 may hold the Falcon dispatch pointer” interpretation in the negative. A direct live register trace was not collected; this conclusion is the matching instruction-plus-complete-decompilation static evidence.
- The function also contains guarded indirect calls, but the decompiled names `PTR__guard_dispatch_icall_140E02AA8` alone do not identify their targets. No source-level reference to the nested `0x9B0`-byte Falcon HS dispatch object, signed production Booter bytes, loader descriptor or physical GPU branch is shown.

**Disposition:** reject `FUN_1400AF170:0x1400AF749` as the producer of a non-null callback receiver for `FUN_140532110` and as a bridge to known `FUN_140BF3880` registration. This **closes the specific literal-writer hypothesis**. It is **not** proof that all possible writers are absent: computed-offset stores, aliases and bulk copies are outside the prior literal-write filter. No additional general `+0x170` or `+0x2710` scans are justified merely to find another numerical coincidence. Previous broader transfer scan remains `STATUS=PARTIAL` (246 filtered candidates, first 80 captured), unaffected by this complete targeted report.

## Remaining actual proof sequence and next task

The independent nested Falcon HS instance is constructed via `FUN_1417E99B0` and `FUN_14056C510`, published at outer+`0x108` (embedded owner+`0x18`), and conditionally receives `FUN_140BF3880` or fallback at **its own** `+0x170` slot. Neither actual indirect invocation of that same instance nor the origin of `FUN_140BF3880`'s real third-argument production signed Booter descriptor is established. The installed Windows 617.42 Booter image/header/signature byte source, AD102/GA102 runtime selector and cryptographic acceptance are also open. Distinguish already-observed host-side UCODES archive staging into GSP arguments from locating a validated production Booter record: **those are not equivalent**.

**Next priority:** end this unrelated numeric-table branch and return to read-only production Windows Booter asset/descriptor provenance, using previously pinned GSP/UCODES staging evidence and actual archive/descriptor consumers rather than repeating speculative callback-offset searches. For any candidate, require exact driver/resource bytes, archive record identity, length/hash, signed descriptor origin, then a verified instance-specific invocation path. Do not assert production firmware provenance based solely on Linux 615.78.08 reference source or 610.43.03 assets. No new exploratory Ghidra command is justified **by this negative writer result alone**.

No device, driver, EFI, registry, Ghidra database or firmware modifications. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`, `RECOVERY_VERIFIED=false`; immutable process/recovery audit untouched. Update the authoritative execution plan *in place* as a current-state snapshot, not as chronological notes.

---

# 2026-11-05 17:06 PST — Writer field cluster confirmed; focused decompilation did NOT resolve R8/RDI provenance

## Primary source, identity, and exact completion boundary

User-run passive PyGhidra report `nvlddmkm-61742-booter-discovery-20261105-170648-353403.txt` (3,213 bytes, SHA-256 `42353f86452dc88048aed507711399f721d613efaca8eea217893b19bb6a0e7d`). Ghidra source: original NVIDIA Windows 617.42 `nvlddmkm.sys`, MD5 `3fb9afac9d0e394723e830aa14e60512`, loaded VA base `0x140000000`. Explicit `TRACE_INSTRUCTION_SITES=['0x1400af749']`, `TARGET_FUNCTIONS=['0x1400af170']`, `DECOMP_FOCUS_TERMS=['10000','0x2710']`, `SCAN_STRINGS=False`. Script returned `STATUS=COMPLETE`, `HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE` and reported the output path. This status applies to the bounded request; it does **not** establish object identity, execution, firmware load, or the full decompilation dataflow.

The decompiler obtained a **9,511-character complete C representation internally**, but it emitted only **focused excerpts**, not the full C body. The focus term `10000` matched **one unrelated numeric literal**, `0x8C10000` in `FUN_1400E0C10(3,0x38169535,0x8C10000)`; the requested `0x2710` matched **zero** lines. `excerpt_truncated=False` means the emitted excerpt stayed within limits, **not** that the relevant writer's `R8` or `RDI` provenance was obtained. This is a misleading lexical focus result rather than evidence of a store-source trace. Future step should omit `DECOMP_FOCUS_TERMS` altogether because 9,511 characters are below existing `MAX_DECOMP_CHARS=14,000`.

## Exact writer context and control-flow limitation

The report confirms a cluster of qword stores at addresses inside `FUN_1400AF170`:

```asm
0x1400AF734 MOV qword ptr [RDI+0x26F8],R8
0x1400AF73B MOV qword ptr [RDI+0x2700],R8
0x1400AF742 MOV qword ptr [RDI+0x2708],R9
0x1400AF749 MOV qword ptr [RDI+0x2710],R8
0x1400AF750 MOV qword ptr [RDI+0x2718],RBX
0x1400AF757 MOV qword ptr [RDI+0x2720],R9
0x1400AF75E MOV qword ptr [RDI+0x2728],RBP
0x1400AF765 MOV qword ptr [RDI+0x2730],R14
```

The clustered stores suggest structured field initialization but **do not prove** whether R8 is zero, a generic pointer or the nested Falcon HS dispatch. The instruction window also lists `0x1400AF72F JMP 0x1400AF536` immediately before the later-addressed cluster: previous `BEFORE` lines cross a **control-flow boundary** and are not necessarily executed as fallthrough leading to `0x1400AF749`. Register values and branch reachability must be read from the containing function's actual paths rather than spatial listing order.

Ghidra's incoming references to `FUN_1400AF170`: four conventional direct calls at `0x1400AF86A`, `0x1400AF9A0`, `0x141925C57`, `0x1419289AE`, and five DATA references. These are potential provenance entry points, not a demonstrated link to `FUN_140532110` or the nested HS dispatch. The initial focused excerpt shows a guarded call and error check, but has no demonstrated bearing on the field store.

## Impact on unlock proof and exact next task

The earlier exact `+0x2710` filter found one recognized direct store `[RDI+0x2710]=R8`; the separately established `FUN_140532110` reads `receiver=[owner+0x2710]` with `owner=[ [param_1+0x160]+0xE8 ]` and transfers through `receiver+0x170`. **Same displacement alone is still not object alias proof.** The 0x9B0-byte Falcon HS dispatch instance is independently stored at outer+0x108 (embedded context+0x18). No register value, producer–consumer object alias, `FUN_140BF3880` runtime invocation or production signed Booter blob has been proven in this run.

**One remaining bounded discrimination**, without additional scans: request the complete 9,511-character decompilation of `FUN_1400AF170` with no focus terms. Determine whether the write `+0x2710` is initialization/clear or an actual pointer publication, and obtain the source of `R8` and the owner in `RDI`. Follow a caller only if a concrete object-identity bridge appears. If it does not, **close this side branch as unlinked and return to the P0 Windows production signed Booter image/header/signature bytes, third-argument descriptor producer for `FUN_140BF3880`, and proven invocation**. Do not count static callback registration or reference firmware as active validation.

Ghidra Python 3 console (one line, read-only; no new script required):

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1400af170"], "__name__": "__main__"})
```

**Physical/authorization gates unchanged:** `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`, `RECOVERY_VERIFIED=false`; AD102/GA102 selection, cryptographic acceptance, recovery and unlocked tensor issue-rate have not been tested. No driver/Ghidra database/UEFI/GPU writes. The immutable `windows_gpu_unlock_process_and_recovery_audit_2026-11-04.md` remains untouched.

---

# 2026-11-05 17:00 PST — One recognized literal +0x2710 writer in Windows 617.42; producer/consumer object alias still open

## Source, identity and scan completeness

User-run passive, read-only Ghidra report `nvlddmkm-61742-booter-discovery-20261105-170034-045170.txt` (2,328 bytes, SHA-256 `c1c99fb70e7d8420230fb4b6bb1b5dde47282d58609e22309e2a9766ef89622c`) on Windows NVIDIA `nvlddmkm.sys` 617.42, MD5 `3fb9afac9d0e394723e830aa14e60512`, Ghidra image base `0x140000000`. `SCAN_STRINGS=SKIPPED_BY_CALLER`, `SCAN_SLOT_DISPLACEMENT=0x2710`, `SLOT_SCAN_FOCUS=write`. It visited all 12 initialized executable blocks, 19,689,472 bytes; 376 raw displacement hits; 32 matching pre-existing instructions; one accepted literal write site, `recorded=1 capped=False scan_complete=True`, and `STATUS=COMPLETE`. `DECOMPILATION=SKIPPED`; no Ghidra database or hardware mutations (`HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE`). This completes the **bounded scanner's criteria**, not an exhaustive enumeration of every possible pointer update: computed addresses, bulk copies, unrecognized operand forms and runtime conditions lie outside its guarantee.

## Exact observed writer and potential producer–consumer bridge

The *single recognized direct write* is at VA `0x1400AF749` in `FUN_1400AF170`:

```asm
MOV qword ptr [RDI + 0x2710], R8
```

Prior independent reports establish that `FUN_140532110` obtains `owner = *( *(param_1+0x160) + 0xE8 )`, then `receiver = *(owner+0x2710)` and on its nonnull branch loads `target = *(receiver+0x170)` and uses the CFG-guarded indirect tail transfer. The matching **literal displacement and store width** make the new writer a **specific plausible producer** for that receiver field. The report does **not** establish that writer `RDI` equals the consumer's `owner`, whether writer `R8` is a dispatch object, whether the store is on the relevant runtime path, or whether its value equals the separately proven `0x9B0` Falcon HS instance published at `outer+0x108` (`embedded+0x18`). Nor does the store establish callback invocation, `FUN_140BF3880` as a target, or signed Windows Booter byte or signature provenance. `STATUS=COMPLETE` for scanner scope must not be interpreted as hardware unlock readiness.

## Next bounded read-only discriminator and stop condition

Inspect the exact writer's input registers and focused containing-function decompilation, then **stop this branch** unless a concrete `RDI` owner and `R8` value/dataflow alias connects to the published nested Falcon HS instance. Do not increase general scan caps or repeat unrelated `+0x170` candidate sampling. The current primary P0 blocker remains production Windows 617.42 signed Booter image/header/signature source, actual third-argument descriptor producer into `FUN_140BF3880`, verified instance-specific invocation and GA102/AD102 selector/crypto acceptance.

Ghidra Python 3 console command (single pasteable line; existing no-database-write script):

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TRACE_INSTRUCTION_SITES": ["0x1400af749"], "TARGET_FUNCTIONS": ["0x1400af170"], "DECOMP_FOCUS_TERMS": ["10000", "0x2710"], "__name__": "__main__"})
```

Exact-card ROM provenance, passive pre-Stop baseline and fault/recovery design remain independently open. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`, `RECOVERY_VERIFIED=false`; no active UEFI/driver/GPU/firmware changes and immutable process/recovery audit untouched.

---

# 2026-11-05 16:53 PST — Callback receiver owner unresolved after static reference and entry-register inspection

## Source and bounded result

User-run passive PyGhidra report `nvlddmkm-61742-booter-discovery-20261105-165318-052877.txt` (2,280 bytes, SHA-256 `8872ce0b9560bad36bda4bf4e7e5f14f11ef9adb98f1e0c236f92ea8adf51989`), loaded NVIDIA Windows 617.42 `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, Ghidra base `0x140000000`. Requested one instruction site and three DATA sites; `STATUS=COMPLETE` for those bounded queries. No full string scan or decompilation, `HARDWARE_ACTION=NONE`, `GHIDRA_MUTATION=NONE`. Virtual addresses belong to loaded Ghidra image, not raw PE offsets. No kernel, EFI or GPU operation was performed.

## Exact evidence

- `FUN_140532110` starts `0x140532110 SUB RSP,0x28`, `0x140532114 MOV RAX,[RCX+0x160]`, `0x14053211B MOV R9,RDX`, `0x14053211E MOV R8,[RAX+0xE8]`, `0x140532125 MOV RDX,[R8+0x2710]`, `0x14053212C TEST RDX,RDX`, with null branch returning numeric error `0x56`. This confirms the source-register chain under the ordinary Windows x64 ABI. The earlier complete body independently showed the guarded tail transfer through `[RDX+0x170]` on the nonnull path; the real callback target and Ghidra-inferred call signature remain unverified.
- `DATA_SITE 0x140E0A8E0` is in `.rdata`, `defined=True`, but the *containing defined region* starts at `0x140E02C20`. It contains an outbound DATA reference to `FUN_140532110`. There are zero incoming references reported at exact `0x140E0A8E0`; a single DATA reference from `0x141002A80` targets the defined region's root at `0x140E02C20`. These are **not** a caller of `FUN_140532110` or proof that an executable consumer selects this table entry.
- `DATA_SITE 0x140E6AF10` is another `.rdata` DATA pointer to `FUN_140532110`, `defined=True`, and has zero existing incoming refs at its exact address. `DATA_SITE 0x14140AA78` is a `.pdata` DATA pointer to the function and is consistent with normal PE exception/unwind metadata, not a virtual-method invocation. Inbound lists were not capped. No actual receiver constructor, relevant writer or runtime caller was identified.

## Relevance and proof gates

The candidate's receiver remains `RDX = *(*(*(param_1+0x160)+0xE8)+0x2710)` and its callback slot `[RDX+0x170]`. This is **not** known to be the independent Falcon HS 0x9B0-byte dispatch object installed at `outer+0x108` (embedded context `+0x18`) and configured with `FUN_140BF3880`/fallback at its own `+0x170`. The identical callback offset is insufficient; data-region XREFs are also insufficient. Absence of a direct static XREF does not disprove indirect runtime calls. The previously established 246 transfer-filtered candidates and 80-record cap (`STATUS=PARTIAL`) are unchanged; this narrow report's `STATUS=COMPLETE` does not supersede that cap.

**One final rooted passive discriminator (optional):** the existing already-verified scanner can search code writes to **exactly** `[base+0x2710]` rather than generic `+0x170` transfers. Correlate any writer's receiver base with the `param_1+0x160 -> +0xE8` chain and the already-proven Falcon owner; a numeric displacement match alone is not an alias. Stop this branch without expanding generic caps if no direct pointer-production bridge appears. The production Windows signed Booter image/header/signatures, `FUN_140BF3880`'s **actual third-argument descriptor producer**, and concrete nested dispatch invocation remain the priority P0 proof gates.

Existing read-only Ghidra Python 3 console command:

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "SCAN_SLOT_DISPLACEMENT": "0x2710", "SLOT_SCAN_FOCUS": "write", "__name__": "__main__"})
```

`CAN_DETACH=false`; `CAN_UNLOCK=false`; `CAN_FLASH=false`; `RECOVERY_VERIFIED=false`. The separately immutable process/recovery audit remains unchanged. No physical runtime/microcode/crypto-acceptance results.

---

# 2026-11-05 16:45 PST — `FUN_140532110` is an indirect +0x170 dispatcher through a distinct unaliased object chain

## Primary report and verification scope

Read-only user-run PyGhidra report `nvlddmkm-61742-booter-discovery-20261105-164522-801778.txt` (1,913 bytes; SHA-256 `194469dcde1c12c0c0d337bff2fec21db81d8c99040113cd4bd1047903d12436`). Target original NVIDIA Windows 617.42 `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, loaded Ghidra image base `0x140000000`. Single complete, unclipped decompilation of `FUN_140532110` and three DATA references; `STATUS=COMPLETE` for this bounded request, `SCAN_STRINGS=SKIPPED_BY_CALLER`, `HARDWARE_ACTION=NONE`, `GHIDRA_MUTATION=NONE`. The report does not claim runtime dispatch execution, firmware provenance or actual hardware alteration.

## Full function evidence

Ghidra decompiles `FUN_140532110(longlong param_1, undefined8 param_2)` as reading an object pointer through `param_1 + 0x160`, then `+0xE8`, then **decimal 10000 = hex `0x2710`**:

```c
longlong receiver = *(longlong *)(*(longlong *)(*(longlong *)(param_1 + 0x160) + 0xe8) + 10000);
if (receiver == 0) {
    FUN_1400E0C90(0xE3467DC, 0x23C0000);
    FUN_1401000C0(0x23C);
    return 0x56;
}
return (**(code **)(receiver + 0x170))(param_1, receiver, param_2);
```

Previously verified instructions at `0x140532154..0x140532162` establish `MOV RAX,[RDX+0x170]`, `MOV R8,R9`, and `JMP qword ptr [0x140E02AA8]` after stack cleanup. This is a CFG-protected **tail transfer** to a function pointer on the derived receiver (not a normal subsequent `CALL` in this particular path). Ghidra printed warnings `Switch with 1 destination removed`, `Could not recover jumptable ...`, and `Treating indirect jump as call`; therefore, the decompiler's two-parameter inferred prototype and formal third callback argument `param_2` **are not definitive ABI proof**. The pre-tail `MOV R8,R9` is verified but its source value has not been backward sliced; the decompiler may have assigned a misleading parameter label. The return value from the transfer is not observed in a runtime test.

Incoming references to `FUN_140532110`: `0x14140AA78`, `0x140E0A8E0`, `0x140E6AF10`; all reported as `DATA` rather than unconditional calls. Those reference sites have not yet been classified into concrete vtable/interface instances.

## Critical identity boundary

The known `0x9B0` Falcon HS dispatch is constructed via `FUN_1417E99B0` / `FUN_14056C510` and stored at `outer+0x108` (`embedded owner+0x18`). **No evidence shows that the receiver at `[[[param_1+0x160]+0xE8]+0x2710]` is the same instance.** An offset equality of `+0x170` across structs cannot close the alias, and this `0x56` null-object return must not be equated with the distinct not-supported fallback `FUN_140092D80` solely because it also returns `0x56`.

`FUN_140BF3880` actual indirect invocation, the true third argument supplying its signed firmware image descriptor, production Windows signed Booter image/header/signatures, GA102/AD102 device-group selection, cryptographic acceptance and physical tensor issue-rate unlock remain **UNPROVEN**. This report neither demonstrates nor rules out the genuine Falcon invoker elsewhere in the binary.

## Next bounded discriminating task

Do **not** rerun the 2,445-hit `+0x170` scan or increase the 80-candidate cap. Inspect Ghidra's actual instructions immediately preceding `0x14053211E` (the `[RAX+0xE8]` object lookup), and the existing DATA references at `0x140E0A8E0`, `0x140E6AF10`, `0x14140AA78` for interface owner context. This is a hypothesis test for the receiver's type, not a runtime proof. If the object cannot be linked to the previously rooted Falcon instance, close/deprioritize this candidate and return to the Windows Booter signed-byte/descriptor-producer proof gate. Use the existing passive script, no new code/dependencies:

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TRACE_INSTRUCTION_SITES": ["0x14053211e"], "TRACE_DATA_SITES": ["0x140e0a8e0", "0x140e6af10", "0x14140aa78"], "__name__": "__main__"})
```

Existing separate recovery/process audit remains immutable. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`, `RECOVERY_VERIFIED=false`. No GPU, UEFI, driver, ROM, firmware or Ghidra database mutation.

---

# 2026-11-05 16:37 PST — Four +0x170 guarded-transfer windows; direct Falcon dispatch object alias still not found

## Primary bounded evidence and result scope

User-run report `nvlddmkm-61742-booter-discovery-20261105-163745-577020.txt` (4,677 bytes; SHA-256 `db6f1524c1dea69da08d8217ecd19cfd449763068d662fcfdcd31fb8d8fc5fed`). Windows NVIDIA 617.42 `nvlddmkm.sys` identity MD5 `3fb9afac9d0e394723e830aa14e60512`, image base `0x140000000`. Read-only four requested existing-instruction windows; `SCAN_STRINGS=SKIPPED_BY_CALLER`, `DECOMPILATION=SKIPPED`, no Ghidra database writes or hardware actions, `STATUS=COMPLETE`. Completion pertains ONLY to these four instruction windows; the preceding `+0x170` sweep remained `STATUS=PARTIAL` due to its 80-record cap and 246 transfer-filtered candidates.

## Four observed candidate paths; negative conclusions are bounded

1. `FUN_140532110`, `0x140532154`: `R8=[RAX+0xE8]`, `RDX=[R8+0x2710]`, `TEST RDX,RDX`; zero path logs an error and returns `EAX=0x56`. Nonzero path `RAX=[RDX+0x170]`, `R8=R9`, `JMP` to CFG guard at `0x140E02AA8`. This is a **guarded tail-dispatch** with a forwarded third argument; `RAX` origin before the `+0xE8` read is not recovered. The resolved `+0x2710` owner field does **not** by itself match the independently grounded Falcon nested dispatch pointer at **outer+0x108 = embedded owner+0x18**. The shared numeric `0x56` error return with other driver paths is not proof of the same dispatch target.
2. `FUN_140588AD0`, at `0x140588DD2` and `0x1405890AC`: each reads `RAX=[RDX+0x170]`, moves `RCX=RDI`, invokes CFG guard, and zero-extends `AL` into `EAX`. Nearby alternative branches read callbacks at `[RDX+0x180]` and transform the returned integer, while other branches call `FUN_1401425E0`. These look like neighboring interface operations returning byte-sized results; **that is suggestive, not a proved unrelated callback type**, and `RDX` provenance is not in the bounded windows. They are two sites within one function, not two independent discovered subsystems.
3. `FUN_14059B580`, at `0x14059B970`: prior call to `FUN_14059C510` takes `RCX=R13`, `RDX=R12`; then `RAX=[R13+0x170]`, `RCX=R13`, `RDX=R12`, CFG call. Surrounding writes to `[R13+0x370]`-related storage indicate an object with at least that field; this alone neither proves nor rejects the 0x9B0 Falcon dispatch identity. No origin of `R13` or callee descriptor field observed.

**Cross-stream classification:** all four windows show credible guarded pointer consumption **only**. No object-base proof connects any `RDX`/`R13` receiver to the particular 0x9B0-byte dispatch instance that `FUN_14056C510` constructs and stores at outer+0x108 (embedded owner+0x18). In particular, no callback was shown to equal registered Falcon HS function `FUN_140BF3880`, no HS third-argument signed binary descriptor producer was found, and no Windows production signed Booter byte source, signature acceptance, physical GA102/AD102 selector value, or GPU unlock was verified. Do not report these as negative whole-driver absence findings.

## Next narrow read-only proof gate

Rather than increasing the generic scan cap or sampling arbitrary candidates, request the **full short decompilation** of `FUN_140532110` to recover its input object's origin, the `+0xE8 -> +0x2710 -> +0x170` chain and actual forwarded argument contract. If this object is not demonstrably linked to the published outer+0x108 Falcon dispatch instance, classify it as unproven/unrelated and return to the P0 Windows signed Booter source/actual HS invocation proof. If the caller references reveal a concrete publication edge, follow that exact edge rather than a new full-driver scan.

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x140532110"], "__name__": "__main__"})
```

`CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`, `RECOVERY_VERIFIED=false`. The immutable recovery/process audit is unchanged. No driver, firmware, EFI, registry, ROM, Ghidra database, or GPU mutation.

---

# 2026-11-05 16:30 PST — 246 slot-0x170 guard-transfer candidates, 80 captured (PARTIAL)

**Primary evidence:** read-only user report `nvlddmkm-61742-booter-discovery-20261105-163029-235692.txt` (17,752 bytes, SHA-256 `15817a80243963559ea50002e06f34eb153f94f845a3057ec6b97e8c7e5f3772`), expected `nvlddmkm.sys` Windows 617.42 MD5 `3fb9afac9d0e394723e830aa14e60512`, base `0x140000000`. `SCAN_STRINGS=False`; executable-only `SCAN_SLOT_DISPLACEMENT=0x170`, `SLOT_SCAN_FOCUS=transfer`. All **12** executable blocks were visited; **19,689,472 bytes scanned**, **2,445** raw disp32 hits, **1,901** distinct instruction candidates, **246** transfer-filtered candidates. **Only first 80 candidates printed (67 functions)**, so `capped=True scan_complete=False`, `STATUS=PARTIAL`. This is a candidate **reporting cap**, not an interrupted scan, Ghidra timeout, or firmware failure. No decompilation, database mutations or hardware action.

**Meaning of filter:** `_slot_transfer_evidence` accepts a bracketed `[base+0x170]` load when a register transfer/guarded indirect call appears within an eight-instruction lookahead. Proximity alone does **not** prove the guard consumes that function pointer, that a code path reaches it, or that the base is the **0x9B0-byte Falcon HS dispatch instance** registered by `FUN_1417E8550`. The known `FUN_140124A90` at `0x140124B56` recurs among the 80; its context has not been proved to alias the nested dispatch. The first-80 VA order and sparse records are **not a ranking** or exhaustive inventory. No actual `FUN_140BF3880` invocation, third-argument signed descriptor production, signature acceptance, device-family branch or GPU unlock was proven.

**Next bounded inspection** (existing `nvlddmkm_booter_discovery.py`, four instruction windows only, no rescan) uses a *weak locality and duplicate-site heuristic* for recorded candidates. Do not promote those addresses to Falcon evidence without object provenance:

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TRACE_INSTRUCTION_SITES": ["0x140532154", "0x140588dd2", "0x1405890ac", "0x14059b970"], "__name__": "__main__"})
```

The decision gate is concrete traced provenance from `outer+0x108` (`embedded+0x18`) through the actual nested dispatch `+0x170` to the CFG indirect call, then actual image descriptor (callee third argument) provenance. If neither these four windows nor the known owner chain yields a bridge, avoid further arbitrary offset sampling; redirect P0 to native Windows signed Booter byte/header/signature source and descriptor producer. Current execution map updated *in place*, while full investigation v113 prepends evidence. `CAN_DETACH=false`; `CAN_UNLOCK=false`; `CAN_FLASH=false`; `RECOVERY_VERIFIED=false`. Immutable audit unchanged.

---

# 2026-11-05 16:20 PST — Static Falcon interface table XREFs closed, no executable invoker

**User-run source:** `nvlddmkm-61742-booter-discovery-20261105-162054-788737.txt`, 2,252 bytes, SHA-256 `bb22716045a90d4af84db35e092e669171b6cbcbd9c8d5467d58878c9fc68536`. Read-only Ghidra of `nvlddmkm.sys` Windows 617.42, MD5 `3fb9afac9d0e394723e830aa14e60512`, base `0x140000000`. Three `TRACE_DATA_SITES` inspections completed, no caps or decompilation (`STATUS=COMPLETE`; `DECOMPILATION=SKIPPED`; `HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE`).

| Exact defined .rdata source | Outbound DATA target | Inbound existing Ghidra DATA refs |
|---|---|---|
| `0x140F27640` | `0x140F275A0` | `0x1417E9BAE`, `0x1417E9BB5` in `FUN_1417E99B0`, plus `0x140F27618` |
| `0x140F27658` | `0x140E8EC18` | `0x1417E9B92`, `0x1417E9B9C` in `FUN_1417E99B0`, plus `0x140F27620` |
| `0x140F27670` | `0x140EBEB20` | `0x1417E9BA3`, `0x1417E9BAA` in `FUN_1417E99B0`, plus `0x140F27628` |

For each source Ghidra reported `defined=True`, inbound `count=3 capped=False`, and **DATA** reference types. These links confirm only that `FUN_1417E99B0` initializes the three static interface-table pointers and that neighboring data points to them. The table sources are not proven callable entrypoints and the references are not executable consumers of the 0x9B0-byte nested Falcon dispatch, much less a call to `FUN_140BF3880`.

**Disposition:** exact three-table XREF task **CLOSED (STATIC)** with no new execution gate passed. Avoid repeated generic table metadata XREF enumeration. The object-rooted proof gate is a caller that fetches the actual dispatch pointer at outer+0x108 (embedded context +0x18), and invokes its **instance-relative** +0x170 loader/fallback callback. The previously documented `FUN_140BF3880` third-argument binary-descriptor fields are the *callee contract*, not evidence of the producer; production Windows signed Booter bytes/header/signature and crypto acceptance remain open. An existing read-only `SCAN_SLOT_DISPLACEMENT=0x170` with `SLOT_SCAN_FOCUS=transfer` can yield candidates **if not already run**; never interpret candidates as object aliases without callsite argument tracing. This is targeted filtering, not permission for another unfiltered broad scan.

**Next one-line Ghidra console command (bounded candidate work, not executable proof):**
```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "SCAN_SLOT_DISPLACEMENT": "0x170", "SLOT_SCAN_FOCUS": "transfer", "__name__": "__main__"})
```

`CAN_DETACH=false`; `CAN_UNLOCK=false`; `CAN_FLASH=false`; `RECOVERY_VERIFIED=false`. No driver, UEFI, firmware, registry, Ghidra database or GPU modification; immutable recovery/process audit untouched. Current execution-plan status updated in place; cumulative research notes now v112.

---

# 2026-11-05 16:09 PST — resolved interface consumer in 0x9B0 Falcon dispatch construction

**Primary evidence:** user-run passive PyGhidra report `nvlddmkm-61742-booter-discovery-20261105-160902-590021.txt` (3,892 bytes; SHA-256 `36d76d89ee795e8578cb103dab0a2a8f91f75cee524ff0895d8c641e12221989`). Windows NVIDIA 617.42 `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, image base `0x140000000`. `STATUS=COMPLETE` for single **full, unclipped** `FUN_1417E99B0` decompilation; no Ghidra DB or hardware mutations. This does not imply verified runtime firmware operation.

**Exact new interprocedural chain:** `FUN_1417E99B0` allocates or reuses 0x9B0 bytes, zeroes object, stores `param_3` flags at byte offset `+0x3C` (versus separate 0x1BB8 class-registration object `+0x44`). It requires `lVar6 = FUN_14010DC60(param_2,&DAT_140EA93F8)` or a fallback `FUN_14010E030(param_2,0x74BC71)` followed by retry. A null result exits through error `0x1F`. For a resolved interface, it initializes embedded subobjects at `puVar4+1` (+0x08) and `puVar4+8` (+0x40), stores vtable-like pointers `PTR_DAT_140F27640`, `PTR_DAT_140F27658`, `PTR_DAT_140F27670`, **calls `FUN_1417E8550(puVar4,lVar6)`**, then after success of `FUN_140296090` and `FUN_141750C80` **calls `FUN_1417E83E0(puVar4,lVar6)`**, publishes `*param_1=puVar4` and returns 0.

Prior independent `FUN_1417E8550` decompilation showed a selector read from **second argument+0x10** controls registration of **`FUN_140BF3880` or `FUN_140092D80`** into the nested dispatch object's `+0x170` slot. The newest decompilation directly binds that second argument to the resolved **`0x74BC71` type/interface object**, NOT to the metadata descriptor itself. Prior `FUN_1417E83E0` complete analysis found capability-byte writes but no overwrite of `+0x170` on this path. The distinction between a static function-pointer assignment and **actual invocation** is unchanged.

**Closed:** consumption of `lVar6` in Falcon dispatch setup; successful construction path and selector input source (resolved interface+0x10). **Open:** provenance of original `param_2` physical object and its selected 16-bit value on RTX 4090/3080; any runtime alias with `FUN_1417960A0`; actual nested object's `+0x170` indirect-call site; caller's third-argument binary descriptor producer, signed Windows production Booter bytes/header/signatures, actual firmware acceptance and unlock. The separately confirmed large-context `FUN_140124A90` and two guarded tail wrappers at `FUN_140175B60`/`FUN_1403235F0` are only numeric `+0x170` candidate users; no proven alias to this particular nested object.

**Next smallest passive task:** trace consumers of **the published 0x9B0 dispatch pointer**, which `FUN_14056C510` stores at embedded owner+0x18 (outer +0x108 on the previously proven outer-object path). Require specific object-base and callsite proof, not another broad displacement scan or duplicate constructor decompile. Then establish `FUN_140BF3880` third-argument signed descriptor provenance from the proven invoker; defer active actions. If a concrete consumer is not located, document that invocation remains unresolved.

Documentation: historical findings prepended to `research/nvidia-tensor-core-unlock-investigation-v111.md`; stable `research/nvidia_unlock_evidence_to_execution_map.md` updated **in place** as an execution snapshot, not a diary. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`, `RECOVERY_VERIFIED=false`. Immutable recovery audit unchanged.

---

# 2026-11-05 16:02 PST — Two constructors share exact 0x74BC71 metadata; no runtime pointer alias

**Primary user report:** `nvlddmkm-61742-booter-discovery-20261105-160258-725939.txt`, 4,617 bytes, SHA-256 `45e1d244bc58c3f8ed1ee16f95d89099249f521b9173b327f8077a4bed2f8dcd`. Original Windows NVIDIA `nvlddmkm.sys` 617.42 MD5 `3fb9afac9d0e394723e830aa14e60512`; Ghidra image base `0x140000000`. `STATUS=COMPLETE` for two static regions and two *focused excerpts*; `HARDWARE_ACTION=NONE`, `GHIDRA_MUTATION=NONE`. Full function bodies were not emitted.

**Static type metadata:** `0x140EA93F8` begins dwords `0x18`, `0x74BC71`; `0x140EA93D0` begins dwords `0x18`, `0x34A6D6`. Both have the qword `0x140E51850` at offset +8. `STATIC_QWORD0_LE=0x0074BC7100000018` is **two adjacent dwords**, not an executable pointer. `0x140EA93D0 + 0x28 = 0x140EA93F8`, so the 64-byte window at the first descriptor overlaps the next descriptor; never infer one 64-byte contiguous metadata record from this inspection.

**Verified matching constructor lookup:** `FUN_1417E99B0` (previously established 0x9B0-byte Falcon dispatch constructor) and independent `FUN_1417960A0` (0x1BB8-byte class-registration constructor) both call `FUN_14010DC60(param_2,&DAT_140EA93F8)`, with fallback `FUN_14010E030(param_2,0x74BC71)` and retry. `FUN_1417960A0` independently obtains the `0x34A6D6` interface using `DAT_140EA93D0`. The two constructors' *input objects*, returned interface pointers, consumer-side assignments and actual runtime paths have **not been shown equal**. This shared dependency is not a Booter loader or an AD102/GA102 selector.

**Disposition:** metadata layout and shared type dependency **PASS (STATIC)**. Actual Falcon HS invocation, Windows production signed Booter/header/signature bytes and the third-argument producer of `FUN_140BF3880` remain **OPEN**. No changes to `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`, or `RECOVERY_VERIFIED=false`. Next bounded inspection: get complete (unfocused) short decompilation of `FUN_1417E99B0`, particularly consumption of resolved `lVar6`, then move back to direct Booter provenance unless a concrete object-level bridge appears:

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1417e99b0"], "__name__": "__main__"})
```

**Documentation discipline:** cumulative research findings prepended to `research/nvidia-tensor-core-unlock-investigation-v110.md`; stable `research/nvidia_unlock_evidence_to_execution_map.md` snapshot updated **in place** with the resolved metadata proof and next blocker, not a new dated section. Process/recovery audit untouched.

---

# 2026-11-05 15:53 PST — Generic type/interface lookup established; exact metadata descriptor shared with Falcon HS constructor

**Input:** read-only user-run `nvlddmkm-61742-booter-discovery-20261105-155334-373621.txt` (9,207 bytes; SHA256 `5a137e26ac2290895b1611199cbec7fca21b1a72a523a3c488278b518640322d`), correct Windows NVIDIA 617.42 `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, Ghidra base `0x140000000`. `STATUS=PARTIAL` means both DATA_SITE inbound reference lists reached the existing ten-reference cap, not that either of the two full helper decompilations was clipped. Ghidra reports `DATA_SITES_COMPLETE=FALSE`, `TARGET_INCOMING_REFS_TRUNCATED=true` for each helper, `HARDWARE_ACTION=NONE`, `GHIDRA_MUTATION=NONE`.

**Generic helpers:** `FUN_14010DC60` compares `*(uint32_t*)(param_2+4) & 0xFFFFFF` against object/type metadata identifiers, traverses base/subobject metadata when necessary and returns an adjusted matching pointer or null. `FUN_14010E030` searches a linked interface/object chain and compares the supplied 24-bit ID to metadata IDs, returning an adjusted match or null/error. This is grounded **RTTI-like interface resolution**, not a shown firmware payload, GPU architecture enum or secure-loader stage. `DAT_140EA93F8` and `DAT_140EA93D0` are referenced widely in .rdata; their exact class semantics remain unproven. Fallback keys `0x74BC71` and `0x34A6D6` are used as 24-bit lookup identifiers.

**Critical cross-workstream link:** the earlier documented `FUN_1417E99B0`, builder of the **0x9B0-byte nested Falcon HS dispatch object**, also calls `FUN_14010DC60(param_2,&DAT_140EA93F8)` — **the exact same descriptor pointer used for `lVar5` in `FUN_1417960A0`**. This is a concrete shared type/interface dependency, not proof of object-pointer identity, callback invocation, third-argument signed Booter descriptor provenance, or physical device selection. Do **not** dismiss the whole constructor-registration branch as unrelated merely because its helper is generic; compare the uses of the resulting interface pointer.

**Bounded next read-only task:** compare `FUN_1417E99B0` and `FUN_1417960A0` around the exact shared `DAT_140EA93F8` lookup, fallback and returned-pointer consumers. Recover raw descriptor metadata only as needed. Existing PyGhidra one-liner:
```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1417e99b0", "0x1417960a0"], "DECOMP_FOCUS_TERMS": ["DAT_140ea93f8", "FUN_14010e030"], "TRACE_STATIC_BYTES": ["0x140ea93f8", "0x140ea93d0"], "__name__": "__main__"})
```
If no actual bridge is revealed, stop further generic XREF work and return to primary **production signed Windows Booter image/header/signatures, `FUN_140BF3880` third-argument descriptor producer and proven dispatch invocation**. Preserve `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`, `RECOVERY_VERIFIED=false`, immutable process/recovery audit unchanged. The stable execution map is updated **in place** as a snapshot, not a timeline.

---

# 2026-11-05 15:45–15:46 PST — Complete registration constructor: descriptor source lookup and failure gates

**User evidence:** two `STATUS=COMPLETE`, read-only PyGhidra reports `nvlddmkm-61742-booter-discovery-20261105-154540-478484.txt` (SHA256 `07bc033d51ab467a973b0e83a7b9518d4571e568b363a9a66d775520fe15b4e7`) and `nvlddmkm-61742-booter-discovery-20261105-154644-861376.txt` (SHA256 `810107cc6d58024d79712316b30bff0437276007b0e22c91b0ad93313846b0ea`). Diff verified: **same substantive listing and complete 3,064-character decompilation**, differing only in elapsed time and report path. Do not count as two independent reverse-engineering discoveries. Source Windows driver 617.42, `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, base `0x140000000`; no hardware or database modifications.

**New acquisition provenance:** `FUN_1417960A0` allocates `0x1BB8` bytes with `FUN_1400FF170` if `param_3 & 2` is clear (failure `0x51`), or reuses existing `*param_1` when bit 2 is set (missing pointer `0x3B`); zeroes buffer then stores flags at `+0x44`. When `param_2` is nonzero, it obtains `lVar5=FUN_14010DC60(param_2,&DAT_140EA93F8)`, with optional fallback `FUN_14010E030(param_2,0x74BC71)` plus renewed same descriptor lookup; separately it obtains `lVar7=FUN_14010DC60(param_2,&DAT_140EA93D0)` with fallback key `0x34A6D6`. Missing required results follow `0x1F` error paths. These values become `RDX=lVar5` and `R8=lVar7` for `FUN_1417930C0(puVar3,lVar5,lVar7)` followed by `FUN_141795D50`, corroborating prior instruction windows. After additional setup/return checks, success executes `FUN_141792A90`, assigns `*param_1=puVar3`, returns `0`. This is a **generic constructor and callback registry path**, *not* demonstrated signed Booter load/permission writes, physical AD102/GA102 selection, or actual call through the registered `+0x150` field.

**Next passive discrimination (one-line command; existing script):**

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x14010dc60", "0x14010e030"], "TRACE_DATA_SITES": ["0x140ea93f8", "0x140ea93d0"], "__name__": "__main__"})
```

Limit further work on this branch to proving descriptor types/selector member, then finding a concrete connection to Booter descriptor production or an invoked callback; otherwise deprioritize. High-priority unsolved proof remains the actual Windows stock signed Booter bytes/signatures and the producer of the third argument at `FUN_140BF3880`, runtime invocation and acceptability. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`; immutable recovery audit untouched. Authoritative plan `research/nvidia_unlock_evidence_to_execution_map.md` updated **in place**; no dated notes inserted there.

---

# 2026-11-05 15:24 PST — Caller provenance of class callback registration and second-stage setup

**Observed source:** user-run passive PyGhidra report `nvlddmkm-61742-booter-discovery-20261105-152456-204455.txt`, 2,956 bytes, SHA-256 `c23fa1fbf82f7fc82dfb7fa3d253b9e8c35b7afc5a47e306f6145863042a0cf6`; correct Windows 617.42 `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, base `0x140000000`, `STATUS=COMPLETE` for one instruction window plus focused C decompilation; `HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE`. Unselected parts of caller source were omitted by the focus filter, notwithstanding `excerpt_truncated=False`.

**Verified call sequence:** `FUN_1417960A0` prepares `R8=RBP` at `0x141796358`, `RDX=R14` at `0x141796376`, and `RCX=RDI` at `0x141796380` before calling `FUN_1417930C0` at `0x141796386`. Immediately afterward `0x14179638B..0x141796394` restores that same register tuple and calls `FUN_141795D50`. Ghidra C corroborates `FUN_1417930c0(puVar3,lVar5,lVar7);` followed by `FUN_141795d50(puVar3,lVar5,lVar7);`. `RDI` points at the caller's initialized object with `[RDI]=0x140EDCDF0` and `[RDI+0xF0]=0x140EDCEA8` before the registry call, and related objects receive other static pointers. The full object type, `R14`/`RBP` source, selector value/meaning, callback invoke site and HS loader relationship remain unknown. Do NOT label either RTX 4090 AD102 or RTX 3080 GA102 as selector 5..9 without separate direct evidence.

**Priority:** recover the **full 3,064-character decompiled `FUN_1417960A0` body** (no focus terms) for the definitions of `lVar5`/`R14` and `lVar7`/`RBP`; then trace actual use of registered `+0x150` callback only if a link to the independently established production Booter HS-byte/descriptor flow appears. A registered callback is not an invoked loader. Existing one-line read-only script:

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1417960a0"], "__name__": "__main__"})
```

**Implementation status:** current `research/nvidia_unlock_evidence_to_execution_map.md` updated in place for this observation; no new active stage passed. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`, `RECOVERY_VERIFIED=false`. Immutable audit untouched.

---

# 2026-11-05 15:16 PST — class-selector callback registration for FUN_140A47B50 located; still separate from HS dispatch

## New evidence and scope

User-run read-only Windows 617.42 Ghidra report `nvlddmkm-61742-booter-discovery-20261105-151625-447814.txt` (5,439 bytes; SHA-256 `fbac2998ab07810d796342bb77d321fce6ba3da0f15149bced1a71fec0fd8344`), verified `nvlddmkm.sys` MD5 `3fb9afac9d0e394723e830aa14e60512`, base `0x140000000`. Four requested instruction windows and one focused decompiled excerpt completed: `STATUS=COMPLETE`, `GHIDRA_MUTATION=NONE`, `HARDWARE_ACTION=NONE`. The full decompiler output was **45,749 C characters but not printed**; `excerpt_truncated=False` describes the selected focus region only.

## Exact registration / selection

- In `FUN_1417930C0`, assembly `0x141793252 LEA EAX,[RCX-5]`, `0x141793255 CMP EAX,4`, `0x141793258 JA 0x141793263`, `0x14179325A LEA RAX,[FUN_140A47B50]`, `0x141793261 JMP 0x14179322C`, `0x14179322C MOV [R8+0x150],RAX` establishes that this class/selector branch installs `FUN_140A47B50` into the `R8+0x150` callback slot for *selector values 5 through 9 inclusive*. Focused C independently reports `else if (uVar6-5 < 5) pcVar3 = FUN_140a47b50;`. Physical GA102/AD102 runtime selector assignments are **unknown**.
- Alternative branches populate the same slot with other callback implementations, e.g. `FUN_14067F8C0` for the nearby `0x1D..0x1E` case. Adjacent `R8+0x158` also receives conditional callbacks depending in part on `TEST EDX,0x88000000`. The entire 45K-character registration function and all class variants are **not** claimed fully analyzed.
- This adds **static callback registration** to the earlier proven `FUN_140A47B50` orchestration (`FUN_140A444D0` CALL, internal `RBX=R8`; `FUN_140A48220` tail JMP, same object; `+0x21A0`-controlled 64-byte templates at `+0x2160`). There remains no observed indirect invocation of the registered `+0x150` callback or verification of its per-physical-GPU selection.

## Confirmed but independent caller contexts

- `FUN_140125040` at `0x140125089` calls `FUN_140124A90` with `RCX=RBX, EDX=7, R8D=0x10`.
- `FUN_140125100` at `0x140125225` calls it with `RCX=RBX, EDX=R14D, R8D=8`.
- `FUN_140124A90` has the previously known conditional guarded callback through `[[RBX+0x2160]+0x170]`, but **no established alias** links its large context to the class-registered constructor object or to the independent `0x9B0`-byte Falcon HS dispatch (whose `+0x170` can register `FUN_140BF3880`). Same offset values across objects are not proof of the same callback.

## Next bounded passive command

The existing direct CALL into registration `FUN_1417930C0` is at `0x141796386`. Resolve its effective `RCX`, `RDX` and `R8` arguments and trace the selector/flag provider; the callback-field `+0x150` consumer is a subsequent separate proof gate. Use existing read-only script and its truthful terminal status:

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TRACE_INSTRUCTION_SITES": ["0x141796386"], "TARGET_FUNCTIONS": ["0x141796386"], "DECOMP_FOCUS_TERMS": ["FUN_1417930c0"], "__name__": "__main__"})
```

If the focused term is absent or the containing function is unavailable, the request remains partial, not negative proof. Production Booter signed bytes, header/signatures, `FUN_140BF3880` descriptor producer, actual Falcon invocation, cryptographic acceptance and GPU unlock remain unproven. `CAN_DETACH=false; CAN_UNLOCK=false; CAN_FLASH=false`. Immutable process/recovery audit unchanged.

---

# 2026-11-05 15:10 PST — Internal shared-object alias verified; constructor-to-CFG consumer remains open

## Primary source

User-run passive report `nvlddmkm-61742-booter-discovery-20261105-151042-298386.txt` (5,761 bytes, SHA-256 `85da9ddd2f2ee4b5886181c77559df39d3972fca4afa5215791fc9d5d1e85593`). Correct Windows NVIDIA `nvlddmkm.sys` 617.42 MD5 `3fb9afac9d0e394723e830aa14e60512`, Ghidra base `0x140000000`, read-only; four bounded existing-instruction windows and the unclipped `FUN_140A47B50` decompilation completed (`STATUS=COMPLETE`). No Ghidra DB or GPU changes (`HARDWARE_ACTION=NONE`, `GHIDRA_MUTATION=NONE`). Complete is scoped to this output, not whole-driver flow or hardware execution.

## Decisive new link

- `FUN_140A47B50` at `0x140A47B6D MOV RDI,R8` preserves third argument `param_3`. It passes `R8=RDI` to `FUN_140A444D0` via `CALL 0x140A47C4C`, then again restores `R8=RDI` before the tail `JMP FUN_140A48220` at `0x140A47C74`. Thus both initializers receive the same third-argument object.
- **Newly proven internal alias:** the `FUN_140A444D0` prologue has `0x140A444F9 MOV RBX,R8`. Consequently prior `[RBX+0x21A0]` updates and `LEA [RBX+0x2160]` address publications in the first initializer are on the same object seen as `[R8+0x21A0]` and `[R8+0x2160]` in the second. Previously open internal RBX/R8 alias **closed in static code**.
- `0x140A444EF MOV RDI,R9` also shows the first initializer's `RDI` starts as the **fourth argument**, not the shared third-argument object. On the guarded `TEST RDI,RDI` path, `LEA RAX,[RDI+0x2160]` points into that distinct input if nonzero. The `CMOVZ RAX,R9` fallback uses volatile R9 at the later instruction, which cannot automatically be equated with entry R9 across intervening calls.
- Static template choice remains `[R8+0x21A0]==0` -> template `0x140FE99C0`; nonzero -> `0x140FE9A00`; four MOVUPS stores initialize `R8+0x2160..0x219F`. `+0x2240` is a subsequent branch condition, not the chooser.
- The indirect `MOV [RCX], &RBX+0x2160` at `0x140A475F1` still lacks `RCX` provenance and a proven consumer.

## Important unresolved interface boundary

**Do not yet equate this constructor object with `FUN_140124A90`'s RBX**, which loads `RDX=[RBX+0x2160]`, then `RAX=[RDX+0x170]` and executes a CFG-guarded indirect call. The earlier conditional static-template `+0x170` results `0x140C06B80` and nonexecutable `0x140FE9B70` differ from known Falcon HS loader `FUN_140BF3880`; those were hypothesis-level dereferences, not proven runtime paths. The separate 0x9B0-byte Falcon dispatch construction is established, but actual invocation, signed third-argument descriptor, production Booter image/header/signature source, silicon-specific runtime selection, cryptographic acceptance, and any unlock remain **unverified**.

## Next bounded read-only step

Analyze the existing **code DATA references** to `FUN_140A47B50` inside `FUN_1417930C0` (at `0x14179322C` and `0x14179325A`) and actual direct callsites of `FUN_140124A90` (`0x140125089`, `0x140125225`). Prefer the current PyGhidra `TRACE_INSTRUCTION_SITES` mode plus one focused decompilation; no full scan or new code needed. If a requested focused term does not appear, `STATUS=PARTIAL` for excerpt proof rather than asserting absence.

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TRACE_INSTRUCTION_SITES": ["0x14179322c", "0x14179325a", "0x140125089", "0x140125225"], "TARGET_FUNCTIONS": ["0x1417930c0"], "DECOMP_FOCUS_TERMS": ["FUN_140a47b50"], "__name__": "__main__"})
```

No EFI/driver/GPU/firmware changes. `CAN_DETACH=false`; `CAN_UNLOCK=false`; `CAN_FLASH=false`. Immutable recovery audit untouched.

---

# 2026-11-05 — Direct shared-object callsite confirmed for FUN_140A444D0 and FUN_140A48220

**Primary evidence:** user-provided Ghidra xrefs, decompiled C and exact machine instructions in `FUN_140A47B50` for Windows 617.42 `nvlddmkm.sys`. At `0x140A47B6D`, `MOV RDI,R8` preserves the third argument. At `0x140A47BEB` `MOV R8,RDI` prepares the call to `FUN_140A444D0` (`0x140A47C4C`). At `0x140A47C51`, `MOV R8,RDI` explicitly prepares the second function; after restoring nonvolatile registers, `0x140A47C74 JMP FUN_140A48220` tail-jumps to the initializer. **Therefore the two functions receive the same third-argument object on this call path.** The Ghidra `CALL_RETURN` flow override does not change the machine-code jump semantics. The return-value semantics are not established by inferred `void` prototypes.

The previous ledger's statement that effective callsite arguments were still unavailable is now superseded. Nonetheless this caller proof is **not** proof that `RBX` *inside* `FUN_140A444D0` equals incoming `R8`, nor that either initializer's object aliases `RBX` in `FUN_140124A90` or the nested `0x9B0` Falcon HS dispatch object. If internal `R8 -> RBX` binding holds, the previously proven `[RBX+0x21A0]` construction and `[R8+0x21A0]` template selection compose into one initialization flow. Verify the exact prologue instead of extrapolating from matching offsets.

**Next read-only PyGhidra command** uses the existing script, preserves the bounded final `STATUS`/`REPORT` output, runs no generic scan and asks for one short decompilation plus four instruction windows. The two `FUN_140A444D0` addresses are *sampling anchors* that will resolve to containing existing instructions, not asserted opcode boundaries:

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TRACE_INSTRUCTION_SITES": ["0x140a444e8", "0x140a44510", "0x140a47c4c", "0x140a47c74"], "TARGET_FUNCTIONS": ["0x140a47b50"], "__name__": "__main__"})
```

Follow the constructor's internal parameter-base binding, then the separate published `[RCX] = &RBX+0x2160` at `0x140A475F1`; do not infer an actual `FUN_140BF3880` callback or signed Windows Booter descriptor. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`; immutable process/recovery audit unchanged.

---

# 2026-11-05 14:51 PST — +0x21A0 is the actual +0x2160 template selector; published embedded-object address still untraced

## Primary evidence and scope

User-run passive report `nvlddmkm-61742-booter-discovery-20261105-145110-386655.txt` (5,386 bytes; SHA-256 `df97fa8a3a8591322723d18760d1b143e1a6d7e7b3a957df51ca1dd3535860cc`) from Windows `nvlddmkm.sys` 617.42, MD5 `3fb9afac9d0e394723e830aa14e60512`, base `0x140000000`. Four requested instruction-site windows completed: `STATUS=COMPLETE`, `DECOMPILATION=SKIPPED`, `HARDWARE_ACTION=NONE`, `GHIDRA_MUTATION=NONE`. No new runtime or object-provenance proof.

## Proven low-level relationship and correction

In `FUN_140A444D0`: `0x140A456E9 TEST RDI,RDI` -> `0x140A4570B LEA RAX,[RDI+0x2160]` -> `0x140A45719 CMOVZ RAX,R9` -> `0x140A4571D MOV [RBX+0x21A0],RAX`. Thus the field is set to the other object's embedded address if RDI is nonzero, otherwise to R9. Neither RDI nor R9's object provenance is established.

In `FUN_140A48220`, the earlier `0x140A49272 CMP [R8+0x21A0],0` sets flags preserved by the following four `MOVUPS` stores. The newly revalidated `0x140A4929A JZ 0x140A492BA` therefore selects **`0x140FE99C0` when `[R8+0x21A0]==0`, and `0x140FE9A00` otherwise**, before `0x140A492DE..0x140A492F6` write 64 bytes into `R8+0x2160..0x219F`. Correct earlier ambiguity: `0x140A492D6 CMP [R8+0x2240],0` occurs **after** the template-choice branch and controls a later `0x140A492FE JZ` (following the SIMD stores), not the choice of +0x2160 source table. That +0x21A0 value was also read by earlier +0x2050 template-copy sequence, but this does not prove any cross-function object alias.

Another newly revalidated chain in `FUN_140A444D0`: `0x140A475D5 LEA RAX,[RBX+0x2160]`, `0x140A475E3 MOV [RBX+0x1C58],RCX`, `0x140A475F1 MOV [RCX],RAX`. The embedded-region address is indirectly published, and the output-slot address is retained, but **RCX's origin and any downstream consumer are not in the 12-before/4-after window**.

Critical remaining proof: `FUN_140A444D0` RBX and `FUN_140A48220` R8 might be related, but no effective callsite arguments were recovered. Nor are those objects proven to match the separate `FUN_140124A90` RBX (which dereferences `[RBX+0x2160]` then slot `+0x170` through CFG), much less the independently constructed 0x9B0-byte Falcon HS dispatch. Previous conditional static-template target evaluation (`0x140C06B80` or nonexecutable self-pointer `0x140FE9B70`) remains inconsistent with simply labeling the static table as the known `FUN_140BF3880` HS callback.

## Next bounded, read-only investigation

Prefer incoming **code XREFs** to `FUN_140A48220` and `FUN_140A444D0`, inspect caller's effective R8/RBX object arguments, then recover the origin of RCX at `0x140A475F1` and consumer of its published pointer. Avoid redoing full-driver +0x170/+0x2160 scans or the timed-out whole-function decompilation. No script, driver, firmware, EFI, GPU or audit changes in this turn; physical GA102/AD102 selection, signed production Booter descriptor/source and authentication remain open. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`.

---

# 2026-11-05 14:43 PST — +0x2160 indirect address stores identified; static +0x170 callback hypothesis weakened

## Input and verification

User-run passive read-only PyGhidra report `nvlddmkm-61742-booter-discovery-20261105-144338-833088.txt` (6,069 bytes, SHA-256 `948d20a4d5b08bb5e55001da9481ffe8fb648f69e5ccba8c13db4cfc83eadc78`), for Windows NVIDIA `nvlddmkm.sys` 617.42, MD5 `3fb9afac9d0e394723e830aa14e60512`, image base `0x140000000`. Four instruction-site windows plus two initialized nonexecutable 64-byte static windows returned. `STATUS=COMPLETE`, `DECOMPILATION=SKIPPED`, `HARDWARE_ACTION=NONE`, `GHIDRA_MUTATION=NONE`. This is a completed bounded static inspection, not whole-function dataflow or runtime proof.

## Conditional pointer +0x170 dereference now discriminates against static template alias

Previously `FUN_140A48220` at `0x140A492DE` copied 64 bytes of static template data to `[R8+0x2160..0x219F]`. First qword of the two possible templates is their own address: `0x140FE99C0` and `0x140FE9A00`. If (still unproven) its `R8` aliases the `RBX` of consumer `FUN_140124A90` and no later overwrite occurs, then `RDX=[RBX+0x2160]` and `RAX=[RDX+0x170]` imply:

| Template first qword | `RDX+0x170` | Found qword | Implication |
|---|---|---|---|
| `0x140FE99C0` | `0x140FE9B30` | `0x140C06B80` | Code-address-shaped, executable/function identity unverified; not known HS loader `0x140BF3880` |
| `0x140FE9A00` | `0x140FE9B70` | `0x140FE9B70` | Self-reference into initialized **nonexecutable** static data; not a legitimate CFG call target if actually used directly |

The second 64-byte window at `0x140FE9B70` includes further pointer-shaped entries but begins with the data self-pointer above; the first at `0x140FE9B30` begins with `0x140C06B80` followed by several code-shaped pointers and an integer `1`. **Neither candidate `+0x170` pointer is `FUN_140BF3880`.** This weakens the hypothesis that this bulk-template initializer seeds the same object consumed as the real HS-loader callback. Does NOT prove no alias exists across mode-specific branches, overwrites, or unreachable call paths; nor does it disprove the independently constructed nested `0x9B0` Falcon HS dispatch object.

## Genuine address escapes in `FUN_140A444D0`

- `0x140A4570B: LEA RAX,[RDI+0x2160]`; preceding `TEST RDI,RDI`; `0x140A45719: CMOVZ RAX,R9`; `0x140A4571D: MOV [RBX+0x21A0],RAX`. Conditionally stores the address of an embedded region (or R9) to a *different* field. This may feed other setup paths; owner identity and alias with `FUN_140A48220` not established.
- `0x140A475D5: LEA RAX,[RBX+0x2160]`, then `0x140A475F1: MOV [RCX],RAX`. **Actual store of an address of the +0x2160 region through indirect output**, not a write of a Falcon dispatch pointer *to* that region. Trace origin and consumer of RCX.

These correct CSV byte-match VAs `0x140A4570E`/`0x140A475D8` into actual instruction starts. `FUN_140A48220` selects `[R8+0x2160]` template conditioned on `[R8+0x2240]` but its earlier distinct `[R8+0x2050]` template condition uses `[R8+0x21A0]`; do not conflate them.

## Smallest read-only next acquisition

One-line Ghidra Python 3 console command using existing script (no changes or broad scans):

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TRACE_INSTRUCTION_SITES": ["0x140a4571d", "0x140a475f1", "0x140a492d6", "0x140124b56"], "__name__": "__main__"})
```

Next: prove origin of `RCX` at `0x140A475F1`, base `R8` of template-copy function, and relevant object ownership; classify whether consumer `RBX` can alias either and whether the CFG target at `[RDX+0x170]` is executable on reachable path. If not, exclude this unrelated interface and follow the separately confirmed nested Falcon HS object instead. Stock signed Windows Booter image/header/signatures, its descriptor argument producer, physical AD102/GA102 branch, cryptographic acceptance and active unlock remain **UNPROVEN**. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`; process/recovery audit unchanged.

---

# 2026-11-05 14:34 PST — Manual +0x170/+0x2160 Ghidra CSV triage: static pointer-table hypothesis, not proven HS-object alias

## New passive evidence and parsing caveats

User exports `0x2160.csv` (11,885 bytes; SHA-256 `a880c734f0fc1d75161fd5522cf51628ca513b0983ae8ca11f87bda234d7e78b`) and `0x170(1).csv` (172,500 bytes; SHA-256 `70e6d8c2529071f169a80d588581732d32ad4ad4673227261a010b242159c50e`), compared with completed passive report `nvlddmkm-61742-booter-discovery-20261105-143104-624064.txt` from Windows 617.42 `nvlddmkm.sys` (MD5 `3fb9afac9d0e394723e830aa14e60512`, Ghidra base `0x140000000`). The CSV `Location` field is generally the address of **matched displacement bytes inside an instruction**, not the opcode start; recover the containing instruction before using it as a code address.

`0x2160.csv` has **172 raw matches**: 167 strict `[base+0x2160]` instruction operands and five undefined/data records. The only explicit recognized stores are the already identified instruction starts `0x140A492DE` (16-byte MOVUPS), `0x141568841` (32-bit zero) and `0x1416656EC` (32-bit R14D). **New address-taking leads** at matched-byte locations `0x140A4570E` (`LEA RAX,[RDI+0x2160]`) and `0x140A475D8` (`LEA RAX,[RBX+0x2160]`) may expose implicit helper/copy initialization; a LEA itself is not a write.

`0x170(1).csv` has **2,586 raw matches**; only 1,503 render an exact bracketed `+0x170` memory operand, including 331 textual qword stores and 181 Ghidra-rendered `=>FUN_*` stores. Precisely one of those annotated qword stores names `FUN_140BF3880` (matched-byte VA `0x1417E8E48`, the previously confirmed nested Falcon HS loader registration) and 15 name `FUN_140092D80` (including matched-byte VA `0x1417E8EFC` in the same constructor). The shared offset across many distinct objects is not an object alias or callsite proof. General raw byte counts are not comparable to previous executable-only scan counts without matching their scopes.

## 64-byte template contents resolved by the latest user-run static report

Report ended `STATUS=COMPLETE` and reported `GHIDRA_MUTATION=NONE`, `HARDWARE_ACTION=NONE`. `FUN_140A48220` uses one of two 64-byte groups as SIMD sources for a sequence copying four consecutive 16-byte chunks into `[R8+0x2160..+0x219F]`.

- Static `0x140FE99C0`, eight LE qwords: `0x140FE99C0, 0x140C153C0, 0x140C15460, 0x140C154E0, 0x140C15560, 0, 0, 0`.
- Static `0x140FE9A00`, eight LE qwords: `0x140FE9A00, 0x140C153C0, 0x140C15460, 0x140C154E0, 0x140C15690, 0x140C15770, 0x140C15DA0, 0x140C16100`.

Both are pointer-shaped groups with **self-referential first qwords**, not all-zero constants. Remaining pointer-shaped values must be validated as executable/defined Ghidra functions before naming them callback tables. There is still **no proof** that the initializer `R8` aliases the `RBX` context in `FUN_140124A90`, nor that `[RBX+0x2160]` is the separately allocated `0x9B0` Falcon HS dispatch object. Under the conditional alias hypothesis alone, reading `[static_table+0x170]` would inspect `0x140FE9B30` or `0x140FE9B70`; these are **beyond** the known 64-byte blocks and could be unrelated neighboring data. Do not assume a callback target there.

## Smallest next read-only acquisition

Execute in the existing PyGhidra Python 3 console (no new code, no broad memory scan, no repeat of timed-out decompilation):

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TRACE_STATIC_BYTES": ["0x140fe9b30", "0x140fe9b70"], "TRACE_INSTRUCTION_SITES": ["0x140a4570e", "0x140a475d8", "0x140a492de", "0x140124b4c"], "__name__": "__main__"})
```

Check the LEA destinations and their downstream uses, the initializer's R8 base and consumer's RBX base, then actual pointer identity. Treat missing/short static reads as PARTIAL. Only follow the real signed `FUN_140BF3880` descriptor after confirming a nested dispatch invocation. No production Booter image/header/signature provider, per-GPU runtime selector, signature acceptance, detach, unlock or flash established. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`; immutable recovery audit unchanged.

---

# 2026-11-05 14:20 PST — +0x2160 writer-site forensics: two constant pools, one proven 32-bit clear, one selector-dependent 32-bit store; decompiler limits explicit

## Primary user-run evidence and exact run status

Report: nvlddmkm-61742-booter-discovery-20261105-142004-899582.txt, verified uploaded **5,865 bytes**, SHA-256 **f49c23913e5a3ec30de64af544a90470c898e36db039518af57e46c2cff8128b**. Ghidra loaded Windows NVIDIA nvlddmkm.sys 617.42 MD5 3fb9afac9d0e394723e830aa14e60512 at image base 0x140000000. Passive, read-only existing instructions and decompiler; SCAN_STRINGS skipped, no reported Ghidra DB write or hardware action. **STATUS=PARTIAL** after 13.794 s: FUN_140A48220 decompilation timed out; FUN_141662D70 produced 51,015 C characters but its DECOMP_FOCUS_TERMS=['0x2160'] matched zero lines, so no decompiled excerpt was captured; FUN_141568760 yielded a matching bounded excerpt (full generated C 1,414 chars). Do NOT classify a successful decompiler run that yielded zero focused excerpts as source-level inspection of that function.

## Three write candidates — source-level distinctions

1. **FUN_140A48220** at 0x140A492DE:
   - 0x140A4929C..0x140A492B1 loads XMM0..XMM3 from static 16-byte chunks at 0x140FE9A00/10/20/30; an alternative branch 0x140A492BA..0x140A492CF loads XMM0..XMM3 from 0x140FE99C0/D0/E0/F0.
   - Before store the code compares [R8+0x2240] to zero; 0x140A492DE..0x140A492F6 writes 16 bytes each from XMM0..XMM3 to [R8+0x2160], [R8+0x2170], [R8+0x2180], [R8+0x2190] = **64 consecutive bytes initialized from one of two constant groups**.
   - This is NOT evidence of a single pointer-width assignment; some or all bytes may happen to be zero, fixed scalar values, or pointers. Exact constant bytes are **not present in this report**, and R8's relationship to GPU_context used by FUN_140124A90 is still unknown.
   - Whole-function decompilation timed out and must not be called complete.

2. **FUN_141568760** at 0x141568841:
   - Before store, code invokes a CFG-guarded indirect function, obtains a returned pointer in RAX, then reads RCX=[RAX+0x49B0]. It executes MOV AL,0x1 followed by **MOV dword ptr [RCX+0x2160],0x0** and later sets a flag at an unrelated RBX+0x2C. RCX source is not proven to be the main GPU-context base.
   - Focused decompiled expression confirms: *(undefined4 *)(*(longlong *)(lVar2+0x49b0)+0x2160)=0, under branch where lVar2 != 0 and *(char *)(lVar2+0xF3A) != 0; returns 1 on that branch.
   - This is **32-bit clearing** of a field, not a proven producer of a 64-bit Falcon callback-owner pointer.

3. **FUN_141662D70** at 0x1416656EC:
   - Listing shows a selector/state sequence at RBX+0x212C; loads RCX=[RBX+0x21F8], checks [RCX+0x4450] < 0x160, tests dword [RBX+0x2160] nonzero, and conditionally stores **MOV dword ptr [RBX+0x2160],R14D**, followed by setting dword [RBX+0x218C]=1.
   - It is a **conditional 32-bit overwrite**; the value of R14D and object identity are not established by this 12-before/4-after instruction window. Function's full 51,015-character C was generated, but focused term 0x2160 appeared **zero times**; decompiler may have expressed it indirectly or optimized it, and the report does not contain its body.
   - Do not infer a 64-bit pointer writer from the 32-bit store, or that R14D equals zero absent assembly evidence.

This reinforces the previously established distinction: FUN_140124A90 obtains RDX=[RBX+0x2160], loads RAX=[RDX+0x170], then makes a CFG-guarded call. **There is still no static proof that this callback object is the nested 0x9B0-byte Falcon HS dispatch instance**, or that any of the three +0x2160 writers alias the consumer RBX base.

## New tiny, read-only data-inspection option and limited verification

Extended the existing research/ghidra/nvlddmkm_booter_discovery.py with optional **TRACE_STATIC_BYTES**, accepting up to four explicit VA strings; each reads exactly **64 bytes** from an initialized, nonexecutable Ghidra memory block (refuses block overruns), using the existing _memory_bytes helper. It prints four 16-byte hex lines and first qword in little-endian hexadecimal without labeling the bytes as pointers, and returns PARTIAL if any region is unavailable. No disassembly, Ghidra DB writes, GPU operations, new dependency, or extra file. Existing source validation against the expected MD5/image base remains. Four **standalone** local logic tests and Python syntax check passed on an independently copied helper, covering successful two-address read, invalid region rejection, short read and malformed/capped requests. Four equivalent regression cases were added to the repo's existing test file, but **the complete repository test suite and actual PyGhidra execution of this option were NOT run in this environment**; do not misreport 4 helper tests as full repository test results.

Next Ghidra Python 3 console run after syncing main, without repeating the timed-out decompilation:

    exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TRACE_STATIC_BYTES": ["0x140fe99c0", "0x140fe9a00"], "TRACE_INSTRUCTION_SITES": ["0x140a49292", "0x1416656c9"], "__name__": "__main__"})

A static constant whose first 8 bytes resemble an address does not alone prove pointer semantics; verify expected PE image range and data/function references before drawing conclusions. Trace R8 origin at FUN_140A48220 and R14D definition in FUN_141662D70 only from actual listing. If neither constant block yields an object pointer and no 64-bit literal writer is seen, consider computed-offset or aggregate-copy producers and separately trace the dynamic constructor path. No unsafe GPU action permitted.

## Remaining gates

The signed production Booter source/header/signature, third-argument descriptor producer of FUN_140BF3880, direct **verified** invocation via nested dispatch+0x170, actual GA102/AD102 runtime selector, cryptographic acceptance and any unlock remain unproven. No device/driver/UEFI/firmware changes; CAN_DETACH=false, CAN_UNLOCK=false, CAN_FLASH=false. Immutable process/recovery audit untouched.

---

# 2026-11-05 14:14 PST — Writer-focused +0x2160 scan resolves three static stores, no confirmed GPU-context pointer producer

## Source, integrity and completion status

New user-run Ghidra report: nvlddmkm-61742-booter-discovery-20261105-141443-070611.txt. Original uploaded file **2,695 bytes**, SHA-256 **5b47e7e59a21fdcccdf2f11223256dfe6db86a192f20a787f1b912c6a4544b1e**. Driver nvlddmkm.sys Windows 617.42, MD5 3fb9afac9d0e394723e830aa14e60512, Ghidra image base 0x140000000. Mode: passive read-only existing executable-byte/instruction scan, SCAN_STRINGS skipped, SLOT_SCAN_DISPLACEMENT=0x2160, SLOT_SCAN_FOCUS=write, no Ghidra database or GPU modifications.

Final Ghidra report **STATUS=COMPLETE** (elapsed 0.130s). All **12 initialized executable blocks** and **19,689,472 bytes** covered within fixed budget. **167 raw disp32 matches**, **167 distinct existing instruction matches**, **3 selected field-write candidates**, **3 recorded**, **capped=False**, **scan_complete=True**. Therefore the writer-filter output was not truncated. This is exhaustive only for the specific raw-displacement/opcode/textual filter; it does not exclude computed-address writes, struct copies, aliases, or other instruction forms.

## Three observed explicit write candidates (object identity unknown)

| Instruction VA | Existing Ghidra containing function | Exact instruction | Interpretive boundary |
|---|---|---|---|
| 0x140A492DE | FUN_140A48220 | MOVUPS xmmword ptr [R8 + 0x2160],XMM0 | Writes 16 bytes starting at this field, potentially clears or initializes a region; XMM0 value and R8 object provenance not yet observed |
| 0x141568841 | FUN_141568760 | MOV dword ptr [RCX + 0x2160],0x0 | Writes a 32-bit zero; does NOT by itself establish a 64-bit pointer assignment |
| 0x1416656EC | FUN_141662D70 | MOV dword ptr [RBX + 0x2160],R14D | Writes 32-bit contents of R14D; does NOT by itself establish a 64-bit pointer assignment |

The consumer previously established in FUN_140124A90 reads a **64-bit pointer** by MOV RDX,qword ptr [RBX+0x2160], then MOV RAX,qword ptr [RDX+0x170] and CALL qword ptr [0x140E02AA8] via Windows Control Flow Guard. It has **not** been proved that the register bases of any of the three static writers alias the consumer's RBX GPU/context object. Even if a write aliases it, the 128-bit store is not necessarily construction of a callback-object pointer; it may clear two qwords, and the 32-bit writes are partial. No initialization to the nested Falcon 0x9B0-byte dispatch-object address has been shown.

The earlier FUN_140001040 dword +0x170 bitfield unpacker is an unrelated false positive from the original broad slot scan: it writes 0/1 to a 32-bit output field, not a 64-bit callback. This is a separate confirmed exclusion and does not affect the current +0x2160 write scan.

## Next bounded, read-only evidence acquisition

Investigate ALL THREE containing functions at their exact write sites, but focus decompilation output on relevant +0x2160 references because first and third functions may be very large. Existing script supports both bounded existing-instruction context and DECOMP_FOCUS_TERMS (no change/test necessary):

    exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TRACE_INSTRUCTION_SITES": ["0x140a492de", "0x141568841", "0x1416656ec"], "TARGET_FUNCTIONS": ["0x140a492de", "0x141568841", "0x1416656ec"], "DECOMP_FOCUS_TERMS": ["0x2160"], "__name__": "__main__"})

Read the instruction windows to locate XMM0/R8/RCX/RBX/R14D definitions; inspect surrounding decompiled lines and called helper semantics. If focus excerpts are capped or absent, retain PARTIAL rather than claiming whole-function proof. Under no circumstances identify a function as producer of the **specific GPU context+0x2160 pointer** without evidence of base-object identity and full 64-bit pointer value.

Current boundaries unchanged: actual invocation of nested HS dispatch +0x170, param_3 signed binary descriptor provenance, Windows production Booter source, AD102/GA102 runtime selection, cryptographic signature acceptance, unlock/detach/flash all unproven or not authorized. CAN_DETACH=false, CAN_UNLOCK=false, CAN_FLASH=false. Immutable process/recovery audit untouched.

---

# 2026-11-05 14:03 PST — GPU-context +0x2160 producer unresolved; explicit field-write scan added

## Source evidence and coverage distinction

New user-run passive Ghidra report: nvlddmkm-61742-booter-discovery-20261105-140309-008364.txt. Uploaded 12,852 bytes; SHA-256 **42552890bfc06f5e600a56366339853e53aaa84886aab7f9ef44bb326cb739db**. Loaded Windows NVIDIA nvlddmkm.sys 617.42 MD5 **3fb9afac9d0e394723e830aa14e60512**, base 0x140000000, read-only existing executable bytes and Ghidra instruction listing. SCAN_STRINGS=False, SCAN_SLOT_DISPLACEMENT=0x2160, default SLOT_SCAN_FOCUS=all. Reports HARDWARE_ACTION=NONE, GHIDRA_MUTATION=NONE and **STATUS=PARTIAL**.

Exactly **12 initialized executable blocks**, totaling **19,689,472 bytes**, were scanned (reported time 0.111s). **167 raw displacement-byte matches**, 167 distinct defined instructions, 167 selected by all-mode, but only **80 recorded** due MAX_SLOT_CANDIDATES=80. The remaining **87** matching instructions are **not visible** in this report. The 80 displayed lines comprise **78 MOV qword PTR loads** from [base+0x2160] and **2 LEA** address computations. They contain **zero explicit memory writes to +0x2160**. Critically, this is not evidence that the full driver has no such writer; the 87 omitted instructions may contain stores. Byte coverage was complete; candidate reporting incomplete.

Existing exact consumer in FUN_140124A90 at 0x140124B4C:

    MOV RDX,qword ptr [RBX + 0x2160]
    MOV RCX,RBX
    MOV RAX,qword ptr [RDX + 0x170]
    CALL qword ptr [0x140E02AA8]

The context field at +0x2160 provides a pointer to an object with a +0x170 callback; actual identity as the independently constructed 0x9B0-byte Falcon HS dispatch object is STILL UNPROVEN. No HS-loader invocation, production Booter binary/header/signature, descriptor producer or GPU runtime class selection is established.

## Minimal scanner improvement and independent host verification

Added optional **SLOT_SCAN_FOCUS='write'** to existing research/ghidra/nvlddmkm_booter_discovery.py. This reuses SCAN_SLOT_DISPLACEMENT's same executable-block raw disp32 scan, existing Ghidra instruction map, memory/time/80-entry bounds and complete/PARTIAL/ERROR reporting. It selects only explicit memory-destination writes and read-modify-write operations with a +0xNNNN field in an existing Ghidra assembly instruction (e.g., MOV qword ptr [REG+0x2160],REG; MOVUPS; XCHG including memory-second operand), rather than false-positive loads, comparisons and LEA operations. It annotates output as FIELD_WRITE_QWORD, FIELD_WRITE_XMMWORD, FIELD_EXCHANGE, etc. The reported candidate is NOT proved to be a pointer assignment to the specific GPU-context object; base register, field meaning and original RHS must be traced. The filter is intentionally non-exhaustive: can miss memcopies, computed-index stores, different opcode variants, or writes at an overlapping offset.

Added focused regression tests to existing research/ghidra/test_nvlddmkm_string_leads.py covering integration of stored 64-bit values vs loads, false positive LEA/CMP removal, SIMD stores, exact +0x2160 address validation, memory-second XCHG, and rejecting unrelated offsets. **29/29 tests passed** with the final local sources; Python syntax compilation succeeded. The same source and test Git blob identifiers were recreated on GitHub and matched the tested local files. **Actual Ghidra execution of this new mode remains pending.**

## Next read-only request: find explicit producer candidates

Synchronize main and run this existing Python 3 Ghidra console command (no hardware or DB writes):

    exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "SCAN_SLOT_DISPLACEMENT": "0x2160", "SLOT_SCAN_FOCUS": "write", "__name__": "__main__"})

If candidates are reported, decompile containing functions and inspect source register pointers, offset width and actual target object's identity. If no literal write is found and scan is COMPLETE, only infer **no matching explicitly encoded displacement stores under this bounded filter**, NOT no producer: initialization may occur through memcpy, struct copy, or an alternate alias. If candidate cap is reached mark STATUS=PARTIAL and preserve uncertainty. Do NOT conflate this context+0x2160 callback table with the outer 0x3550-byte object / embedded +0xF0 / nested +0x170 Falcon HS callback without alias evidence.

No production Booter provenance, signed descriptor origin, accepted signature or AD102/GA102 live branch has been proven. Safety gates CAN_DETACH=false, CAN_UNLOCK=false, CAN_FLASH=false. Immutable process/recovery audit remains untouched.

---

# 2026-11-05 13:54 PST — Three guarded +0x170 transfer paths decompiled; GPU-context +0x2160 producer is next proof gate

## Primary source and completion

User-run read-only Ghidra report nvlddmkm-61742-booter-discovery-20261105-135448-028572.txt, actual uploaded 10,209 bytes, SHA-256 b34d5b973a98860dc32b513f3ccc8baf4fc7e8752351a9751cb5f65bbadfd87b. Driver nvlddmkm.sys Windows 617.42, MD5 3fb9afac9d0e394723e830aa14e60512, Ghidra base 0x140000000. All three selected function decompilations are complete (clipped=False), and report STATUS=COMPLETE, SCAN_STRINGS skipped, HARDWARE_ACTION=NONE and GHIDRA_MUTATION=NONE. This is evidence for source/listing interpretation, NOT a physical GPU run.

## Specific guarded calls: offset +0x170 alone does not identify the Falcon dispatch object

1. FUN_140124A90, which is an independently identified GSP-initialization-stage routine with a separate branch invoking FUN_1401B2C10 (GSP cached-argument builder), has the following consecutive machine instructions under a branch conditioned on byte at context+0xEB9:

    0x140124B46 JZ 0x140124DB4
    0x140124B4C MOV RDX,qword ptr [RBX + 0x2160]
    0x140124B53 MOV RCX,RBX
    0x140124B56 MOV RAX,qword ptr [RDX + 0x170]
    0x140124B5D CALL qword ptr [0x140E02AA8]

   This is a bona fide static sequence selecting a callback from [GPU_context+0x2160]->+0x170 and transferring through Windows CFG guarded-call dispatcher; the Ghidra report DOES NOT determine what object [RBX+0x2160] holds or whether it equals the separately constructed nested Falcon HS dispatch object. FUN_140124A90 reaches context offsets including +0x57E0, +0x57E4 and +0x584C, beyond the standalone 0x3550-byte outer allocation reconstructed earlier; the two structure bases cannot simply be equated. GSP cached args constructed nearby are not proof of production Booter image/header/signature sourcing. Inbound direct calls to FUN_140124A90 are at 0x140125089 and 0x140125225; no runtime evidence for either GPU.

2. FUN_140175B60 is the compact wrapper:

    0x140175B60 MOV RAX,qword ptr [RCX + 0x170]
    0x140175B67 JMP qword ptr [0x140E02AA8]

   A true guarded indirect *tail transfer* through the caller-supplied RCX object's +0x170 slot (assuming the known Windows CFG dispatch convention), but the object type is unknown. Ghidra decompiled the body as an opaque guard-dispatch call with void(void) prototype; that decompiler prototype is not proof of the actual arguments or return. Only DATA incoming references are listed: 0x140E05EE8, 0x140E599C0, 0x140E5C390. None identifies a Falcon caller.

3. FUN_1403235F0 contains:

    0x1403235F0 MOV RAX,qword ptr [RDX + -0x8]
    0x1403235F4 ADD RDX,-0x8
    0x1403235F8 MOV RAX,qword ptr [RAX + 0x170]
    0x1403235FF JMP qword ptr [0x140E02AA8]

   The +0x170 callback here is relative to an **intermediate pointer loaded from [original_RDX-8]**, not directly relative to RDX. Original RDX is adjusted before tail transfer. This resembles an interface-specific callback indirection but no original type/vtable identity has been recovered. Ghidra DATA references: 0x140E0783C, 0x140E9EB40, 0x140EDADD8, 0x140EE0280, 0x140EE3050. No proven link to the Falcon HS dispatch or any Booter descriptor.

The previous 246 filtered scan matches therefore form a candidate index, not 246 verified Falcon HS loader invocations. The three individually inspected sites establish actual assembly-level transfer mechanics but not nested dispatch object aliasing, physical execution or firmware authentication.

## Highest-value next passive experiment, no changes to scripts or hardware

The immediate missing dataflow fact is the **producer of GPU_context+0x2160**, used as the callback table base by FUN_140124A90. Rather than expand the 80-cap +0x170 scan, run the existing bounded raw-disp32 plus existing-instruction scan on +0x2160:

    exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "SCAN_SLOT_DISPLACEMENT": "0x2160", "__name__": "__main__"})

This mode searches initialized executable bytes only with a fixed 192-MiB/90-second/80-candidate bound. Results contain potential writers, reads and unrelated fields sharing the offset; do NOT infer producer/object identity until the relevant containing functions are decompiled and their register origins verified. Treat STATUS=PARTIAL accurately if candidates are capped. Specifically test whether the pointer stored at +0x2160 originates from the previously characterized FUN_1417E99B0 / FUN_14056C510 nested 0x9B0-byte Falcon dispatch instance, or whether the +0x170 guarded call in FUN_140124A90 belongs to a separate driver interface. Record a negative result as elimination, not as progress toward HS-loader execution.

Pending proof gates: actual static invoker of nested dispatch+0x170 selecting FUN_140BF3880, its param_3 HS binary descriptor producer, production Booter image/header/signature origin, GA102 versus AD102 runtime branch, cryptographic acceptance and safe reversible testing. CAN_DETACH=false, CAN_UNLOCK=false, CAN_FLASH=false. Process/recovery audit unchanged.

---

# 2026-11-05 13:46 PST — Transfer-focused +0x170 scan: 246 candidates, 80 reported; no Falcon dispatch caller proven

## Source report and scope

User-run read-only PyGhidra report: nvlddmkm-61742-booter-discovery-20261105-134631-021861.txt, 17,758 bytes, SHA-256 4ef5fe9d208c7c206d5d3208291cb68a72326df81b5478d1c39d66d4629fb5a7. Target driver Windows 617.42 nvlddmkm.sys MD5 3fb9afac9d0e394723e830aa14e60512, Ghidra base 0x140000000. Mode SCAN_SLOT_DISPLACEMENT=0x170, SLOT_SCAN_FOCUS=transfer, SCAN_STRINGS=False. No hardware action or Ghidra DB changes. Report STATUS=PARTIAL due to capped reported candidates.

All 12 executable initialized blocks were scanned, 19,689,472 bytes; 2,445 raw byte-pattern matches, 1,901 existing instruction-level +0x170 memory-operand matches, 246 transfer-focused heuristic matches, **80 recorded and 166 omitted**. All 80 recorded belong to GUARD_TRANSFER_NEARBY, covering 67 unique functions. The remaining 166 are not available for inspection in this report; their classification is unknown. Reported elapsed time 1.617 seconds. The coverage of executable bytes was complete, but selected-candidate reporting was not complete. Do not mislabel this as a full caller inventory.

## Guard-transfer candidate is not object provenance

The focused heuristic recognizes a 64-bit memory load such as MOV RAX,qword ptr [base+0x170] followed within eight existing same-function instructions by Windows CFG-guarded CALL or JMP through the dispatch pointer at 0x140E02AA8. It does not prove the base object equals the known Falcon 0x9B0-byte nested dispatch object, the pointer remains unmodified, or this branch executes in any GPU runtime path. The 246 matches are NOT 246 Falcon calls or an established producer of signed Booter bytes.

## Next bounded investigation targets

- FUN_140124A90 at 0x140124B56: MOV RAX,qword ptr [RDX+0x170], guarded CALL one instruction later. Independently linked to GSP boot-args construction, but RDX identity unknown; do not merge GSP argument builder and signed production Booter provenance.
- FUN_140175B60 at 0x140175B60: MOV RAX,qword ptr [RCX+0x170], guarded JMP one instruction later. Compact apparent tail-transfer; base object unknown.
- FUN_1403235F0 at 0x1403235F8: MOV RAX,qword ptr [RAX+0x170], guarded JMP one instruction later. Compact apparent tail-transfer; base object unknown.
- Secondary 0x14012B802 and 0x14013AE27 have larger gaps and need register-liveness proof.

Run the existing read-only script in the Ghidra Python 3 console:

    exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x140124a90", "0x140175b60", "0x1403235f0"], "TRACE_INSTRUCTION_SITES": ["0x140124b56", "0x140175b60", "0x1403235f8"], "__name__": "__main__"})

Inspect origin of the load's base register in each decompiled function and whether it can be traced to outer+0xF0 embedded context, nested pointer at outer+0x108, then nested slot+0x170. If a function clips, leave overall status PARTIAL, then request targeted DECOMP_FOCUS_TERMS. No new scanner changes are warranted solely to raise candidate caps.

## Evidence-to-execution boundary

Static hierarchy established: outer object 0x3550 bytes, embedded context at +0xF0, dispatch pointer at outer+0x108, nested dispatch 0x9B0 bytes, back-pointer at dispatch+0x4B0, and +0x170 function pointer conditionally selecting FUN_140BF3880 (Falcon HS binary DMA load/execute) or FUN_140092D80 (constant 0x56). Actual invocation of THIS nested dispatch slot, third-argument signed HS binary descriptor producer, production Booter image/header/signature, cryptographic acceptance and physical AD102/GA102 selected branch remain unproven. CAN_DETACH=false, CAN_UNLOCK=false, CAN_FLASH=false. Immutable process/recovery audit unchanged.

---

# 2026-11-05 13:25 PST — 0x170 scan completed executable-byte coverage but omitted 1,821 candidate instructions; transfer-focused scan added

## User report and precise interpretation

Input Ghidra report nvlddmkm-61742-booter-discovery-20261105-132517-487652.txt, **11,094 bytes**, SHA-256 **cdc66a22a542ddb5f8e5db0dd19c29685e8125d56b0cb36427843d27f3b62313**. Loaded original NVIDIA Windows 617.42 nvlddmkm.sys MD5 3fb9afac9d0e394723e830aa14e60512, base VA 0x140000000. Passive existing-reference/byte scan, SCAN_STRINGS=False, SCAN_SLOT_DISPLACEMENT=0x170, HARDWARE_ACTION=NONE, GHIDRA_MUTATION=NONE.

The scan enumerated **12 initialized executable blocks, read 19,689,472 executable bytes**, found **2,445 raw literal disp32 byte matches** and **1,901 distinct existing Ghidra instructions** with a textual +0x170 memory operand. Because MAX_SLOT_CANDIDATES=80, it **recorded only 80** candidate instructions and suppressed the other **1,821**. Its STATUS=PARTIAL and scan_complete=False are justified by *incomplete reporting*, not by an unread executable block: all 12 blocks appear in the report's SLOT_SCAN_BLOCK records and total scanned bytes equal their summed sizes. Reported duration 1.205 s. Previously recorded +0x170 results from ordinary integer fields, stack slots, compares, and writes cannot be interpreted as calls of nested dispatch object +0x170. No actual indirect invocation, descriptor provider or runtime GPU path was found.

## Corrected next step: filter semantically relevant transfer candidates

The existing research/ghidra/nvlddmkm_booter_discovery.py now accepts optional **SLOT_SCAN_FOCUS='transfer'** with SCAN_SLOT_DISPLACEMENT='0x170'; the default **'all'** remains backward compatible. No new dependencies or new script file.

Focused mode retains only already-defined Ghidra instructions of two limited forms:

1. CALL/JMP with an explicit memory operand containing +0x170 (class DIRECT_MEMORY_TRANSFER).
2. MOV of a qword pointer from memory +0x170 into a 64-bit register followed within **at most eight existing instructions and the same Ghidra function** by CALL/JMP through that register (REGISTER_TRANSFER_NEARBY), or a nearby known CFG guarded-dispatch transfer (GUARD_TRANSFER_NEARBY).

It scans the same executable bytes using existing Ghidra Listing and still observes the **192 MiB**, **90 s**, and **80 recorded candidates** bounds, maintaining cross-chunk matches and failure status on unreadable blocks/incomplete budgets. Summary now distinguishes all distinct offset-bearing instructions from *focus-selected* candidates, and the cap applies to selected candidates. A reported STATUS=COMPLETE would mean the specified focus search exhausted executable blocks without caps; it would **not** imply exhaustiveness of all indirect transfer shapes.

**Proof limitations:** The focus mode performs no actual def-use or control-flow equivalence proof: an instruction within eight linear instructions may be unreachable or clobber the register, and longer-range alias chains, different instruction encodings, trampolines and separate-function loads may be missed. Candidate base register is not yet identified as the 0x9B0-byte nested dispatch object, and direct guarded calls cannot be treated as authenticated production Booter execution. Do not assert these matches are effective callbacks until individually decompiled and traced.

**Verification:** Local syntax compilation succeeded for script and updated tests; all **24/24 tests in the existing Ghidra test module passed**, including previous whole-scan/cap/budget cases and new focused-mode integration, direct memory transfer, nearby register/guard transfer, unrelated-field and unrelated-call rejection, same-function boundary checks, and invalid focus rejection. This new focus mode has **not** run in Ghidra; tests are host-level evidence only.

After updating the user's local main checkout, run exactly:

    exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "SCAN_SLOT_DISPLACEMENT": "0x170", "SLOT_SCAN_FOCUS": "transfer", "__name__": "__main__"})

If the candidate report is still capped, keep STATUS=PARTIAL and tighten using real evidence, not an invented success. Follow genuine caller sites backward from the known embedded context pointer outer+0x108 -> nested dispatch and forward to the third-argument signed-data descriptor consumer FUN_140BF3880. Physical AD102/GA102 selection, Windows production Booter image/header/signature provenance and cryptographic acceptance remain unproven. No unlock/detach/flash or system/firmware modification permitted; CAN_DETACH=false, CAN_UNLOCK=false, CAN_FLASH=false. Immutable recovery audit untouched.

---

# 2026-11-05 13:10 PST — Windows 617.42 HS-loader alternative is a not-supported return; real Falcon DMA consumer descriptor mapped

## Primary evidence and status

User-run passive Ghidra report nvlddmkm-61742-booter-discovery-20261105-131018-348907.txt; exact uploaded size **9,897 bytes**, SHA-256 **07ed5e47971eacd5fd6cc6ccbe55ce041a775d339461029fb9ee994073e121e1**. Expected driver nvlddmkm.sys Windows 617.42 MD5 **3fb9afac9d0e394723e830aa14e60512**, Ghidra image base 0x140000000. Two complete unclipped function decompilations, reported STATUS=COMPLETE, SCAN_STRINGS=SKIPPED_BY_CALLER, HARDWARE_ACTION=NONE, GHIDRA_MUTATION=NONE. A completed static decompilation **does not** prove a GPU ever executes either implementation.

## Two possible dispatch slot +0x170 implementations are semantically distinct

- **FUN_140092D80:** Entire decompiled body is simply return 0x56. This is a constant error path, not a second Falcon image loader. NVIDIA open-gpu-kernel-modules 615.78.08 declares NV_ERR_NOT_SUPPORTED = 0x00000056 ("Call not supported") in src/common/sdk/nvidia/inc/nvstatuscodes.h: https://github.com/NVIDIA/open-gpu-kernel-modules/blob/615.78.08/src/common/sdk/nvidia/inc/nvstatuscodes.h. That is an independent cross-version symbolic match only; no original Windows 617.42 symbolic status definition has been recovered. The function has many unrelated direct call and data references; broad xrefs do not establish it is a specific Booter selector.
- **FUN_140BF3880:** Full decompiled body is int FUN_140bf3880(longlong param_1,longlong param_2,undefined8 *param_3), and uses string "flcnLoadAndExecuteHsBinaryViaDma_GA10X". It implements Falcon high-security binary DMA loading/execution operations when called. The first two arguments appear to be GPU/context objects; their recovered high-level C types remain UNKNOWN. The third is a descriptor consumed by this generic HS binary loader, NOT automatically an authenticated production GSP Booter descriptor.

## Third-argument consumer-side layout (all offsets from param_3 in bytes)

| Offset | Direct evidence | Qualification |
|---|---|---|
| +0x00 | *param_3 supplied as byte-copy source to FUN_1400DF7C0 when a fresh allocation is needed | Image source pointer; provenance unresolved |
| +0x08 | 32-bit length is rounded up via (value + 0xFF) & 0xFFFFFF00, stored back into descriptor | Only when param_3+0x40 is null |
| +0x0C | 32-bit subfield used to compute a GPU address with length/offset subtraction | Exact semantics unknown |
| +0x10 | first transfer-loop byte count, increments by 0x100 | No formal field type recovered |
| +0x14 | first transfer-loop target offset | Used with 0x114 register programming |
| +0x18 | first transfer-loop secondary offset | Used with 0x11C register programming |
| +0x1C | addend for another GPU-read address calculation | Exact field name unknown |
| +0x20 | second-phase transfer byte count | Increments by 0x100 |
| +0x24 | second-phase target offset | Used with 0x114 programming |
| +0x28 | 32-bit offset value, 0xFFFFFFFF sentinel special case | Used in second-phase base/counters |
| +0x2C | byte tested for equality to 1 | Controls optional final FUN_1406A40F0 call |
| +0x30, +0x34, +0x38, +0x3C | additional integer arguments / control words read near completion | No name/signature fields yet |
| +0x40 | optional pointer to an existing memory descriptor (param_3[8]); otherwise create/map/copy a temporary allocation and clean it up | A pre-provisioned pointer suppresses the new-copy path |

Visible callback sequence includes FUN_1401B9020 descriptor allocation, FUN_1401B87B0 storage alloc, FUN_1401BC180 mapping, FUN_1400DF7C0 byte copy, FUN_1401BB0B0 mapped GPU address, FUN_1406A2460 state setup, FUN_1406A2310, FUN_1406A23B0 progression checks, FUN_1406B6470 programming offsets 0x114/0x11C/0x118 with configured values, FUN_140754610 near completion, conditional FUN_1406A40F0, and optional resource cleanup with FUN_1401BABD0 and FUN_1401BA330. Guarded indirect calls printed as PTR__guard_dispatch_icall_140E02AA8 do not reveal actual destination functions; do not attribute them without instruction-level proof.

## Next targeted, passive search for actual invocation

The incoming direct refs to FUN_140BF3880 are DATA, not ordinary CALLs, and its assignment into the nested dispatch-object +0x170 is established by separate earlier FUN_1417E8550 evidence. Finding the actual **indirect invoker of +0x170**, and tracing its third-argument descriptor backward, is now the primary blocker.

The existing PyGhidra discovery script was extended, without adding dependencies, by the optional SCAN_SLOT_DISPLACEMENT=0x170 mode. It scans **initialized executable memory blocks only**, not firmware/hardware or nonexecuting driver data; finds x64 little-endian disp32 bytes 70 01 00 00 with cross-chunk handling; accepts candidates only if already-defined Ghidra instruction text contains a bracketed +0x170 operand; reports containing function entry, VA, and assembly. Search is bounded by 192 MiB, 90 seconds and 80 recorded instruction candidates, and issues STATUS=PARTIAL if a budget/recording cap prevents complete coverage. Candidate displacement usage alone is NOT proof of dispatch-object identity, callback invocation, argument provenance or runtime selection. Local Python compilation passed and **16/16 relevant local unit tests passed**, including cross-chunk matching, rejection of unrelated immediates, incomplete byte budget, exact multi-block budget boundary, capped candidates and invalid offset rejection. **This scan option has NOT been run inside Ghidra.**

Next Ghidra Python 3 command, after syncing main:

    exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "SCAN_SLOT_DISPLACEMENT": "0x170", "__name__": "__main__"})

Follow only actual candidate instructions showing plausible indirect invocation and then recover the third-argument descriptor's producer and source signed image/header/signature from static references; even a code match does not prove runtime invocation. Physical RTX 4090/3080 class selection, Windows production Booter image origin, cryptographic signature acceptance and live unlock remain UNPROVEN. Keep CAN_DETACH=false, CAN_UNLOCK=false, CAN_FLASH=false. Immutable process/recovery audit unchanged.

---

# 2026-11-05 — FUN_141752AA0 is a tail-call thunk to the dispatch builder; EAX status propagation proven

## Primary evidence

User-submitted read-only Ghidra instruction report: nvlddmkm-61742-booter-discovery-20261105-130201-823136.txt, 1,921 bytes, SHA-256 9163e32a133e60d824e1503790d4f3d8d6ebc035586648cfea240d1dfdaeb9da. Ghidra target: NVIDIA Windows nvlddmkm.sys driver 617.42, MD5 3fb9afac9d0e394723e830aa14e60512, loaded base 0x140000000. TRACE_INSTRUCTION_SITES of 0x141752AF2 with SCAN_STRINGS=False. Existing listing only, no decompilation, no new disassembly or database writes, no physical GPU operation; STATUS=COMPLETE applies to bounded instruction-site output, not runtime behavior.

## Machine-code resolution of previous EAX/void prototype disagreement

The report identifies entry FUN_141752AA0 and ends its main visible path at the following instruction sequence:

    0x141752AEA MOV byte ptr [R9 + 0x14],0x0
    0x141752AEF MOV RCX,R9
    0x141752AF2 JMP 0x14056c510

**This is an unconditional tail jump**, not CALL followed by RET. R9 holds the embedded parent/dispatch-owner context on this path; its address is transferred into Windows x64 first-argument register RCX for FUN_14056C510. Under normal return mechanics the target function returns directly to FUN_141752AA0's original caller, rather than returning to FUN_141752AA0. No EAX/RAX overwrite is visible at this tail jump. The previous independently recorded caller of FUN_141752AA0 at 0x14017B258 immediately executes MOV EBX,EAX; TEST EAX,EAX; JNZ 0x14017B2A1. Thus **the caller's status test receives FUN_14056C510's result on this tail-call path**.

This **supersedes** prior descriptions of FUN_141752AA0 as having a meaningful void-return interface or as necessarily ignoring the builder's status. The separately decompiled void prototype reflected Ghidra's incomplete type inference, not reliable machine-level result semantics. The return status is meaningful for the caller. The previously proven FUN_14056C510 source has distinct error results and passes FUN_1402E7E60's zero status through the successful construction path.

Important control-flow nuance: the instruction-inspection tool lists AFTER 0x141752AF2, e.g. at 0x141752AF7 CMP R10D,0x2, purely as **spatial listing context**. These following instructions are not executed as sequential fall-through from the unconditional JMP. Do not infer a post-jump EAX adjustment from the displayed AFTER lines; those instructions belong to other reachable branches of FUN_141752AA0.

## Current evidence gates and next bounded step

The dispatch-object construction ABI is now structurally established end-to-end at the static code level:

1. 0x3550-byte outer object contains embedded context at outer+0xF0.
2. Embedded context stores 0x9B0-byte nested dispatch object at context+0x18 (outer+0x108).
3. Nested object records embedded context in dispatch+0x4B0; machine-level RCX continuity into FUN_1406B3FD0 proves the fixed defaults apply to the same dispatch object.
4. Architecture-dependent FUN_1417E8550 registers FUN_140BF3880 or alternative FUN_140092D80 at nested dispatch slot +0x170.
5. FUN_141752AA0 tail-jumps to FUN_14056C510 and the outer constructor checks the result in EAX, so this portion of static status propagation is confirmed.

**Still unresolved:** actual runtime code consuming/calling nested dispatch+0x170; argument contract and signed production Booter descriptor source at that indirect call; which selector branches physical GA102/AD102 take; signature acceptance and any safe reversible hardware testing. The alternative slot function FUN_140092D80 has not been classified. Next read-only Ghidra command decompiles that alternative function and the known HS-loader implementation as a paired **comparison of callbacks** (no binary scan; new finding should guide search for a real dispatch invoker):

    exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x140092d80", "0x140bf3880"], "__name__": "__main__"})

If clipped, report PARTIAL and obtain selective excerpts; do not interpret a successful decompile as evidence the callback is ever invoked. Avoid mistaking the external GSP UCODES bindataArgs or GSP SR metadata for the production Booter image. No unlock/detach/flash or firmware/driver/UEFI modification. CAN_DETACH=false; CAN_UNLOCK=false; CAN_FLASH=false. Immutable audit untouched.

---

# 2026-11-05 — Existing callsite assembly clarifies Falcon dispatch ABI and status consumption

## Source and verification

User-run PyGhidra report nvlddmkm-61742-booter-discovery-20261105-124949-471906.txt, 2,289 bytes, SHA-256 8d22e0097242d0764a9625035e089df517d9b96256d3ccdeee1f66bc1212f695; Windows nvlddmkm.sys 617.42 Ghidra MD5 3fb9afac9d0e394723e830aa14e60512, base 0x140000000. SCAN_STRINGS=SKIPPED_BY_CALLER; TRACE_INSTRUCTION_SITES reports two existing executable code sites, STATUS=COMPLETE, HARDWARE_ACTION=NONE, GHIDRA_MUTATION=NONE. No decompilation was requested or performed in this run. The Ghidra listing is the primary evidence; no driver/firmware modification or physical GPU test occurred.

## ABI inconsistency A — now resolved at the machine-code callsite

Site 0x1402E7E6B lies in FUN_1402E7E60. Ghidra prints, in order:

    0x1402E7E60 SUB RSP,0x28
    0x1402E7E64 MOV qword ptr [RCX + 0x4b0],RDX
    0x1402E7E6B CALL 0x1406b3fd0
    0x1402E7E70 XOR EAX,EAX
    0x1402E7E72 ADD RSP,0x28
    0x1402E7E76 RET

Under the Windows x64 calling convention, RCX is the first pointer argument. No instruction changes RCX between storing dispatch+0x4B0=parent and invoking FUN_1406B3FD0. Therefore, the separately decompiled FUN_1406B3FD0(longlong param_1) receives the **same dispatch-object pointer** in RCX. Its previously recovered fixed-default writes at offsets +0x3F0 through +0x458 and +0x988 through +0x9A4 are assigned to the nested 0x9B0-byte dispatch object on this path. This supersedes the preceding caution that the helper's pointer argument might target a different object. Earlier decompiler output that printed FUN_1406B3FD0() with no arguments was an incomplete prototype inference. Following the call, FUN_1402E7E60 explicitly sets EAX=0, so its normal return is zero independently of the callee's EAX.

The instruction context establishes register transfer at this site, not runtime GPU behavior or hidden function-side effects outside the separately recovered complete callee.

## ABI inconsistency B — caller's status check established; callee forwarding unresolved

At code site 0x14017B258, within outer-object constructor FUN_14017AF30, listing output includes:

    0x14017B252 MOV RDX,RBP
    0x14017B255 MOV RCX,RSI
    0x14017B258 CALL 0x141752aa0
    0x14017B25D MOV EBX,EAX
    0x14017B25F TEST EAX,EAX
    0x14017B261 JNZ 0x14017b2a1
    0x14017B263 MOV R8,R14

This proves the outer constructor **uses the value in EAX immediately after FUN_141752AA0 as its success/error status**, contradicting a literal reliance on the independent Ghidra decompilation prototype void FUN_141752AA0(...). The caller passes arguments RCX=RSI and RDX=RBP. It does **not**, by itself, prove what value the callee places in EAX or whether FUN_141752AA0 forwards FUN_14056C510's return. The complete earlier decompilation of FUN_141752AA0 ends with FUN_14056C510(param_1), but the final assembly epilogue has not been examined. Therefore keep the precise callee return type/forwarding proof gate **OPEN** and do not assert error-propagation semantics at runtime.

## Updated next read-only task

Use existing committed TRACE_INSTRUCTION_SITES option to inspect exactly the final call and epilogue inside FUN_141752AA0, at previously observed callsite VA 0x141752AF2:

    exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TRACE_INSTRUCTION_SITES": ["0x141752af2"], "__name__": "__main__"})

If instructions show a call immediately followed by epilogue/RET with no writes to EAX/RAX, status forwarding is strongly established at ABI level; otherwise report the actual result without forcing a semantic label. Next research must identify a **real indirect invocation** of the nested dispatch slot +0x170 and the production signed Falcon/Booter firmware descriptor producer. The 0x3550 outer object, its embedded context at +0xF0, nested dispatch pointer at outer+0x108 and back-pointer at dispatch+0x4B0 remain static construction facts only. AD102/GA102 actual runtime branch, signed Booter image, cryptographic acceptance and active unlock are unproven. CAN_DETACH=false, CAN_UNLOCK=false, CAN_FLASH=false; immutable recovery audit untouched.

---

# 2026-11-05 — Outer HAL callback selection and finalization flags; targeted callsite instruction inspection added

## Uploaded evidence, direct scope and status

Report **nvlddmkm-61742-booter-discovery-20261105-124243-679240.txt**: exact uploaded size 18,724 bytes, SHA-256 **98d35a81225b9dd4c5fdd4cf142d0d6e577566b8d1c43e2f79bb255d4c31cdf4**. Ghidra-loaded Windows 617.42 nvlddmkm.sys MD5 **3fb9afac9d0e394723e830aa14e60512**, base 0x140000000; passive read-only existing function/reference map, no hardware action or database mutation, SCAN_STRINGS disabled.

- FUN_140179580 (direct caller 0x14017B23E, DATA reference 0x1413DCC50): **clipped=True**, visible C capped at 14,000 characters, so combined report ends **STATUS=PARTIAL**. Do not claim the function's full body/selector logic was reviewed.
- FUN_1401793C0 (direct caller 0x14017B2DF): **clipped=False**, complete decompiled function. Both were called from the previously established FUN_14017AF30 outer 0x3550-byte constructor (setup, then post-initialization).

## Distinguish outer callback table from the nested Falcon HS dispatch slot

FUN_140179580(longlong param_1,longlong param_2,longlong param_3) initializes an **architecture-dependent callback table in the outer object**. The visible code loads uVar1 = *(ushort *)(param_2+0x10), uVar2 = *(ushort *)(param_3+0x10), then derives a high-bit group uVar3 = uVar1 >> 5 and low 5-bit subselector uVar7 = uVar1 & 0x1f, and selects among many named function addresses and fallback implementations. Visible assignments include outer-object fields **+0x1B0, +0x1B8, +0x1C0, +0x1C8, ... through at least +0x278**. The extent and further conditions of the clipped suffix are NOT determined. Both descriptor inputs are observed as reads; the visible decisions mostly use the first descriptor. No visible proof of an HS Booter image parse, signed-image selector, or invocation of FUN_140BF3880.

This *outer* callback table must not be conflated with the separately constructed 0x9B0-byte **nested** dispatch object at outer+0xF0+0x18 = outer+0x108, whose own **slot +0x170** is conditionally assigned to FUN_140BF3880 or alternative FUN_140092D80 in FUN_1417E8550. The slot offset +0x170 is relative to the nested dispatch object, not to the outer 0x3550-byte allocation.

FUN_1401793C0(longlong param_1,longlong param_2,longlong param_3) is a **class-dependent feature/state initializer** for that outer object. The complete body reads class selectors at param_2+0x10 and param_3+0x10, sets conditional flags at outer +0x58, +0x3C4, +0x3C5, +0x3C6, +0x3CB, +0x3E0, +0x3E1; clears or defaults +0x3C3, +0x3C8, +0x3CA, +0x3CC, +0x3D0, +0x3D8, +0x104; and returns. It does not directly reference the nested +0x170 dispatch slot or provide any signed image descriptor. Static GPU generation-specific groups are not runtime evidence for the user's two physical GPUs.

## Targeted resolution of previously recorded ABI contradictions

Two **unresolved**, not-yet-proven decompiler ABI issues remain from earlier turns:
1. FUN_1402E7E60 writes dispatch+0x4B0 = parent and calls FUN_1406B3FD0(), but the separately decompiled callee has a required pointer argument and many field writes. Actual RCX and other register contents at **0x1402E7E6B** have not been checked.
2. FUN_14017AF30's decompiler shows assignment/checking an integer result from FUN_141752AA0 at **0x14017B258**; independently, the helper was decompiled as returning void. Check whether the machine code tests the return register after the call and whether the argument/return ABI inference is sound. Neither contradictory interpretation should be declared proven until instruction-level evidence is collected.

A small additive option **TRACE_INSTRUCTION_SITES** was implemented in existing research/ghidra/nvlddmkm_booter_discovery.py: accepts at most four explicit loaded virtual addresses in executable blocks, uses already existing Ghidra Listing instructions (no disassemble/reanalyze/write) to print up to 12 earlier and 4 later instructions within the same Ghidra function, and emits explicit final STATUS=COMPLETE/PARTIAL/ERROR plus report path. Unavailable/executable mismatch yields PARTIAL, not a false success. The focused output is **instruction context, not ABI or runtime proof**. Regression tests in existing research/ghidra/test_nvlddmkm_string_leads.py cover exact bounded instruction order, invalid site handling and request-size/input rejection. Initial local tests exposed missing properties in the test mocks; these were fixed without weakening checks. **Final host Python syntax compilation passed, and 24/24 local unit tests passed.** Ghidra execution of the new option has not happened.

Read-only next command after syncing repository main:

    exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TRACE_INSTRUCTION_SITES": ["0x1402e7e6b", "0x14017b258"], "__name__": "__main__"})

For the truncated outer-table function, any later investigation must use DECOMP_FOCUS_TERMS driven by actual target offsets/functions; do not assume its omitted tail is irrelevant. The main remaining execution proof is a **real indirect invocation** through the *nested* dispatch object's +0x170 field, including its third-argument signed-image descriptor provider, signed production Booter origin, per-AD102/GA102 branch and signature acceptance. Those gates remain open and untested. No firmware flash, unlock, detach, driver/UEFI mutation or GPU execution authorized by these static findings. CAN_DETACH=false, CAN_UNLOCK=false, CAN_FLASH=false. Immutable recovery audit unchanged.

---

# 2026-11-05 — Outer 0x3550-byte object contains HS dispatch-owner subobject; field defaults and ABI ambiguities recovered

## User-run Ghidra evidence

- Report nvlddmkm-61742-booter-discovery-20261105-123638-627493.txt, SHA-256 d2ac133e888a808e9acf08b52ad8b677f5473a60e4fdff093232ba5c7b3fd194, size 6,309 bytes (actual uploaded bytes checked). nvlddmkm.sys NVIDIA Windows 617.42 MD5 3fb9afac9d0e394723e830aa14e60512; image base 0x140000000.
- Requested 0x14017B258 resolved to enclosing function FUN_14017AF30, complete unclipped decompilation; FUN_1406B3FD0 also complete/unclipped; report STATUS=COMPLETE. The script used SCAN_STRINGS=False and explicitly reports HARDWARE_ACTION=NONE and GHIDRA_MUTATION=NONE.
- Existing Ghidra references for outer constructor FUN_14017AF30 include DATA at 0x1413DCC5C, 0x141055298, 0x1410552A8, 0x1410552C0, and an UNCONDITIONAL_JUMP from 0x1401793B0. Existing incoming direct caller of FUN_1406B3FD0 is 0x1402E7E6B.

## Outer object and nested ownership — correction to generic parent labeling

FUN_14017AF30(longlong *param_1,longlong param_2,uint param_3) allocates (or reuses if param_3 bit 1 is set) a 0x3550-byte outer object, zeroes it, stores flags at +0x44, and locates required descriptors via FUN_14010DC60 using DAT_140EA93F8 and DAT_140EA93D0, with fallbacks FUN_14010E030(...,0x74BC71) and (...,0x34A6D6). It prepares multiple embedded interfaces and installs distinct static vtable-like pointer values (PTR_DAT_140E763F0, PTR_DAT_140E76408, PTR_DAT_140E76420, PTR_DAT_140E764A8, PTR_DAT_140E76618, PTR_DAT_140E76670).

Critical source-level placement:

    puVar1 = puVar3 + 0x1e;        // undefined8* => byte offset +0xF0
    FUN_141752b20(puVar1,lVar5);
    ...
    iVar2 = FUN_141752aa0(puVar1,lVar5);

The previously decompiled FUN_141752AA0 calls FUN_14056C510(param_1), which constructs a separate 0x9B0-byte dispatch object using FUN_1417E99B0; conditional registration in FUN_1417E8550 can set dispatch slot +0x170 to FUN_140BF3880 (GA10x HS load-and-execute) or alternative FUN_140092D80, depending on a 16-bit class/group selector. FUN_14056C510 writes the dispatch pointer at its param_1 +0x18. Since its param_1 in this outer path is **outer+0xF0**, the exact location in this 0x3550-byte outer object is **outer+0x108**. FUN_1402E7E60(dispatch, embedded_context) writes the back-pointer at **dispatch+0x4B0 = outer+0xF0**.

Thus prior documentation shorthand calling the 0x9B0 dispatch object's linked context the “parent object” is imprecise: in this proved construction path, it is a nested/embedded context within a different outer allocation, not the 0x3550-byte allocation base. This is a *static successful-branch* object layout, NOT actual runtime dispatch, AD102 or GA102 selection, GPU authentication, or Booter image provenance.

The outer constructor additionally calls FUN_140179580(puVar3,lVar5,lVar7), then initializes embedded interface constructors FUN_14173CE00, FUN_141752AA0, thunk_FUN_14056A280, FUN_141750C80, and finally FUN_1401793C0(puVar3,lVar5,lVar7) on its success branch. Neither FUN_140179580 nor FUN_1401793C0 is classified yet, and neither is proved to invoke the HS loader.

## FUN_1406B3FD0: fixed field-default initializer, not Booter image staging

Full decompilation of FUN_1406B3FD0(longlong param_1) writes defaults including:

| Field offset | Observed value |
|---|---|
| +0x444 | 0x1000 |
| +0x43C | 0xFFD2 |
| +0x440 | 0xFFF2 |
| +0x448 | 0x40000 |
| +0x44C | 0x20 |
| +0x3F0 | 0 |
| +0x3F4, +0x3F8, +0x3FC, +0x400, +0x404 | 1,2,3,4,5 |
| +0x408, +0x410, +0x418, +0x438, +0x458 | 0xD,1,1,6,1 |
| +0x988 | 0 |
| +0x98C, +0x994, +0x99C, +0x9A4 | UINT64_MAX |

The body has no direct file read, image extraction, Booter signature or HS-loader call. **Important ABI caveat:** the earlier FUN_1402E7E60 decompiler prints FUN_1406B3FD0() without explicit argument, whereas FUN_1406B3FD0 expects a pointer and uses it for these field writes. This is an inconsistent decompiler rendering. Validate actual effective register input at callsite 0x1402E7E6B in read-only Ghidra Listing before definitively attributing those writes to the dispatch object.

A second ABI/signature mismatch is now visible: the outer constructor displays "iVar2 = FUN_141752AA0(puVar1,lVar5)" and checks "if (iVar2 == 0)", while the earlier complete decompilation of FUN_141752AA0 describes a void function ending with FUN_14056C510(param_1). Those inferred prototypes are inconsistent. Do not claim the wrapper checked or ignored builder error semantics definitively without examining the actual callsite instruction sequence and return register behavior. This also qualifies the prior description of FUN_141752AA0 as necessarily void.

## Next bounded read-only steps

1. Decompile the two still-unknown outer object setup/finalization functions as one bounded Ghidra report, with no memory scan:

    exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x140179580", "0x1401793c0"], "__name__": "__main__"})

2. Separately use existing Ghidra Listing/read-only disassembly around **0x1402E7E6B** and **0x14017B258** to establish true register argument and status-return behavior, avoiding speculative ABI claims.
3. Continue only from a verified indirect callsite of embedded-context+0x18 -> dispatch+0x170 (or equivalent object-propagated alias) to identify the source and fields of the HS load descriptor. No such callsite is yet proven. Normal production Booter image/header/signature origin, signature verification, physical GPU selector, execution, unlock, detach and flash remain open. All safety gates unchanged: CAN_DETACH=false; CAN_UNLOCK=false; CAN_FLASH=false. Immutable process and recovery audit untouched.

---

# 2026-11-05 — Falcon HS dispatch object linked bidirectionally to parent; parent initializer classified

## New complete passive decompilation

Report nvlddmkm-61742-booter-discovery-20261105-123324-990179.txt, SHA-256 06578432093815b551c1f8850c83627f461488961adb67f33d37568967899334 (3,501 bytes). Target nvlddmkm.sys Windows driver 617.42, MD5 3fb9afac9d0e394723e830aa14e60512, image base 0x140000000. Ghidra script: SCAN_STRINGS=SKIPPED_BY_CALLER, no database mutation, no hardware action, both decompilations clipped=False, STATUS=COMPLETE. These are static decompiler results, not runtime validation.

## Concrete low-level observations

1. FUN_1402E7E60(longlong param_1, undefined8 param_2), direct call from 0x14056C5CF in FUN_14056C510:
   - Stores *(undefined8 *)(param_1 + 0x4B0) = param_2.
   - Calls FUN_1406B3FD0(), which is NOT decompiled in this report. Because the call has no explicit decompiled parameters, do not assume it has no side effects or infer its purpose.
   - Returns 0 on the visible normal control path. There are no conditional error returns in this complete function.
   - Earlier FUN_14056C510 passes (local_18,param_1) to this helper. Therefore, in this caller, param_1 of the helper is the 0x9B0-byte dispatch object constructed by FUN_1417E99B0 and param_2 is the parent context.
   - The parent stores the dispatch object at *(parent+0x18) = local_18 following successful initialization. Thus parent+0x18 -> dispatch object and dispatch+0x4B0 -> parent are BOTH proved by source-level assignments on the successful path.

2. FUN_141752AA0(longlong param_1,longlong param_2), containing previous target 0x141752AF2:
   - Uses a 16-bit group/bit selector *(ushort *)(param_2+0x10), as in the previously recovered constructor's architecture/class-dependent table initializer.
   - Writes byte 1 to param_1+0x10; writes class/feature-conditioned bytes to +0x12 and +0x13; writes byte 0 to +0x14.
   - Calls FUN_14056C510(param_1), with decompiled return type void. It does not examine the integer returned from FUN_14056C510. That means this wrapper does not itself propagate a builder error, NOT that the builder cannot fail.
   - Sixteen existing incoming direct call references: 0x14174C74A, 0x14017B258, 0x1417E4F86, 0x1417E72F6, 0x141801A96, 0x141703D6C, 0x141774F31, 0x14179DD74, 0x14179E841, 0x1417A94C3, 0x1417DECB7, 0x1417D46F3, 0x1417D6061, 0x1417D9BEE, 0x1417EB408, 0x1417EDDD2. The varied locations establish widespread source-level use but are not physical-GPU runtime evidence.

## Evidence-to-execution status and next bounded action

Resolved: allocation and initialization of the 0x9B0-byte dispatch object, class-dependent assignment of slot +0x170 to FUN_140BF3880 or alternative FUN_140092D80, post-registration feature flag initialization that does not overwrite +0x170, parent-to-dispatch link at parent+0x18, and dispatch-to-parent back-pointer at dispatch+0x4B0. These are separate from the earlier Windows GSP ELF and UCODES bindata startup-argument chain.

Unresolved: actual call through dispatch slot +0x170; the image descriptor passed to the HS loader, production Booter image/header/signature provenance, cryptographic acceptance and physical RTX 4090/3080 runtime branch values. The group/bit selector comes from a descriptor at +0x10 and its exact meaning remains unrecovered. Do not assert it is the GPU PCI/device ID or a literal NVIDIA generation code.

Next read-only PyGhidra command, checking the parent initializer's caller and unexamined post-link callee without a full driver scan:

    exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x14017b258", "0x1406b3fd0"], "__name__": "__main__"})

If either is clipped, report STATUS=PARTIAL and narrow by observed terms. Continue to search for an actual loaded parent+0x18 / dispatch+0x170 indirect call using real Ghidra evidence; do not assume any callsite from generic class initializers. Do not run firmware/driver/UEFI modifications or touch hardware. Safety gates CAN_DETACH=false, CAN_UNLOCK=false, CAN_FLASH=false. Immutable process/recovery audit untouched.

---

# 2026-11-05 — HS dispatch object attachment and post-registration flags resolved

## Primary evidence and validation boundary

User-uploaded read-only PyGhidra report `nvlddmkm-61742-booter-discovery-20261105-122903-717830.txt`, SHA-256 `2a652a2aaa499c302ec138af0d395f039383a475dcaa297932adc7601295c8e9`, 4,709 bytes. Original Ghidra program: Windows NVIDIA `nvlddmkm.sys` 617.42, MD5 `3fb9afac9d0e394723e830aa14e60512`, base `0x140000000`. Target addresses `0x14056C577` and `0x1417E83E0` resolved respectively to containing function entries `FUN_14056C510` and `FUN_1417E83E0`. Both decompilations report `clipped=False`, overall `STATUS=COMPLETE`; `SCAN_STRINGS=SKIPPED_BY_CALLER`, `HARDWARE_ACTION=NONE`, `GHIDRA_MUTATION=NONE`. These status claims describe the user's script run, not independent physical-device verification.

## Parent object retains the constructed HS dispatch object

`FUN_14056C510(longlong param_1)` rejects null `param_1` with status `0x31`, then constructs the previously characterized `0x9B0`-byte dispatch object:

```c
local_18 = 0;
iVar1 = FUN_1417e99b0(&local_18,param_1,0);
if (iVar1 == 0) {
    if (local_18 == 0) { /* error logged but no immediate return in visible C */ }
    iVar1 = FUN_1402e7e60(local_18,param_1);
    if (iVar1 == 0) {
        *(longlong *)(param_1 + 0x18) = local_18;
        iVar1 = 0;
    }
}
```

The actual observed storage operation is **`*(longlong *)(param_1+0x18)=local_18`**, gated by success of the constructor and of `FUN_1402E7E60`. This proves how the pointer becomes reachable through its containing parent object. No lifetime-management, ownership in the C++ sense, GPU attachment, or runtime invocation is established solely by this assignment. `FUN_14056C510` has an unconditional caller at `0x141752AF2` and a DATA reference at `0x14140D838`.

**Remaining immediate downstream gate:** `FUN_1402E7E60` is invoked between construction and storage; its side effects (including whether it invokes, mutates, or exposes slot `+0x170`) remain UNKNOWN pending its own decompilation.

## Post-dispatch initializer does not overwrite loader pointer

`FUN_1417E83E0(longlong param_1,longlong param_2)` is the *complete* post-registration helper called by `FUN_1417E99B0` after `FUN_1417E8550`. It reads the same 16-bit group/bit selector `*(ushort *)(param_2+0x10)`; its visible writes are **single-byte feature/capability flags** at object offsets `+0x27A`, `+0x27D`, `+0x27E`, `+0x285`, `+0x28E`, `+0x291`, `+0x294`, `+0x296`, and `+0x297`. It does **not** write the function-pointer slot at `+0x170`. Thus this specific helper does not undo the conditional earlier assignment `+0x170 = FUN_140BF3880` (or alternative `FUN_140092D80`). This is not a global proof that no other code writes `+0x170`.

The constructor chain now has confirmed source-level order:
1. `FUN_14056C510` requests object construction using `FUN_1417E99B0(&local_18,param_1,0)`.
2. `FUN_1417E99B0` creates/initializes the 0x9B0-byte object, calls `FUN_1417E8550` (architecture-conditioned function table), and then `FUN_1417E83E0` (capability flags).
3. Back in `FUN_14056C510`, `FUN_1402E7E60(local_18,param_1)` must succeed before the object pointer is stored at parent `+0x18`.

## Next read-only Ghidra tasks

Highest immediate value: decompile `FUN_1402E7E60` (the post-construction pre-attachment initialization) and the enclosing function at callsite `0x141752AF2` (to identify the parent object and dispatch consumers). Neither is yet known to call HS firmware. Do not start by scanning entire Windows driver memory or modifying device state.

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1402e7e60", "0x141752af2"], "__name__": "__main__"})
```

If either decompilation is clipped, `STATUS=PARTIAL` and follow up with grounded `DECOMP_FOCUS_TERMS`. Subsequently locate **an actual indirect call through object slot +0x170**, its real argument mapping, and the signed descriptor producer. The Windows production Booter image bytes, architecture-selecting runtime values on GA102 and AD102, accepted signatures and successful GPU execution are unverified. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`. The immutable process/recovery audit is untouched.

---

# 2026-11-05 — HS-loader dispatch constructor and alternative slot implementation recovered

## Source reports and verification scope

Both are user-run **passive read-only Ghidra** reports for Windows 617.42 `nvlddmkm.sys`, MD5 `3fb9afac9d0e394723e830aa14e60512`, image base `0x140000000`; both explicitly report no Ghidra DB mutation and no GPU operation.

- `nvlddmkm-61742-booter-discovery-20261105-122357-308794.txt`, SHA-256 `5a4fb78dafa38dccbd7f25bad40a18d4d9b48d56d910b1b09ff82e3863565f32`. Requested code VA `0x1417E9BB8` resolves to **FUN_1417E99B0**; unclipped full body, `STATUS=COMPLETE`. Concurrent inspection of PE header data site `0x1400001E0` succeeded.
- `nvlddmkm-61742-booter-discovery-20261105-122400-588278.txt`, SHA-256 `9a38d9d8be5b180c683d673568343af8a7aa020106378c3bd5a9fd5d475c466e`. `FUN_1417E8550` focused terms (`FUN_140bf3880`, `param_1 + 0x170`, `param_2 + 0x10`) all captured, `excerpt_truncated=False`, `STATUS=COMPLETE` *for requested excerpts*; full Ghidra decompiled C is **22,282 characters**, and its entire body was not reported.

## Constructor: resolution of the dispatch-object owner

`FUN_1417E99B0(longlong *param_1,longlong param_2,uint param_3)` is the initializer/constructor for a **0x9B0-byte object**. It has a direct code caller from `0x14056C577`, an unconditional jump from `0x1417E83D0`, and several DATA references.

- If `(param_3 & 2) == 0`, calls `FUN_1400FF170(0x9B0)` to allocate the object. If `param_3 & 2` is set, requires a non-null existing `*param_1` and reuses it. It zeroes 0x9B0 bytes and sets flags at object +0x3C.
- When `param_3 & 1` is clear, resolves an auxiliary interface via `FUN_14010DC60(param_2,&DAT_140E8EC18)`, then calls `FUN_14010DF30`; other branches zero a field.
- Obtains the **architecture/hardware-class descriptor** `lVar6 = FUN_14010DC60(param_2,&DAT_140EA93F8)`. If null, uses a fallback `FUN_14010E030(param_2,0x74BC71)` then reattempts `FUN_14010DC60(...,&DAT_140EA93F8)`. It rejects a null result. Exact original type names for these interfaces are not recovered.
- Creates embedded interfaces at object+0x08 and object+0x40, initializes three separate vtable-like pointers (`PTR_DAT_140F27658`, `PTR_DAT_140F27670`, `PTR_DAT_140F27640`), then calls **`FUN_1417E8550(puVar4,lVar6)`** to populate the architecture-specific function pointers in the *same object*.
- On the visible success path, follows up with `FUN_140296090(puVar1)`, `FUN_141750C80(puVar2)`, **`FUN_1417E83E0(puVar4,lVar6)`**, then writes `*param_1=(longlong)puVar4` and returns zero. Failure cleans up or clears the existing object. `FUN_1417E83E0` must be analyzed before claiming it cannot replace or otherwise alter the +0x170 slot.

This is proof of **static dispatch-object construction and assignment sequencing**, not proof of any runtime invocation or selection on the user's RTX 4090/3080.

## Corrected architecture-dependent slot selection

The focused `FUN_1417E8550` report shows a 16-bit input at `param_2+0x10` is split with `uVar2 = uVar1 >> 5` and compared in group/bitmask tests. At label `LAB_1417E8E3E`, the function assigns:

```c
*(code **)(param_1 + 0x170) = FUN_140bf3880;
```

**Important additional evidence:** the same function can instead assign:

```c
*(code **)(param_1 + 0x170) = FUN_140092d80;
```

at line 441 in the focused decompilation, with intervening branches depending on `(uVar4 & 0x1f)-5` and group class. `FUN_140092D80` is merely an alternative function pointer at this stage; its semantics have **not** been examined, so do not call it a stub, denial or signature bypass. Neither possible value proves the slot was invoked, which hardware selected it, or that a production Booter descriptor originated from any particular file.

## PE CFG header-reference refinement

The header at VA `0x1400001E0`, contained in a defined `Headers` object rooted at `0x140000108`, points by a DATA reference to `0x141002A00`. The previous reports show a reference at `0x141002A80` (offset +0x80 inside that root) to `0x140E02C20`, and the latter contains a function-table entry for `FUN_140BF3880`. Together this strongly matches a PE32+ Load Configuration directory and its `GuardCFFunctionTable` field. This security metadata is independent of the architecture-conditioned constructor's functional slot +0x170. A specifically typed/decoded PE load-config structure remains necessary to label the chain *formally proven*.

## Next read-only tasks

1. **Inspect constructor's caller at code VA `0x14056C577`** to learn who holds the 0x9B0-byte object and where it is used. The current evidence has no actual dereference-and-invoke callsite for +0x170.
2. **Inspect the post-registration initializer `FUN_1417E83E0`**, invoked after `FUN_1417E8550`, to check whether it modifies or overwrites +0x170, binds selectors or creates descriptor associations.
3. Trace a verified consumer of the constructed object's +0x170 slot and the precise param_3 firmware-image descriptor passed to `FUN_140BF3880`. Distinguish static assignment, selected branch, invocation, signed image provenance, cryptographic acceptance and hardware state as different proof gates.

Existing Ghidra script suffices for the first two (no new dependencies or script modifications):

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x14056c577", "0x1417e83e0"], "__name__": "__main__"})
```

If either entire function is clipped, `STATUS=PARTIAL` accurately reports incomplete whole-function evidence; rerun with focused terms after reading its own metadata. The Windows production Booter image/header/signature, actual AD102/GA102 selector, driver/GPU signature acceptance and unlock remain **unproven**. `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`; immutable recovery audit untouched.

---

# 2026-11-05 — GA10x HS-loader dispatch slot +0x170 established; CFG metadata separated

## Evidence

User-run Ghidra report: nvlddmkm-61742-booter-discovery-20261105-121819-595158.txt, SHA-256 5db74dd090a510ccede289d565c532382ae6071bfa419a873e795df15324099e, 16,051 bytes. nvlddmkm.sys Windows 617.42 MD5 3fb9afac9d0e394723e830aa14e60512, image base 0x140000000. SCAN_STRINGS was skipped and the report is passive/read-only; HARDWARE_ACTION=NONE and GHIDRA_MUTATION=NONE. STATUS=PARTIAL because the 16,000-plus-character decompilation of FUN_1417E8550 was clipped at 14,000 C characters. The visible assignment is valid evidence; omitted function text is NOT reviewed.

## Function-pointer registration proved in the Windows driver

FUN_1417E8550(longlong param_1,longlong param_2), called directly at 0x1417E9BB8, reads a 16-bit selector from param_2+0x10, separates a group selector via >>5, tests masks for group classes including 0x20 and 0x40, and assigns multiple function-pointer slots in param_1.

At Ghidra label LAB_1417E8E3E the visible decompiled assignment is:

    *(code **)(param_1 + 0x170) = FUN_140bf3880;

Nearby slots include +0x168, +0x178, +0x180, +0x188. This is direct proof that the known GA10x Falcon HS binary load/execute function is installed as a callback/dispatch entry at +0x170 on the branch reaching this statement. It is NOT a proof of runtime invocation, AD102 versus GA102 runtime selector values, production Booter image bytes, signed descriptor origin, crypto acceptance, or any hardware unlock. Other candidate pointer targets vary by the class selector. The precise set of branches reaching +0x170 should be confirmed using a focused decompilation, because the surrounding function is clipped.

## Prior .rdata reference likely Control Flow Guard security metadata, not a Booter callback table

The same report shows Ghidra .rdata site 0x141002A80 belongs to a defined object rooted at 0x141002A00; it has an outbound DATA reference to 0x140E02C20 and its root has an incoming reference from PE-header-region address 0x1400001E0. Earlier report classified site 0x140E19A0C, inside the object at 0x140E02C20, as a DATA reference to FUN_140BF3880.

Difference 0x141002A80 - 0x141002A00 = 0x80: exactly the GuardCFFunctionTable member offset in Windows x64 IMAGE_LOAD_CONFIG_DIRECTORY64. Windows PE CFG metadata has a load configuration record whose GuardCFFunctionTable references a sorted RVA list (GFIDS). The observed chain is therefore strongly consistent with PE load config -> CFG function table -> valid indirect target entry for FUN_140BF3880. This is **not evidence of an actual hardware callback or execution path**. This revises the earlier interpretation that the .rdata object might be an NVIDIA-specific dispatch table. Full binary-specific confirmation would inspect the defined type and header contents at 0x141002A00; report the classification as strongly inferred, not confirmed by a fresh PE structure dump. Microsoft primary references:
https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory64
https://learn.microsoft.com/en-us/windows/win32/secbp/pe-metadata
https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

The .pdata reference at 0x141469320 remains probably exception/unwind metadata, not a call. Only the PAGE-region assignment in FUN_1417E8550 is source-level proof of dispatch registration.

## Next discriminating, read-only checks

First decompile the known direct caller to identify who owns param_1 dispatch state, and inspect the PE header source of the suspected Load Config table:

    exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1417e9bb8"], "TRACE_DATA_SITES": ["0x1400001e0"], "__name__": "__main__"})

Then capture bounded focused evidence from the selector function (no full scan):

    exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1417e8550"], "DECOMP_FOCUS_TERMS": ["FUN_140bf3880", "param_1 + 0x170", "param_2 + 0x10"], "__name__": "__main__"})

Next identify callsites that invoke slot +0x170 and recover the provider of the HS loader's param_3 signed descriptor using only existing, read-only Ghidra references. NEVER infer signature verification or Windows Booter provenance from assignment alone. No device action, driver/EFI modification, or active unlock. CAN_DETACH=false; CAN_UNLOCK=false; CAN_FLASH=false. Immutable recovery audit unchanged.

---

# 2026-11-05 — GA10x Falcon HS loader existing DATA XREF provenance: four sites classified, no descriptor source yet

## Primary artifact and limits

User-run read-only Ghidra report: nvlddmkm-61742-booter-discovery-20261105-121152-127076.txt, SHA-256 3374771262e7f70fa23e27d1d1db01ad66f93b47547fd39aa6bc91c49550a993, 2,132 bytes. Target program nvlddmkm.sys 617.42, MD5 3fb9afac9d0e394723e830aa14e60512, image base 0x140000000. Explicit mode: SCAN_STRINGS=False and TRACE_DATA_SITES for four pre-existing references to FUN_140BF3880. STATUS=COMPLETE, ELAPSED_SECONDS=0.025; the script did NOT decompile any function, disassemble bytes, mutate the Ghidra database, or perform hardware operations. STATUS=COMPLETE applies to bounded existing-reference enumeration, not proof of image-descriptor provenance.

## Exactly what the existing Ghidra reference map shows

| Source site | Region and Ghidra defined-data state | Outgoing reference | Incoming reference to source/root | Meaning and limitation |
|---|---|---|---|---|
| 0x141469320 | .pdata, defined=True, root 0x141469320 | DATA -> FUN_140BF3880(0x140BF3880) | None | Likely PE unwind/exception function-table metadata; not evidence of a runtime caller. Verify section semantics if using beyond screening. |
| 0x140E19A0C | .rdata, defined=True, containing root 0x140E02C20 | DATA -> FUN_140BF3880 | No inbound to exact site; one inbound to the root, DATA from 0x141002A80 with no containing function | A large existing read-only data object references the loader. Its table/object type and source-owner chain remain unknown. Do not assume a callable vtable or active descriptor selection. |
| 0x1417E8E3E | PAGE, defined=False at this address, root itself | DATA -> FUN_140BF3880 | Two CONDITIONAL_JUMP refs from 0x1417E8EDA and 0x1417E8EEC; both belong to FUN_1417E8550 | The strongest **code-context** lead. Conditional jumps target this address *inside an existing function*. They do not themselves show that the loader is called or that the incoming branches dispatch to it. |
| 0x1417E8E45 | PAGE, defined=False | DATA -> FUN_140BF3880 | None | Adjacent outbound reference within the same PAGE region. No caller, descriptor producer or semantic role established. |

No incoming-reference lists were capped (all capped=False), and no site was unavailable. The script inspected *outgoing Ghidra references from sites*; outbound kind=DATA must not be silently reclassified as CALL. The previously identified FUN_140BF3880 is capable of Falcon high-security binary load/execute, but it receives an unresolved param_3 firmware image/descriptor. The reference map is NOT proof of the origin or production validity of that descriptor.

## Next bounded read-only evidence

Priority: decompile **FUN_1417E8550** (contains the two conditional branches into the PAGE region referencing FUN_140BF3880) and inspect the candidate root-owner site 0x141002A80 for its current Ghidra outbound references. These are independent, bounded reads and can run together with the script's already implemented modes:

~~~python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1417e8550"], "TRACE_DATA_SITES": ["0x141002a80"], "__name__": "__main__"})
~~~

If FUN_1417E8550 C output is clipped, STATUS=PARTIAL is correct; inspect observed code and repeat with narrower focus terms. No full driver memory scan needed. If 0x141002A80 is an initialized data pointer, its outgoing ref may identify the read-only data object's owner; otherwise preserve UNKNOWN. The source-level producer of the pre-GSP Booter image/header/signature remains **unproven**. Keep Linux 615.78.08 Bo(o)ter bindata archive hypotheses separate from direct Windows 617.42 evidence; the GSP ELF signature sections and host UCODES -> GSP bindataArgs are separate previously resolved paths. All hardware/recovery gates remain closed: CAN_DETACH=false; CAN_UNLOCK=false; CAN_FLASH=false. Immutable process/recovery audit untouched.

---

# 2026-11-05 — Windows GSP suspend/resume metadata producer matched to NVIDIA Linux 615.78.08 source

## Primary evidence and definitive classification

User-run read-only Ghidra file nvlddmkm-61742-booter-discovery-20261105-120132-350753.txt, 4,138 bytes, SHA-256 **6d3ad05bc366ea439a494234721bdfa86126ede4b329cc8010f0f84d9ee618b9**. Program nvlddmkm.sys 617.42, MD5 3fb9afac9d0e394723e830aa14e60512, base 0x140000000. Supplied 0x14091F922 resolved to existing FUN_14091F870; decompilation complete clipped=False, STATUS=COMPLETE; HARDWARE_ACTION=NONE, GHIDRA_MUTATION=NONE.

Earlier this function was tentatively nominated as an *additional GSP/production Booter image-staging lead* because it directly calls the common mapping helper FUN_1401AFD60. **That interpretation is now corrected:** FUN_14091F870 constructs a **GspFwSRMeta suspend/resume metadata structure** and the corresponding saved-FB-region radix-3 mapping. It does not select/load a production Booter image.

Strong independent comparison: NVIDIA's *pinned* Linux 615.78.08 open kernel source **kgspPrepareSuspendResumeData_TU102** in https://github.com/NVIDIA/open-gpu-kernel-modules/blob/615.78.08/src/nvidia/src/kernel/gpu/gsp/arch/turing/kernel_gsp_tu102.c. This source contains the same metadata init, region-size arithmetic, radix-3 creation, 256-byte metadata allocation/copy, and cleanup. Cross-check magic/structure against the published GspFwSRMeta in https://linux.googlesource.com/linux/kernel/git/torvalds/linux/+/976d5e0ddac885b0219252f004f6c561c344df9d/drivers/gpu/drm/nouveau/nvkm/subdev/gsp/rm/r535/nvrm/gsp.h and the current NVIDIA source file reference. Note that Linux source 615.78.08 is **not** Windows 617.42, so naming is a strong behavioral correspondence, not recovered Windows symbols.

## Exact Windows ↔ reference correspondence

| Windows 617.42 Ghidra operation | Meaning supported by pinned source |
|---|---|
| Clears 0x100 bytes at &local_128 | zero-initialize 256-byte GspFwSRMeta |
| local_128 = 0x8A3BB9E6C6C39D93 | GSP_FW_SR_META_MAGIC |
| local_120 = 2 | GSP_FW_SR_META_REVISION |
| local_110 = ((param_2+0xA48) - (param_2+0xA30) - (param_2+0xA28) + (param_2+0xA40)) | sizeOfSuspendResumeData from FRTS end minus non-WPR heap end, matching NVIDIA source expression; individual Windows field names are not independently recovered |
| local_88 = (byte at param_2+0xA50 != 0) | matches metadata flags concept at offset +0xA0 / clock-boost boolean; confirm constants/field mapping before treating as a formally decoded structure |
| FUN_1401AFD60(..., param_2+0xA80, 0) | creates the suspend/resume radix-3 mapping; common allocator, NOT a production Booter asset |
| local_118 = FUN_1401BB0B0(*(param_2+0xA80),1,0) | writes GPU-addressable mapping-root address into sysmemAddrOfSuspendResumeData at metadata byte offset 0x10 |
| FUN_1401B9020(param_2+0xA78, param_1, 0x100) | creates 256-byte metadata resource, observed type-like code 0x15 |
| FUN_1400DF7C0(local_138,0x100,&local_128) | copies entire metadata object into allocated descriptor |
| FUN_1401BD4C0(...metadata mapping...) | map/unmap or synchronization; exact helper naming not independently verified |

The pinned NVIDIA *boot mode* source also distinguishes normal boot arguments (WPR metadata) from suspend/resume arguments (SR metadata), in its _kgspGetBooterLoadArgs routine. Therefore **this data structure is intended for Booter consumption on the resume path**, which gives it a legitimate place in the firmware sequence; this is not evidence that FUN_14091F870 itself loads any Booter code or authenticates a production Booter signature.

## Effect on active evidence-to-execution plan

- Close prior hypothesis "**FUN_14091F870's third FUN_1401AFD60 call may stage a Booter image**" as contradicted by direct static decompilation plus matching 615.78.08 source.
- Mark **suspend/resume SR metadata allocation/staging** as statically established for this driver. The user's actual resume behavior/hardware acceptance is untested.
- Do **not** attribute the host's UCODES bindataArgs (GSP_ARGUMENTS_CACHED at +0x98/+0xA0) to this path. The two structures are separate.
- Normal-boot Booter image/header/signature bytes, originating archive/source, signed descriptor producer, selector for AD102 vs GA102, and hardware authentication are still UNPROVEN. The pinned Linux production Booter comparison and Windows GSP ELF signatures remain distinct.
- Highest remaining static priority returns to the **HS Falcon loader** FUN_140BF3880. Existing incoming references to this function entry are DATA at 0x141469320, 0x140E19A0C, 0x1417E8E3E and 0x1417E8E45. Inspect their existing Ghidra containing data objects and inbound reference owners to identify the dispatch callback or image-descriptor constructor (read-only only). Do not attempt to decompile the DATA addresses as code, run the loader, alter GPU firmware/registry, or repeat the full 114 MB scan. No existing exact caller for its firmware descriptor is proven.
- **Safety gates remain CAN_DETACH=false, CAN_UNLOCK=false, CAN_FLASH=false.** Immutable recovery audit untouched.

---

# 2026-11-05 — Second Windows GSP boot-argument caller classified; no production Booter source identified

## Verified user Ghidra evidence

Source report: nvlddmkm-61742-booter-discovery-20261105-115716-144155.txt; SHA-256 307f78f05283d10445cabe8091bc343a6770c77e5407c30e25423b7bae273d9c; nvlddmkm.sys 617.42 MD5 3fb9afac9d0e394723e830aa14e60512, base 0x140000000. Requested address 0x140124B86 belongs to fully decompiled FUN_140124A90. Report: STATUS=COMPLETE, clipped=False, HARDWARE_ACTION=NONE, GHIDRA_MUTATION=NONE. Existing direct callers of FUN_140124A90 at 0x140125089 and 0x140125225, plus three DATA references.

## New static classification

FUN_140124A90(param_1,param_2,param_3) is a GSP-related host initialization orchestration routine, not an identified pre-GSP production Booter byte selector:

1. Early exits with success if the int at param_1+0xD8C is 1; subsequent work is conditional. Reads a byte at param_1+0xEB9 to choose alternate flows.
2. In the nonzero +0xEB9 path, obtains GSP context lVar2 from param_1+0x2238 and another context lVar3 from param_1+0x21F8. Assigns the incoming param_2 and param_3 to locals local_58 and local_54, and calls FUN_1401B2C10(param_1,lVar2,&local_58). This is the already cross-verified NVIDIA GSP_ARGUMENTS_CACHED construction routine containing the mapped UCODES bindataArgs radix3/size.
3. Performs several guarded indirect calls with lVar2 and uVar7, where uVar7 is selected as one of {1,2,3} based on state flags (for example +0x584C, +0x991, +0x9B1, +0x9AD). The *functions behind the indirect calls and interpretation of uVar7 remain unresolved*. Includes FUN_140303D90(param_1,*(...+0x23B8)) on one branch and status/error propagation.
4. Writes progress-mask bits 0x10000, 0x20000, 0x40000, 0x80000 into the uint at param_1+0x540C at successive visible sites. These are observable state flags, not verification that the corresponding firmware stages actually finished on the user's GPUs.
5. Does not directly load an image file, parse ELF/UCODES records, choose a production Booter signature, or prove pre-GSP Falcon execution within this fully visible decompiled body. Indirect callees could still perform relevant work; thus absence of direct Booter logic is a bounded source-level conclusion, not global exclusion.

**Resolution:** the independent caller of FUN_1401B2C10 is now classified. UCODES host-side staging-to-GSP boot-argument handoff is unchanged and already established; do not re-run the general UCODES consumer search. The pre-GSP signed Booter image/header/signature bytes, AD102/GA102 runtime selection and signature acceptance remain OPEN.

## Next discriminating non-mutating Ghidra target

Prior independent reports prove a third direct caller of the generic image mapping/staging function FUN_1401AFD60 at code VA **0x14091F922**, separate from its two callsites within the GSP ELF section-extraction function FUN_1401AB740. Earlier CSV XREF review also associated string RmBootGspRmWithBoostClocks with function **FUN_14091F180** (XREF from 0x14091F5A3), plausibly the containing function at 0x14091F922. It is therefore a focused lead for mapping an *additional* host-side image/staging path. **Do not infer that this path is the production Booter without examining the function.**

Read-only Python 3 Ghidra command, no whole memory scan:

~~~python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x14091f922"], "__name__": "__main__"})
~~~

If it is clipped, report PARTIAL and use narrower DECOMP_FOCUS_TERMS grounded in the new output. Alternatively, continue tracing the known DATA XREFs to high-security Falcon loader FUN_140BF3880 to find who builds its param_3 signed-image descriptor. Do not chase logging helpers or assume stock Windows behavior equals pinned Linux 615.78.08. No driver/firmware/UEFI modification, GPU action or recovery gate change. CAN_DETACH=false; CAN_UNLOCK=false; CAN_FLASH=false.

---

# 2026-11-05 — Windows UCODES bindata handoff proven in GSP_ARGUMENTS_CACHED

## Primary report and independent reference

- User-run read-only Ghidra report: nvlddmkm-61742-booter-discovery-20261105-115119-418340.txt. SHA-256: 9bfdda59024cb64997bf384806c8a2f6d94fca85189cb2184ddc346233bfd7f1. Program nvlddmkm.sys 617.42, MD5 3fb9afac9d0e394723e830aa14e60512, base 0x140000000. Function FUN_1401B2C10 fully decompiled (clipped=False), STATUS=COMPLETE; no hardware action, no Ghidra DB modification.
- NVIDIA pinned Linux 615.78.08 public declaration, gsp_init_args.h: https://github.com/NVIDIA/open-gpu-kernel-modules/blob/615.78.08/src/nvidia/inc/kernel/gpu/gsp/gsp_init_args.h
- NVIDIA pinned Linux 615.78.08 implementation, kgspPopulateGspRmInitArgs_IMPL in kernel_gsp.c: https://github.com/NVIDIA/open-gpu-kernel-modules/blob/615.78.08/src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c#L5675-L5765
- Distinct pinned Linux 615.78.08 GSP boot-image preparation, kgspPrepareBootBinaryImage_IMPL, loads GSP boot-image/descriptor via kgspGetGspRmBootUcodeStorage_HAL, same file beginning at L5767. The equivalent *Windows* source of the pre-GSP boot image still has NOT been traced.

## Windows decompilation matched to the published ABI, field-for-field

FUN_1401B2C10(param_1,param_2,param_3) loads the destination buffer from *(param_2+0xAC0), clears 0xB8 bytes, writes the magic 0x20505347 ("GSP " in little-endian ASCII), and writes the U16 structure length 0xB8 at byte offset +0x04.

Independent standard C ABI field-layout computation against pinned NVIDIA GSP_ARGUMENTS_CACHED declaration gives:
| Field | Byte offset | Bytes | Windows matching behavior |
|---|---:|---:|---|
| magic | 0x00 | 4 | 0x20505347 |
| size | 0x04 | 2 | 0xB8 |
| flags | 0x08 | 8 | stack-placement / transition flags |
| messageQueueInitArguments | 0x10 | 0x40 | copies fields from *(param_2+0x9A8) |
| srInitArguments | 0x50 | 0x10 | default/optional recovery-related inputs |
| gpuInstance | 0x64 | 4 | copies *(param_1+0xD34) |
| profilerArgs | 0x68 | 0x10 | optional mapped descriptor/size |
| sysmemHeapArgs | 0x78 | 0x10 | optional mapped descriptor/size |
| rmStateMonitorBufferArgs | 0x88 | 0x10 | optional mapped descriptor/size |
| **bindataArgs.radix3** | **0x98** | 8 | **address returned by FUN_1401BB0B0(staged UCODES resource,1,0)** |
| **bindataArgs.size** | **0xA0** | 8 | **size from param_2+0x69F78** |
| vbiosOverrideArgs | 0xA8 | 0x10 | optional mapped descriptor/size |
| **total size** | | **0xB8** | 0xB8 |

In Windows, puVar1 is uint32_t*; thus (puVar1+0x26) is byte offset +0x98 and (puVar1+0x28) is +0xA0. The exact source:
~~~c
if (*(longlong *)(param_2 + 0x69f70) != 0) {
    uVar7 = FUN_1401bb0b0(*(longlong *)(param_2 + 0x69f70),1,0);
    *(undefined8 *)(puVar1 + 0x26) = uVar7;
    *(undefined8 *)(puVar1 + 0x28) = *(undefined8 *)(param_2 + 0x69f78);
}
~~~

The cited Linux 615.78.08 implementation has equivalent semantics: if pKernelGsp->pExternalBindata is non-null, it assigns memdescGetPhysAddr(...,AT_GPU,0) to pGspArgs->bindataArgs.radix3 and externalBindataSize to bindataArgs.size. This is an **exceptionally strong cross-version structural correspondence**. The Windows driver class/function name remains a static semantic match, not a directly recovered original C symbol. Do not call the radix3 field a raw UCODES data pointer: it is an address to the mapping root/descriptor used by GSP.

## Confirmed Windows firmware-data path and its limits

Previously shown static chain: external ucodes_ga10x.bin selected in FUN_1400F35F0, opened/read by FUN_1400F3350, carried through composite load context in FUN_1400F1310 → FUN_1401B0E00 → FUN_1401AB740, staged with FUN_1401AFD60 at resource state param_2+0x69F70/0x69F78, and **now conclusively referenced in FUN_1401B2C10 as GSP_ARGUMENTS_CACHED.bindataArgs**. That resolves the previously uncertain downstream *host-side* use: the external UCODES archive is handed to GSP-RM through its initialization arguments. It does not identify which firmware routines running on GSP parse the individual bindata entries; the host assembly does not parse those records here.

The Windows decompilation also has incoming direct-call XREFs at 0x140124B86 and 0x1401B15B3; the second lies inside the previously studied FUN_1401B0E00 GSP boot-initialization path. The GSP init arguments clearly contain a UCODES mapping, but the report does NOT prove a particular GSP runtime consumed it.

**Key architecture boundary:** Linux 615.78.08 uses a separately obtained GSP boot image/descriptor in kgspPrepareBootBinaryImage_IMPL *before* GSP-RM starts. Booter production image/signature bytes are not identified by this bindata handoff. Do not conflate GSP ELF 4,096-byte .fwsignature_* records, GSP-RM boot image/descriptor, Booter load image/signature, and external UCODES/bindata. Linux source semantics are useful corroboration, not exact proof of Windows Booter provenance.

## Updated next evidence and execution gates

1. Archive this host-side UCODES consumer as **resolved static handoff**; stop searching FUN_1401B0E00 for raw 0x69F70 references and stop classifying FUN_1401B2C10 as a parser.
2. **Trace the pre-GSP Falcon/Booter load path** as a *separate* investigation. Earlier FUN_140BF3880 ("flcnLoadAndExecuteHsBinaryViaDma_GA10X") loads/executed HS image data from descriptor param_3, but its descriptor producer, exact signed image bytes and relationship to GSP boot remain unknown. Review existing data-XREF dispatch tables at function entry and call targets without hardware invocation. The alternative caller of GSP args builder at code VA 0x140124B86 is another bounded route to classify GSP init order; do not assume it yields Booter image bytes.
3. Suggested next read-only Ghidra Python 3 command to classify the *other* boot-arguments caller and its context:
~~~python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x140124b86"], "__name__": "__main__"})
~~~
4. If that caller does not illuminate the pre-GSP loader, shift to identifying FUN_140BF3880's production HS descriptor producer by following only its already reported DATA references; do not repeat the memory-wide scan or run any Falcon code.
5. Runtime-selected architecture and external UCODES *consumption by the actual GPU*, host production Booter image/header/signature origin, signature authentication, detachment/recovery readiness, unlock and flash remain UNPROVEN. CAN_DETACH=false; CAN_UNLOCK=false; CAN_FLASH=false. Immutable recovery audit untouched.

---

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
