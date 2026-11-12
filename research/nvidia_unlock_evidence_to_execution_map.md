# NVIDIA GPU unlock — Active execution map

**Current state: 2026-11-12.** This document is the single execution plan for the RTX 4090 and RTX 3080 12 GB on the MSI B850 system. Edit its status and tasks **in place**. Do not add dated updates or duplicate reverse-engineering notes. The [investigation record](nvidia-tensor-core-unlock-investigation.md) is the only maintained source for original NVIDIA driver/firmware analysis and marked dead ends. The moved `research/DUAL_GPU_61742_REMEDIATION_PLAN.md` is retained for reference, not maintained as another plan.

## 1. Objective and decision

Develop a **one-card-at-a-time, preboot** process that can change the relevant NVIDIA Tensor Core FP32-accumulation issue-rate permissions, restore control to the **unmodified Windows NVIDIA driver 617.42**, and prove performance and numerical correctness on each GPU. The second target must remain installed and unchanged during the first target's operation. A same-boot **sequential** two-card process is a later, separate milestone. Parallel execution, CUDA peer-to-peer unlocking, permanent flash changes, unattended EFI persistence, and claims that Tensor Cores are currently disabled are not part of this goal.

**Current decision:** Passive identification and ordered two-card preparation **PASS**. Active NVIDIA release, signed firmware loading, selector writes, FLR, Windows-after-unlock proof, and cold recovery remain **BLOCKED**. Source and host tests are not permission to run a physical transaction.

**Terms:** UEFI means Unified Extensible Firmware Interface. GOP means Graphics Output Protocol. FWSEC is the protected firmware security stage. SEC2 is NVIDIA's security processor. DMA means direct memory access. FLR means PCIe Function Level Reset. ABI means the machine call contract. HMMA means the Tensor Core matrix-multiply instructions. See the investigation record for the original-driver function and firmware details.

**All four gates are false:**

`CAN_DETACH=false`  
`CAN_UNLOCK=false`  
`CAN_FLASH=false`  
`RECOVERY_VERIFIED=false`

No source, test, documentation or diagnostic result sets these to true. Any later active hardware test requires a separate reviewed procedure, recovery evidence, and explicit owner authorization.

## 2. Pinned target and current hardware position

| Required identity | Target 1 | Target 2 |
|---|---|---|
| GPU | RTX 4090 AD102, `sm_89` | RTX 3080 12 GB GA102, `sm_86` |
| PCI location, last observed | `0000:01:00.0` | `0000:04:00.0` |
| Vendor/device | `10de:2684` | `10de:220a` |
| Subsystem | ASUS `1043:88e6` | ZOTAC `19da:b612` |
| GOP firmware family | `nvgop-ad1xx` | `nvgop-ga1xx` |

Host: MSI B850 Gaming Plus WiFi; Ryzen 7 9800X3D; AMD integrated graphics; two installed NVIDIA cards; Windows NVIDIA driver **617.42**. The preserved original driver has MD5 `3fb9afac9d0e394723e830aa14e60512`. Reported GSP firmware is **615.78.05**.

**Last recorded cabling (changeable, not a hardware restriction):** All three displays were attached to RTX 3080, so that recorded preboot console depends on NVIDIA and its verdict was **CONFLICT**. The owner may later move displays to the AMD integrated graphics output to prepare a **headless selected-NVIDIA** path. Earlier AMD-only cabling showed AMD `ConOut` and `ErrOut`, both NVIDIA PCI drivers bound, and no NVIDIA GOPs, so the full topology verdict remained **INCOMPLETE**. Any changed cabling needs a fresh current-boot passive check before later authorized active use. An AMD console observed before a NVIDIA vendor Stop is **not** proof it survives Stop.

The archived `AD102.rom` and `GA102.rom` are accepted structural analysis inputs, not OEM-authenticated original-installed firmware. Recheck live card identity, ancestor bridges, current driver/GOP ownership and all pinned inputs at each separately authorized active attempt. Do not reuse cross-boot UEFI handles or assume unchanged cable routing.

## 3. Existing source work that must not be repeated

| Current capability | State and limit |
|---|---|
| Passive PCI/device-path/GOP inventory, full peer snapshots, ordered selection | **PASS — PHYSICAL PASSIVE and HOST/SYNTHETIC EFI.** Both exact GPUs and distinct PCI roots identified. No device mutation proved. |
| Phase 0 selected identity (`0020/0021`) and Phase 1 ordered preparation (`RUN0001.TXT`) | **PASS — PHYSICAL PASSIVE/PREPARATION.** `ACTIVE_EXECUTION=REFUSED` before `GuInit` with `MUTATION_AUTHORIZED=0`. Do not repeat merely to reconfirm it. |
| Per-target private resource backing | **PASS — SOURCE/HOST/SYNTHETIC EFI.** Selected platform, MSI release plan/graphs, firmware asset table, selector phase and peer identity have distinct backing and one-use claims. This does not allow second-card rebinding. |
| Failure and Windows handover containment | **PASS — SOURCE/HOST/SYNTHETIC EFI.** DMA-map uncertainty retains state; selected owner changes and early/late AMD or peer checks deny handover. No live GPU recovery established. |
| Independent AMD console admission and headless source route | **PASS — SOURCE/HOST checks, ACTIVE BLOCKED.** Every survivor GOP must resolve to AMD; both `ConOut` and `ErrOut` and the live TextOut owner graph must qualify. With no selected GOP, `GuMsiRelease()` skips selected display stages 1/2 but **still calls NVIDIA PCI driver `Stop` at stage 3**. Original zero-child Stop can write BAR0 and poll without a visible local timeout. No live Stop/recovery proof. |
| Original Windows GSP/UCODES files and index | **PASS — ORIGINAL FILES/STATIC.** File SHA pins and NVUCODES indexed external boundaries verified. **Booter record selection and exact signed-loader use are OPEN**. |
| Original Windows Falcon callback/loader analysis | **PARTIAL — STATIC.** Conditional `+0x170` loader registration and generic staging are established. Four `FUN_140BF1390 → FUN_1406A2F10` original call windows now **CLOSED** for immediate R9 buffer and fifth-stack byte-count setup. This controller word-transfer helper does not create signed records. Its RDI base contents, per-GPU signed IMAGE/HEADER/SIG/PATCH mapping, same-instance loader invocation and third input remain **OPEN**. |
| Host and Windows EFI builds | **PREVIOUS CI PASS.** Example universal jobs [43144007489](https://github.com/akashskypatel/universal-gpu-unlock/actions/runs/43144007489); Windows investigation checks [43258988642](https://github.com/akashskypatel/Windows-GPU-UNLOCK/actions/runs/43258988642). No new build/test was run for this documentation consolidation. |
| Active dual-NVIDIA process | **BLOCKED.** Original legacy singleton path and selected one-shot guards must not be reset or bypassed. The true second-card active dispatcher/physical rebind is not implemented. |
| Real firmware and hardware unlock | **NOT TESTED.** No safe vendor Stop, firmware acceptance, permission write, FLR or stock-Windows-after-unlock proof. |

The implementation host remains [`akashskypatel/universal-gpu-unlock`](https://github.com/akashskypatel/universal-gpu-unlock). This Windows repository is the authority for the original driver evidence and the execution decision. Implement only a source-backed correction; do not copy unrelated upstream code or change known-safe guards to obtain passing tests.

## 4. Ordered unlock sequence and stop points

A later operator request must pass **each prerequisite** before execution advances. Steps 01–03 are safe preparation and read-only evidence collection. Later steps are **not authorized today**.

| Step | Action / required observation | State |
|---|---|---|
| 01 | Verify both full PCI identities, parent bridges, current boot handles and physical ROM/input pins. Reject duplicate or changed target/peer. | **PARTIAL.** Exact PCI and bridge identity **PASS (PASSIVE)**; original-installed ROM provenance and full cold hardware inputs remain **OPEN**. Refresh before any future test. |
| 02 | Select **one** target in explicit order. Re-read both target and non-target PCI configuration, driver/GOP path and owner graph. Do not select a default first adapter. | **PASS — PASSIVE/HOST.** |
| 03 | For the intended boot configuration, verify an **independent AMD-owned preboot console** for both output and error, an AMD survivor GOP with live TextOut owner graph, and no selected-NVIDIA console dependency. The owner may rearrange displays to AMD ports; then collect a new passive read-only observation for that boot. | **CONFLICT in last recorded NVIDIA cabling; RECONFIGURABLE.** Prior AMD-only passive evidence does not prove post-Stop safety. |
| 04 | Qualify the **actual** release path. For a headless selected GPU, require all surviving GOPs and `ConOut`/`ErrOut` on AMD. Original AD102 and GA102 zero-child NVIDIA driver `Stop` destructors can still write BAR0 and poll without a visible local timeout. Independently verify a safe way to bound or avoid this callback and a cold-power recovery procedure before any physical release. | **BLOCKED — VENDOR STOP AND RECOVERY.** Static risk established; runtime response and recovery unproven. |
| 05 | Only after independent signed-loader, Stop and recovery evidence plus separate owner approval, release one NVIDIA PCI controller. Preserve the AMD console and NVIDIA peer and recheck both after hardware state changes. `OpenProtocol(EXCLUSIVE)` is **not** a Stop bypass: UEFI may invoke the bound driver's Stop. | **BLOCKED — NOT TESTED.** |
| 06 | Prove the selected card has exclusive PCI access while the peer is unchanged. Admit exact chip/board cold-state, ROM, register and protection prerequisites; refuse unknowns. | **BLOCKED — PHYSICAL.** |
| 07 | Obtain authentic, exact Windows 617.42 AD102/GA102 **signed Booter IMAGE, HEADER, SIG, PATCH** record identity and original producer. Verify selected asset bytes and their host ownership. | **BLOCKED — ORIGINAL DRIVER RE.** Original file/index geometry is complete; record map is not. |
| 08 | Prove the actual same constructed Falcon object calls installed nested method `+0x170 = FUN_140BF3880`. Trace the **populated third host argument** and signature-selection metadata from their original producers through this call. | **BLOCKED — ORIGINAL DRIVER RE.** Generic `FUN_140645BB0` transfer does not meet this gate. |
| 09 | Admit independently checked firmware and profile for **each** GPU, including signed-loader compatibility and correct architecture selection. Reject a borrowed Linux 610/615 reference image and an unknown board signature. | **BLOCKED — AUTHENTIC ASSETS / ABI.** |
| 10 | Execute the architecture-correct **FWSEC / SEC2 secure-load** sequence and prove acceptance with explicit status checks. Do not equate a firmware copy with a valid secure load. | **BLOCKED — HARDWARE.** |
| 11 | Apply only the proven per-card issue-rate permission/selector sequence; check each expected register and permission readback. No unspecified MMIO writes or use of unknown firmware masks. | **BLOCKED — HARDWARE.** |
| 12 | Quiesce the secure engines, contain all DMA and retained mappings, perform bounded PCIe FLR when qualified, and verify the selected GPU and untouched peer without stale handles. | **BLOCKED — HARDWARE.** |
| 13 | Finish the original shared-console owner graph. Verify independent AMD and peer survival **after** release, close/restore results, and no retained fault. Fail instead of handing off if any result is uncertain. | **BLOCKED — PHYSICAL.** |
| 14 | Use the pinned Windows EFI system partition to load stock `bootmgfw.efi` without rewriting BootOrder, firmware variables or Microsoft boot files. Verify stock driver 617.42 enumerates both GPUs. A logged `StartImage` request is not completed proof. | **BLOCKED — ACTIVE HANDOFF.** |
| 15 | Measure matched before/after Tensor Core HMMA FP32-accumulation issue rate, numerical results, per-device clock/power/load and real workloads. Independently test each GPU and compare against a clean cold-boot control. | **BLOCKED — POST-UNLOCK TEST.** |
| 16 | Prove full-power recovery and separately complete one-card physical tests for **both** cards. Only then design/validate a fresh, sequential same-boot second-card bind with a new isolated transaction. | **BLOCKED — RECOVERY AND SECOND CARD.** |

**Dependency rule:** Step 07/08 research may proceed **in parallel** with read-only Step 03/04 source work. Step 10 is not permitted just because Step 09 passes; Steps 04–06 and a separately approved recovery path are also prerequisites. No gate can be inferred from one successful physical boot, a Windows CI check, or static decompilation.

## 5. Required evidence to lift blockers

| Blocker | Exact proof still needed | Acceptance decision |
|---|---|---|
| Secure-loader source/record | Original production Windows AD102 and GA102 IMAGE/HEADER/SIG/PATCH labels or equivalent original producer, byte offsets/lengths/hashes and selected pointer flow. Existing register-word transport `FUN_1406A2F10` does **not** create records; its fourth caller buffer and fifth byte count provide one bounded source lead. | **OPEN.** Never infer Windows slot numbers from Linux bindata values or from a register transfer. |
| Secure-loader invocation | Same-instance `outer+0x108` publication → nested method `+0x170` read → actual guarded call resolving to `FUN_140BF3880`; full third-input data flow and selected original signature. | **OPEN.** DATA references, same offsets and a generic transfer are not enough. |
| Windows secure acceptance | Exact per-card hardware/stock-loader response to an authentic signed firmware set; invalid assets rejected. | **OPEN; physical proof not authorized.** |
| Vendor release and console ownership | AMD-only cabling can clear the changeable console ownership check, but original NVIDIA zero-child `Stop` may write BAR0 `0x6104E0` and poll `0x610630` without a visible local timeout. The original binary-backed AD102 and GA102 Stop chains and a 22-case host fault model were previously examined. A timeout in the caller cannot interrupt a blocked synchronous callback; independently prove a safe release/no-Stop path and cold-power recovery. | **BLOCKED.** Physical Stop and recovery not verified. |
| Card recovery and original ROM | Reviewed recovery media, power-loss/restoration process, original ROM provenance and exact-card cold-state requirements. | **OPEN.** Archived ROM structure alone is insufficient. |
| Per-card execution transition | Safe first-to-second driver/platform/MSI/firmware rebind after verified first-card teardown. | **DEPENDENT / NOT IMPLEMENTED.** Keep one-shot guard. |
| Post-Windows proof | Both card identities and stock driver health; independent HMMA issue rate, numeric controls and matched before/after workload data. | **NOT TESTED after unlock.** |

The investigation file records **DEAD END** and **IRRELEVANT** candidates. Do not re-run those scans or branch analyses unless a new primary instruction, producer or byte source changes their original hypothesis. Correctly marked dead ends are retained to avoid duplicated work. No archived `DUAL_GPU_61742_REMEDIATION_PLAN.md` section becomes a new task merely because it mentions an earlier “next action.”

## 6. Failure rules and release conditions

- Before any mutation, a missing source, unknown ROM, unexpected peer, ambiguous console, invalid PCI path, absent recovery procedure or incomplete signed record **must fail without a driver Stop**.
- After any uncertain driver Stop, DMA, MMIO, SEC2, selector, FLR, S3 registration or EFI close result, retain the exact fault and ownership state. **Do not** retry, clear a sticky fault, switch to another GPU or continue normal Windows handover.
- Do not install or enable unattended DXE execution, alter NVRAM/BootOrder, modify Secure Boot trust, flash video BIOS, or patch the stock Windows driver to bypass an evidence gate.
- Use the original unmodified current Windows driver as the compatibility boundary. A Linux signed-reference asset is a comparison artifact, not a production acceptance record.
- For every future source change, verify the exact production function and independent failure cases through relevant existing host tests and Windows EFI builds. Record the command, result, source SHA and coverage in the commit/CI result, **not** as a dated report in this plan.
- For any future approved physical run, require before/after logs, exact binary and firmware hashes, explicit GPU identities, source evidence for each gate, recovery outcome and meaningful negative controls. An EFI success code, `UNLOCK_VERIFIED=UNKNOWN` or a benchmark speed alone does not qualify a release.

## 7. Owner / agent — Current next steps

**Current release blocker — original NVIDIA binary evidence:** The original AD102 `IMG00.BIN` zero-child NVIDIA `Stop` at image RVA `0x209C`, and GA102 `IMG01.BIN` at RVA `0x20B0`, can call device/adapter/embedded-object destructors that write BAR0 registers and poll status `0x610630` **without a visible local timeout**. The earlier DIAG10 snapshot had `+0x98=0` on both cards, but that flag does not guard this destructor. The original v87 source and v95 host-only fault model were already analyzed; do not repeat them merely to reconfirm. `OpenProtocol(EXCLUSIVE)` can invoke a driver's `Stop` under UEFI 2.10 and is not a bypass. No physical Stop or cold-power recovery is proven.

**Completed Booter transfer branch:** `nvlddmkm-61742-booter-discovery-20261112-102125-074529.txt`, 4,830 bytes, SHA-256 `83cb0ca003b4cb2e8e888b454fd0b961c2c6a74c88229ffa81ab046b387a2220`, correct original MD5/base, `STATUS=COMPLETE`, no Ghidra or hardware mutation. Four `FUN_140BF1390 → FUN_1406A2F10` callsite arguments have been classified: R9 supplies buffer offsets, fifth stack argument supplies word-transfer byte counts. No signed Booter producer or actual `FUN_140BF3880` invocation is present. **No next Ghidra command for these closed calls.**

**Gate distinction:** Changing cables to AMD can clear only current preboot console ownership if passive evidence confirms it. It cannot clear the unbounded vendor Stop risk, post-Stop peer/AMD survival, independent recovery, firmware signature acceptance, or active hardware permissions. No active source changes or host/firmware tests were executed for this static report.

| Responsibility | Current next action |
|---|---|
| **AGENT — Completed** | Verify the four-site original 617.42 report and its R9 buffer offsets and stack byte-count setup; close generic word-transfer callsite work. Recheck current `msi_release.c`, prior original NVIDIA zero-child GOP Stop disassembly (AD102/GA102 destructor writes and unbounded status poll), and UEFI exclusive-open semantics. Update only the two authoritative documents. |
| **AGENT — Next** | Evaluate **source-only** feasibility of a verified before-driver-start PCI ownership route that avoids the previously classified NVIDIA `Stop`, or obtain independent evidence that bounds the exact callback and recovery. Do not infer safety from AMD-only cables, `EXCLUSIVE`, a caller-side timeout, or a warm reboot. In parallel continue genuine Windows 617.42 signed IMAGE/HEADER/SIG/PATCH producer and same-instance `nested+0x170=FUN_140BF3880` third-argument analysis only from new original evidence. Do not repeat generic transfer call windows. |
| **OWNER — Next (optional passive configuration check)** | No further Ghidra output is required for the four completed generic callsites. To clear the *changeable* console conflict only: shut the PC down and fully power it off, move all display cables to the AMD motherboard graphics outputs, leave RTX 4090 and RTX 3080 installed, boot the already trusted **passive-only** topology diagnostic, and attach its full log. Check AMD-owned `ConOut` and `ErrOut`, live AMD TextOut/GOP graph, both exact NVIDIA PCI `BY_DRIVER` owners and no surviving NVIDIA GOP in the current source's conservative admission. The global `INCOMPLETE` verdict with zero NVIDIA GOPs is not itself proof of AMD-owner failure. Do not run any vendor Stop, exclusive claim, firmware load, FLR or active EFI image. No repeated capture if the cables/configuration have not changed. |
| **OWNER + AGENT — Hardware** | Keep `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`, `RECOVERY_VERIFIED=false`. Do not promote an active stage without separate evidence and authorization. |
