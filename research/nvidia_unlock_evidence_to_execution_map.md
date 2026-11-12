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
| Independent AMD console admission and headless source route | **PASS — SOURCE/HOST checks.** A NVIDIA peer cannot count as the AMD console. When selected GPU has no GOP, `Consumers()` requires one driver and no selected display/child edges, and `GuMsiRelease()` starts at stage 3 (selected PCI driver Stop); the stage 1/2 shared output disconnects are not called. **No physical Stop or survival proven.** |
| Original Windows GSP/UCODES files and index | **PASS — ORIGINAL FILES/STATIC.** File SHA pins and NVUCODES indexed external boundaries verified. **Booter record selection and exact signed-loader use are OPEN**. |
| Original Windows Falcon callback/loader analysis | **PARTIAL — STATIC.** Nested object publication, conditional `+0x170` loader registration and one generic transfer's actual source/count are known. No same-instance secure-loader invocation, accepted signed descriptor or production IMAGE/HEADER/SIG/PATCH mapping. |
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
| 04 | Select and validate the **actual** release branch. For a selected NVIDIA card with no GOP, verify the stage-3-only driver Stop route and AMD/peer ownership. With a selected GOP, separately analyze the stage 1/2 shared GraphicsConsole and ConSplitter callbacks. Establish a reviewed recovery procedure for either route. | **BLOCKED — PHYSICAL.** Stage-3-only branch is proven in source, not on hardware; static checks cannot prove callback return or safe recovery. |
| 05 | Only after separate approval, stop/release **one** selected NVIDIA device without affecting the AMD console or other NVIDIA card. Revalidate all owners and the chosen PCI target. | **BLOCKED — PHYSICAL / NOT TESTED.** |
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
| Secure-loader source/record | Original production Windows AD102 and GA102 IMAGE/HEADER/SIG/PATCH labels or equivalent original producer, byte offsets/lengths/hashes and selected pointer flow. | **OPEN.** Never infer Windows slot numbers from Linux bindata values. |
| Secure-loader invocation | Same-instance `outer+0x108` publication → nested method `+0x170` read → actual guarded call resolving to `FUN_140BF3880`; full third-input data flow and selected original signature. | **OPEN.** DATA references, same offsets and a generic transfer are not enough. |
| Windows secure acceptance | Exact per-card hardware/stock-loader response to an authentic signed firmware set; invalid assets rejected. | **OPEN; physical proof not authorized.** |
| Vendor release and console ownership | Show AMD-only `ConOut`/`ErrOut`, selected NVIDIA GOP absence and peer protection for a **headless** branch, or full shared-driver Stop analysis if a selected GOP exists. In both paths prove actual vendor PCI Stop effects, fault containment and independent full-power recovery. | **OPEN.** Cabling can change; last captured NVIDIA console configuration is a conflict. |
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

**Required read-only Ghidra command (one paste; no hardware access):**

```python
exec(open(r"D:\Projects\gpu-unlock\Windows-GPU-UNLOCK\research\ghidra\nvlddmkm_booter_discovery.py", encoding="utf-8").read(), {"currentProgram": state.getCurrentProgram(), "SCAN_STRINGS": False, "TARGET_FUNCTIONS": ["0x1406a2f10"], "FULL_DECOMP_MAX_CHARS": 131072, "__name__": "__main__"})
```

**Report requirements:** driver MD5 `3fb9afac9d0e394723e830aa14e60512`, base `0x140000000`, `DECOMPILER_BEGIN entry=1406a2f10 clipped=False`, `DECOMPILER_END`, `HARDWARE_ACTION=NONE GHIDRA_MUTATION=NONE`, and terminal `STATUS=COMPLETE REPORT=...`. A clipped/undefined function is **PARTIAL** for this evidence task; do not treat missing code as absence. This is a direct source helper from the previously completed `FUN_140BF1390` body, not a known Booter producer. Do not repeat completed `FUN_1402E7CE0`, `FUN_1402EA6F0`, `FUN_140BF5150`, `FUN_1406B94D0`, `FUN_1406B99D0`, or the old wide search.

| Responsibility | Current next action |
|---|---|
| **AGENT — Completed** | Recheck original Windows helper classifications and the existing source-only AMD console admission, shared release and headless branch. Confirm that stage-3-only headless release skips selected GOP/ConSplitter callbacks but still requires an unverified NVIDIA PCI driver Stop. Correct the prior assertion that display wiring is fixed. Update this map and the single investigation record without chronological notes. |
| **AGENT — Next** | Classify the one unreviewed, directly called original `FUN_1406A2F10` body for concrete signed-record construction or a machine-proven loader link. If it is generic, mark its direct-producer hypothesis **DEAD END** and stop. Continue only from real original Windows record/descriptor producer or same-instance `FUN_140BF3880` call evidence. In parallel retain the stage-3-only vendor Stop, AMD/peer survival and cold recovery as independent physical blockers. |
| **OWNER — Next (read-only Ghidra)** | Run the single original-driver `FUN_1406A2F10` command below in the existing MD5-pinned PyGhidra console and attach its full `STATUS/REPORT`, including unclipped function body and original MD5/base. **Optional physical preparation:** after powering off, the owner may move displays to AMD motherboard output (leave both NVIDIA cards installed) and run the already trusted **passive-only** topology diagnostic to establish the new current-boot AMD console/peer state. This can qualify only the passive console gate, not authorize vendor Stop. No display move is required to complete the Ghidra analysis. |
| **OWNER + AGENT — Hardware** | Keep `CAN_DETACH=false`, `CAN_UNLOCK=false`, `CAN_FLASH=false`, `RECOVERY_VERIFIED=false`. Do not promote an active stage without separate evidence and authorization. |
