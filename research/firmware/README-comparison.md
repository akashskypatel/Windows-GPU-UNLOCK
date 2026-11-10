# Read-only 610.43.03 versus 615.78.08 production Booter comparison

This host-only comparison is part of the fork under research/firmware/. It performs no UEFI, GPU, driver, boot configuration, or hardware changes.

**Important version distinction:** The comparison uses NVIDIA public **Linux source 615.78.08** and the independently verified **610.43.03** research assets. It does **not** prove that Windows driver 617.42 / GSP 615.78.05 uses the same Booter or boot images. It writes metadata only, emits no extracted firmware binaries, and refuses to overwrite existing reports.

Official archive:
https://download.nvidia.com/XFree86/NVIDIA-kernel-module-source/NVIDIA-kernel-module-source-615.78.08.tar.xz

Pinned source SHA-256:
`17b4f3d195a5ab1fad9aa1f195c9d3a4ad03aceda18bb9fb68a8bd33d7a000f6`

From the Windows-GPU-UNLOCK repository root:

1. Run the host-only synthetic tests:

```powershell
python -m unittest discover -s research/firmware -p test_compare_boot_assets.py -v
```

2. Download the official source archive to a separate analysis directory:

```powershell
Invoke-WebRequest -Uri 'https://download.nvidia.com/XFree86/NVIDIA-kernel-module-source/NVIDIA-kernel-module-source-615.78.08.tar.xz' -OutFile 'D:\Projects\gpu-unlock\NVIDIA-kernel-module-source-615.78.08.tar.xz'
```

3. Optionally display the downloaded hash, which the comparator will independently verify:

```powershell
Get-FileHash -LiteralPath 'D:\Projects\gpu-unlock\NVIDIA-kernel-module-source-615.78.08.tar.xz' -Algorithm SHA256
```

4. Compare six production assets with your verified reference files:

```powershell
python .\research\firmware\compare_boot_assets.py --source-archive 'D:\Projects\gpu-unlock\NVIDIA-kernel-module-source-615.78.08.tar.xz' --reference-root 'D:\Projects\gpu-unlock\firmware-reference-610.43.03' --output 'D:\Projects\gpu-unlock\boot-assets-610-vs-615-reference.json'
```

The comparator checks the source archive's exact SHA-256, validates the six existing 610.43.03 reference asset hashes through the project's original verifier, decodes only the four required generated C files using 64-bit little-endian NVIDIA bindata with CRC/size/zero-padding checks, and reports six size/hash/byte-identity comparisons.

It prints `STATUS=COMPLETE` with `REPORT=` on completed comparison or `STATUS=ERROR` otherwise. The fields can_detach, can_unlock, and can_flash always remain false.

**Current verification scope (2026-11-10):** The official pinned 615.78.08 source archive **was processed**. The owner supplied the completed `boot-assets-610-vs-615-reference-v2.json` (5,529 bytes; SHA-256 `56e69692fbb880d9b4c9871748b8563f85ec3e40fc0797ef31f5ad1107084aaa`). Four GSP boot image/descriptor outputs are byte-identical across Linux versions; both production Booter bundles differ in **all three parsed components** (72-byte metadata, executable image and 768-byte signatures). This comparison does not establish Windows driver compatibility or authenticated signatures.

## Interpretation of the real 610.43.03 vs 615.78.08 comparison

The user ran the pinned official source archive on Windows. Twelve synthetic tests passed and the production comparison completed. Four of six assets were byte-identical across reference releases: GSP boot image and descriptor for both AD102 and GA102. The production Booter *bundles* changed: AD102 57,672 -> 58,440 bytes (+768) and GA102 61,256 -> 61,768 bytes (+512). This does not establish which Booter bytes the Windows 617.42 driver/GSP 615.78.05 loads.

The comparator now adds per-Booter component SHA-256, size and equality checks for the 72-byte research bundle metadata wrapper, internal production image, and appended signature records. This distinguishes changes in code and metadata from changes in signatures. It does not authenticate signatures or alter any firmware.

The previous v2 run is **complete**. Both chip-specific metadata/image/signature components were inspected with the published original source and exact hashes. No additional 610↔615 rerun is requested.

## Original Windows 617.42 GSP/ucodes inventory (completed static metadata)

The owner supplied `windows-61742-gsp-ucodes-inventory-v3.json` (6,199 bytes; SHA-256 `6c057c145d8850c9982837ede1e24165ef6a47f3fd08ed239b6364909057275e`). It reports a 27,043,992-byte RISC-V ELF64 GSP (SHA-256 `f89d8f615e6146ed2808df974b7af7f1aabda876596391b0aabcc32ba293c34f`) with `.fwversion=615.78.05`, 19 ELF sections, and 4,096-byte AD10x and GA10x signature sections. A distinct 58,215,936-byte `NVUCODES` file (SHA-256 `eed53d76248582d71c629e8b6230aee48ce673c91d782301c94e98ac6a6db7aa`) has 1,293 declared entries, **not yet parsed**. DriverStore and extracted-package file sizes/hashes match, but this is not driver acceptance. The NVUCODES header fingerprint occurs once within GSP `.fwimage` and does **not** prove semantic or runtime pairing.

The existing Windows `inspect_installed_firmware.py` produced the structural inventory; the independent offline universal `tools/check_firmware_evidence.py` checks consistency of the two **reports**, not the underlying firmware bytes. [CI 42843765104](https://github.com/akashskypatel/universal-gpu-unlock/actions/runs/42843765104) PASS (12 host-negative tests and Windows EFI build). Unresolved: authoritative NVUCODES entry definitions, authenticated signatures, Windows production signed Booter producer/descriptor/loader ABI, physical driver Stop and safe recovery. No report, user-attested source or third-party project authorizes hardware mutation.
