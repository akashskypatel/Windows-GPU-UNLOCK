# Windows 617.42 — pinned GA102/AD102 reference firmware preparation

This is a **host-only research tool**. It does not change the installed Windows driver, GPU, UEFI, EFI boot entries, or VBIOS. No firmware binaries are committed or distributed here.

## Version distinction

- Installed Windows display driver being investigated: **617.42** (both `01:00.0` RTX 4090 and `04:00.0` RTX 3080).
- NVIDIA source/GSP binary used by the published unlock reference: **610.43.03**, not 617.42.
- Source for the unmodified vendored generation scripts and manifests: [gpu-unlock-ada at d28c485](https://github.com/JustAResearcher/gpu-unlock-ada/tree/d28c485418c3d9d034cd4bac19200bc33dd3453b/firmware). Those files are byte-for-byte identical to that commit.
- No NVIDIA Windows 617.42 firmware/Booter extraction format or signed 617.42-specific asset set has been authenticated. **Matching the reference asset hashes does not establish that the target cards or stock driver 617.42 will accept the secure transaction.**

## Windows requirements

Windows PowerShell, Python 3.10+ on PATH, `zstd` executable on PATH, network access for the two pinned source downloads, and `nvidia-smi` available when checking the actual installed driver. For example, if Scoop is already configured:

```powershell
scoop install zstd
```

From your Windows-GPU-UNLOCK repository root:

```powershell
git pull --ff-only origin main
```

```powershell
python -m unittest discover -s research/firmware -p test_prepare_windows_firmware.py -v
```

```powershell
python -m unittest discover -s research/profile -p test_verify_secure_assets.py -v
```

Choose two distinct locations **outside the repository**. The cache may exist; the output directory **must not already exist**:

```powershell
python .\research\firmware\prepare_windows_firmware.py --cache 'D:\Projects\gpu-unlock\firmware-input-cache' --output 'D:\Projects\gpu-unlock\firmware-reference-610.43.03' --verify-installed-driver
```

Use `--offline` to require already-downloaded, checksum-matched inputs without accessing the network. The download step checks both source archive and NVIDIA Linux package SHA-256s. The generator checks each extracted stock binary and both generated V67 payloads. The wrapper performs an additional nine-file SHA-256 verification using the existing `research/profile/verify_secure_assets.py`.

The source tarball is **not unpacked wholesale**: the Windows wrapper extracts only the four known GA102/AD102 generated C files, checks their lengths, and delegates their content-hash checks to the unmodified upstream tools. The output is published only when every reference hash matches. A reported driver version and BDF match is an inventory check, **not** a per-card subsystem or hardware compatibility certificate.

## Output

```text
firmware-reference-610.43.03/
  gpu-unlock/610.43.03/
    booter_load_ga102.bin
    gsp_boot_ga102.bin
    gsp_boot_desc_ga102.bin
    v67-ga102-610.43.03.bin
    booter_load_ad102.bin
    gsp_boot_ad102.bin
    gsp_boot_desc_ad102.bin
    v67-ad102-610.43.03-four-plm.bin
    gsp_ga10x.bin
    NVIDIA-LICENSE
  NOTICE.md
  provenance.json
  reference-asset-verification.json
```

The output is intentionally **not** copied to the EFI partition, the USB unlock boot directory or the Windows DriverStore. It must not be used to authorize release, register writes, FLR, firmware execution, or flashing. The pre-existing diagnostic-only EFI remains unchanged.

Expected success status: `STATUS=REFERENCE_BYTES_MATCH_COMPATIBILITY_UNPROVEN CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false`. The tool emits `STATUS=ERROR` on recognized failure and refuses to publish a partial output.

## Attribution and licensing

The embedded scripts, manifests and NOTICE are copied from the pinned GPL-2.0-only research repository. Extracted NVIDIA firmware remains subject to NVIDIA's separate license. The wrapper preserves the upstream `NVIDIA-LICENSE` text and NOTICE in the generated output; do not commit, redistribute or relabel the binaries as open source. Reproduce from legal source inputs on the local machine.

The next hardware-dependent decisions remain open: proof of the actual card/VBIOS provenance, signed asset acceptance, post-GOP-Stop cold state, SEC2/FWSEC execution, and unmodified Windows 617.42 driver handoff. No current test of this Windows preparation tool certifies those gates.


## Passive inspection of the installed Windows 617.42 firmware pair

The stock Windows 617.42 installer (SHA-256 `f115c92760f1d677ae88f7ee114be20c10ef28a9e725736821a08218054867ca`) ships the two separate GA10x files `gsp_ga10x.bin` (27,043,992 bytes) and `ucodes_ga10x.bin` (58,215,936 bytes). These are NOT interchangeable with the pinned 610.43.03 reference firmware above. The installed GPUs independently report GSP firmware version 615.78.05, which is not the Windows KMD version.

Run the host-only structural inspector to enumerate RISC-V ELF sections and decode the 24-byte NVIDIA-defined `NVUCODES` container header. It can compare the installed files with the extracted stock installer using SHA-256. It does not extract executable firmware, inspect encrypted ucode payloads, validate vendor signatures, or interact with a GPU.

```powershell
python -m unittest discover -s research/firmware -p test_inspect_installed_firmware.py -v
```

```powershell
python .\research\firmware\inspect_installed_firmware.py --gsp 'C:\Windows\System32\DriverStore\FileRepository\nv_dispsi.inf_amd64_ccd7fbb71bb72370\gsp_ga10x.bin' --ucodes 'C:\Windows\System32\DriverStore\FileRepository\nv_dispsi.inf_amd64_ccd7fbb71bb72370\ucodes_ga10x.bin' --package-dir 'D:\Projects\gpu-unlock\nvidia-61742-inspect\Display.Driver' --output 'D:\Projects\gpu-unlock\windows-61742-gsp-ucodes-inventory.json'
```

The report path must be new; no existing report is overwritten. The inspector prints `STATUS=COMPLETE` for successful structurally valid inventory, `STATUS=PARTIAL` if installed and extracted package files do not match, or `STATUS=ERROR` on parser or I/O failure, along with `REPORT=...`. A complete report does **not** establish that GSP and ucodes are accepted by the driver or that secure firmware can run on either exact GPU.

Reference: NVIDIA public `src/nvidia/src/kernel/core/bin_data_pvt.h` at tag `615.78.08` describes `BINDATA_UCODES_BIN_HEADER` with little-endian magic, version, declared entries, and the filename-order fingerprint. The fingerprint is pairing metadata, not a code-signing check. `inspect_installed_firmware.py` intentionally does not parse the undocumented entry bodies.

The 2026-11-05 Windows 617.42 inventory reported a structurally consistent 19-section ELF and 1,293-entry `NVUCODES` header. The extended inspector also records `.fwversion` text/raw bytes and SHA-256 digests for each `.fwsignature_*` section, for byte-level version/architecture comparisons only. Signature *digests are not cryptographic verification*. Always use a fresh report path when rerunning the tool.


### Static GSP–NVUCODES fingerprint cross-check

The host-only inspector now scans exactly the ELF .fwimage section in bounded 1 MiB chunks for the 8-byte little-endian fingerprint taken from the supplied NVUCODES header. It records static_fingerprint_comparison with occurrence count, first absolute and section-relative offset, and a unique-match boolean. No match and multiple matches are reported accurately, not converted to pairing success. The fields runtime_pairing_verified=false and gsp_ucodes_pair_accepted_by_driver=false remain unchanged regardless of outcome.

For the user's Windows 617.42-installed GSP 615.78.05 pair, a separate read-only console check observed fingerprint 0x2d38befecdb703a6 **once** at file offset 17492248 (0x010ae918), relative to .fwimage offset 64 at 17492184 (0x010ae8d8). The result is user-supplied static evidence, not a run of this newly integrated inspector.

Use the same --gsp, --ucodes, and --package-dir arguments shown above, but choose a **new** --output path such as windows-61742-gsp-ucodes-inventory-v3.json. The matching bytes support file-pair provenance, not verified signature validity, hardware execution, or a driver/firmware ABI guarantee.

### Original Windows 617.42 NVUCODES index inventory (read-only)

The original preserved Windows 617.42 GSP and NVUCODES files were independently SHA-256 verified on 2026-11-10. A read-only analysis of the original embedded GSP RISC-V loader identified header checks at virtual addresses `0x01AD14A8–0x01AD14EA`, followed by a 24-byte per-index copy and external-flag check at `0x01AD153E–0x01AD157A`. These checks are original Windows evidence in addition to NVIDIA's public private-storage structure definition.

For the **pinned** Windows NVUCODES file (SHA-256 `eed53d76248582d71c629e8b6230aee48ce673c91d782301c94e98ac6a6db7aa`), the separate `inspect_ucodes_index.py` tool validates the 1,293-entry index, its 24-byte records and all external-data ranges. It reports 205 populated external entries and 1,088 empty indices; the table ends at `0x7950`, and the first payload begins at `0x7A00`. No record crosses the end of the 58,215,936-byte source. The tool produces SHA-256 values for each bounded record; it does not output or distribute firmware record bytes.

Run the existing synthetic negative tests with:

```powershell
python -m unittest discover -s research/firmware -p test_inspect_ucodes_index.py -v
```

Run a fresh read-only index report with:

```powershell
python .\research\firmware\inspect_ucodes_index.py --ucodes 'C:\Windows\System32\DriverStore\FileRepository\nv_dispsi.inf_amd64_ccd7fbb71bb72370\ucodes_ga10x.bin' --output 'D:\Projects\gpu-unlock\windows-61742-ucodes-index.json'
```

The output path must be new. The tool requires the original pinned source SHA-256 and rejects changed, unknown, malformed, overlapping, out-of-range and unsupported index entries. The older `inspect_installed_firmware.py` v3 report still correctly states `records_parsed=false`; it remains a header-and-section report and is not retroactively changed.

**Open:** Source-grounded index-to-firmware labels and actual AD102/GA102 production Booter IMAGE/HEADER/SIG/PATCH mapping, signed-image acceptance, live loader invocation/descriptor, and post-operation hardware safety. A valid index is not an authenticated Booter. `CAN_DETACH=false CAN_UNLOCK=false CAN_FLASH=false RECOVERY_VERIFIED=false`.
