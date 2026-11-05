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

**Verification scope:** Twelve synthetic local tests and Python compilation passed in the assistant environment. The official 615.78.08 source archive has not yet been processed. Do not use a reference comparison as evidence of Windows firmware compatibility, cryptographic signature validity, or permission to run unsigned code.
