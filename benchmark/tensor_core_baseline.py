#!/usr/bin/env python3
"""Read-only CUDA/PyTorch matrix throughput baseline, per selected GPU.

Requires an existing CUDA-enabled PyTorch environment; does not install packages,
modify drivers, change power limits, or attempt a tensor-core unlock.

This is an application-level torch.mm benchmark, not a raw MMA instruction test.
Enabled TF32 does not prove which GEMM kernel cuBLAS selected.
"""
import argparse
import json
import statistics
import subprocess
import sys
import time


def gpu_inventory():
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=index,name,pci.bus_id,driver_version,power.limit,clocks.max.sm,clocks.max.memory",
             "--format=csv,noheader,nounits"], text=True, capture_output=True, check=False, timeout=15
        )
        return result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return str(exc)


def bench(torch, gpu_index, n, mode, trials, iterations, warmups):
    dtype = {"fp16": torch.float16, "bf16": torch.bfloat16,
             "tf32_enabled": torch.float32, "fp32": torch.float32}[mode]
    torch.cuda.set_device(gpu_index)
    # Explicitly enable TF32 only for its own trial. cuBLAS can still select
    # an FP32 algorithm, so label this "TF32 enabled", not "TF32 proven".
    torch.backends.cuda.matmul.allow_tf32 = mode == "tf32_enabled"
    a = torch.randn((n, n), device=f"cuda:{gpu_index}", dtype=dtype)
    b = torch.randn((n, n), device=f"cuda:{gpu_index}", dtype=dtype)
    c = torch.empty((n, n), device=f"cuda:{gpu_index}", dtype=dtype)
    try:
        for _ in range(warmups):
            torch.mm(a, b, out=c)
        torch.cuda.synchronize(gpu_index)
        rates, elapsed_ms = [], []
        for _ in range(trials):
            start = torch.cuda.Event(enable_timing=True)
            end = torch.cuda.Event(enable_timing=True)
            start.record()
            for _ in range(iterations):
                torch.mm(a, b, out=c)
            end.record()
            end.synchronize()
            ms = start.elapsed_time(end) / iterations
            if ms <= 0:
                raise RuntimeError("GPU event returned non-positive elapsed time")
            elapsed_ms.append(ms)
            rates.append((2 * n**3) / (ms * 1e-3) / 1e12)
        # Read only: checksum and finiteness after timing, to catch invalid output.
        finite = bool(torch.isfinite(c).all().item())
        checksum = float(c.float().mean().item())
        return {"gpu": gpu_index, "n": n, "mode": mode,
                "median_tflops": round(statistics.median(rates), 3),
                "trial_tflops": [round(v, 3) for v in rates],
                "median_ms_per_mm": round(statistics.median(elapsed_ms), 4),
                "all_finite": finite, "output_mean": round(checksum, 7)}
    finally:
        del a, b, c
        torch.cuda.synchronize(gpu_index)
        torch.backends.cuda.matmul.allow_tf32 = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gpus", type=int, nargs="*", default=None,
                        help="GPU indices, default: all CUDA-visible GPUs")
    parser.add_argument("--sizes", type=int, nargs="+", default=[4096],
                        help="square GEMM sizes (default: 4096)")
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--iterations", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=12)
    parser.add_argument("--output", help="optional JSON result file")
    args = parser.parse_args()
    if min(args.trials, args.iterations, args.warmups) < 1 or any(n < 128 for n in args.sizes):
        parser.error("trials, iterations, warmups must be >=1; sizes must be >=128")
    try:
        import torch
    except ImportError as exc:
        raise SystemExit("This script needs CUDA-enabled PyTorch in the active Python environment; "+str(exc))
    if not torch.cuda.is_available():
        raise SystemExit("CUDA unavailable in this PyTorch environment (verify CUDA-enabled torch and NVIDIA driver)")
    available = torch.cuda.device_count()
    devices = list(range(available)) if args.gpus is None else args.gpus
    if not devices or any(g < 0 or g >= available for g in devices):
        parser.error(f"invalid GPU index; available CUDA device count: {available}")
    info = {"timestamp_local": time.strftime("%Y-%m-%d %H:%M:%S %z"),
            "torch_version": torch.__version__, "torch_cuda_version": torch.version.cuda,
            "nvidia_smi": gpu_inventory(),
            "workload": "torch.mm, cuBLAS-selected GEMM, CUDA event timing",
            "note": "TF32 enabled is a policy setting, not proof of the selected instruction; no unlock detection.",
            "results": []}
    for g in devices:
        info.setdefault("devices", []).append({"index": g, "name": torch.cuda.get_device_name(g),
                                               "compute_capability": torch.cuda.get_device_capability(g)})
        for n in args.sizes:
            for mode in ("fp16", "bf16", "tf32_enabled", "fp32"):
                row = bench(torch, g, n, mode, args.trials, args.iterations, args.warmups)
                info["results"].append(row)
                print(f"GPU{g} {torch.cuda.get_device_name(g)} n={n:5d} {mode:12s} "
                      f"{row['median_tflops']:9.2f} TFLOPS, finite={row['all_finite']}", flush=True)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as out:
            json.dump(info, out, indent=2, default=str)
        print("Wrote", args.output)
    else:
        print(json.dumps(info, indent=2, default=str))


if __name__ == "__main__":
    main()
