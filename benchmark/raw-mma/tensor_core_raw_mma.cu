// Read-only Tensor Core microbenchmark for sm_86 and sm_89.
// Executes direct mma.sync PTX; no firmware, driver, clock, or power modifications.
// CUDA runtime and standard library only. GPU execution has NOT been verified by author.
#include <cuda_runtime.h>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#define CUDA_CHECK(expr) do { cudaError_t e = (expr); if (e != cudaSuccess) { \
  std::fprintf(stderr, "CUDA error at %s:%d: %s\n", __FILE__, __LINE__, cudaGetErrorString(e)); \
  std::exit(1); } } while (0)

constexpr int kThreads = 256;
constexpr int kStreams = 4; // four independent accumulator chains, avoid pure latency measurement
constexpr int kRegistersPerStream = 4;

enum Mode { FP16_FP32 = 0, BF16_FP32 = 1, TF32_FP32 = 2, FP16_FP16 = 3, INT8_INT32 = 4 };

// Operand layouts and register counts follow PTX mma.sync.aligned.m16n8k* contracts.
template <int mode>
__device__ __forceinline__ void mma_float(float &d0, float &d1, float &d2, float &d3,
                                           uint32_t a, uint32_t b) {
  if constexpr (mode == FP16_FP32) {
    asm volatile("mma.sync.aligned.m16n8k16.row.col.f32.f16.f16.f32 "
                 "{%0,%1,%2,%3}, {%4,%5,%6,%7}, {%8,%9}, {%0,%1,%2,%3};"
                 : "+f"(d0), "+f"(d1), "+f"(d2), "+f"(d3)
                 : "r"(a), "r"(a), "r"(a), "r"(a), "r"(b), "r"(b));
  } else if constexpr (mode == BF16_FP32) {
    asm volatile("mma.sync.aligned.m16n8k16.row.col.f32.bf16.bf16.f32 "
                 "{%0,%1,%2,%3}, {%4,%5,%6,%7}, {%8,%9}, {%0,%1,%2,%3};"
                 : "+f"(d0), "+f"(d1), "+f"(d2), "+f"(d3)
                 : "r"(a), "r"(a), "r"(a), "r"(a), "r"(b), "r"(b));
  } else if constexpr (mode == TF32_FP32) {
    asm volatile("mma.sync.aligned.m16n8k8.row.col.f32.tf32.tf32.f32 "
                 "{%0,%1,%2,%3}, {%4,%5,%6,%7}, {%8,%9}, {%0,%1,%2,%3};"
                 : "+f"(d0), "+f"(d1), "+f"(d2), "+f"(d3)
                 : "r"(a), "r"(a), "r"(a), "r"(a), "r"(b), "r"(b));
  }
}

__device__ __forceinline__ void mma_half(uint32_t &d0, uint32_t &d1,
                                          uint32_t a, uint32_t b) {
  asm volatile("mma.sync.aligned.m16n8k16.row.col.f16.f16.f16.f16 "
               "{%0,%1}, {%2,%3,%4,%5}, {%6,%7}, {%0,%1};"
               : "+r"(d0), "+r"(d1)
               : "r"(a), "r"(a), "r"(a), "r"(a), "r"(b), "r"(b));
}

__device__ __forceinline__ void mma_int(int32_t &d0, int32_t &d1,
                                         int32_t &d2, int32_t &d3,
                                         uint32_t a, uint32_t b) {
  asm volatile("mma.sync.aligned.m16n8k32.row.col.s32.s8.s8.s32 "
               "{%0,%1,%2,%3}, {%4,%5,%6,%7}, {%8,%9}, {%0,%1,%2,%3};"
               : "+r"(d0), "+r"(d1), "+r"(d2), "+r"(d3)
               : "r"(a), "r"(a), "r"(a), "r"(a), "r"(b), "r"(b));
}

template <int mode>
__global__ void mma_kernel(uint32_t *out, int iterations) {
  const uint32_t a = (mode == FP16_FP32 || mode == FP16_FP16) ? 0x2c002c00u :
                     mode == BF16_FP32 ? 0x3d803d80u :
                     mode == TF32_FP32 ? 0x3d800000u : 0x01010101u;
  const uint32_t b = a;
  const int output = (blockIdx.x * blockDim.x + threadIdx.x) * kStreams * kRegistersPerStream;
  if constexpr (mode == FP16_FP16) {
    uint32_t d[kStreams][2] = {};
    #pragma unroll 1
    for (int i = 0; i < iterations; ++i) {
      #pragma unroll
      for (int s = 0; s < kStreams; ++s) mma_half(d[s][0], d[s][1], a, b);
    }
    #pragma unroll
    for (int s = 0; s < kStreams; ++s) {
      out[output + s*4] = d[s][0];
      out[output + s*4+1] = d[s][1];
    }
  } else if constexpr (mode == INT8_INT32) {
    int32_t d[kStreams][4] = {};
    #pragma unroll 1
    for (int i = 0; i < iterations; ++i) {
      #pragma unroll
      for (int s = 0; s < kStreams; ++s)
        mma_int(d[s][0], d[s][1], d[s][2], d[s][3], a, b);
    }
    #pragma unroll
    for (int s = 0; s < kStreams; ++s)
      #pragma unroll
      for (int k = 0; k < 4; ++k) out[output + s*4+k] = (uint32_t)d[s][k];
  } else {
    float d[kStreams][4] = {};
    #pragma unroll 1
    for (int i = 0; i < iterations; ++i) {
      #pragma unroll
      for (int s = 0; s < kStreams; ++s)
        mma_float<mode>(d[s][0], d[s][1], d[s][2], d[s][3], a, b);
    }
    #pragma unroll
    for (int s = 0; s < kStreams; ++s)
      #pragma unroll
      for (int k = 0; k < 4; ++k) out[output + s*4+k] = __float_as_uint(d[s][k]);
  }
}

template <int mode>
void launch(uint32_t *p, int blocks, int iterations) {
  mma_kernel<mode><<<blocks, kThreads>>>(p, iterations);
  CUDA_CHECK(cudaGetLastError());
}

void invoke(int mode, uint32_t *p, int blocks, int iterations) {
  switch (mode) {
    case FP16_FP32: launch<FP16_FP32>(p, blocks, iterations); break;
    case BF16_FP32: launch<BF16_FP32>(p, blocks, iterations); break;
    case TF32_FP32: launch<TF32_FP32>(p, blocks, iterations); break;
    case FP16_FP16: launch<FP16_FP16>(p, blocks, iterations); break;
    case INT8_INT32: launch<INT8_INT32>(p, blocks, iterations); break;
  }
}

static const char* mode_name[] = {"fp16_f32acc", "bf16_f32acc", "tf32_f32acc", "fp16_f16acc", "int8_i32acc"};
static const int kDimension[] = {16, 16, 8, 16, 32};

bool verify(int mode, uint32_t *dout, int blocks) {
  // 64 MMA iterations are exactly representable in all five modes at chosen inputs.
  constexpr int check_iterations = 64;
  invoke(mode, dout, blocks, check_iterations);
  CUDA_CHECK(cudaDeviceSynchronize());
  uint32_t bits[16];
  CUDA_CHECK(cudaMemcpy(bits, dout, sizeof(bits), cudaMemcpyDeviceToHost));
  const float expected = (mode == TF32_FP32) ? 2.f : 4.f;
  const int expected_int = 2048;
  for (int s = 0; s < kStreams; ++s) {
    for (int k = 0; k < (mode == FP16_FP16 ? 2 : 4); ++k) {
      uint32_t value = bits[s*4+k];
      if (mode == FP16_FP16) {
        if (value != 0x44004400u) {
          std::fprintf(stderr, "Validation failed: %s stream=%d reg=%d packed=0x%08x expected=0x44004400\n", mode_name[mode], s, k, value);
          return false;
        }
      } else if (mode == INT8_INT32) {
        if (value != static_cast<uint32_t>(expected_int)) {
          std::fprintf(stderr, "Validation failed: %s stream=%d reg=%d value=%u expected=%d\n", mode_name[mode], s, k, value, expected_int);
          return false;
        }
      } else {
        float result;
        std::memcpy(&result, &value, sizeof(result));
        if (!std::isfinite(result) || std::fabs(result-expected)>0.0001f) {
          std::fprintf(stderr, "Validation failed: %s stream=%d reg=%d value=%f expected=%f\n", mode_name[mode], s, k, result, expected);
          return false;
        }
      }
    }
  }
  return true;
}

void bench_device(int device, int iterations, int trials, int blocks_per_sm) {
  CUDA_CHECK(cudaSetDevice(device));
  cudaDeviceProp p;
  CUDA_CHECK(cudaGetDeviceProperties(&p, device));
  if (p.major != 8 || (p.minor != 6 && p.minor != 9)) {
    std::fprintf(stderr, "GPU%d capability %d.%d not in audited target set (sm_86 / sm_89)\n", device, p.major, p.minor);
    std::exit(1);
  }
  const int blocks = p.multiProcessorCount * blocks_per_sm;
  const uint64_t warps = uint64_t(blocks) * (kThreads / 32);
  const size_t size = size_t(blocks) * kThreads * kStreams * kRegistersPerStream * sizeof(uint32_t);
  uint32_t *out = nullptr;
  CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&out), size));
  cudaEvent_t start, stop;
  CUDA_CHECK(cudaEventCreate(&start));
  CUDA_CHECK(cudaEventCreate(&stop));
  std::fprintf(stderr, "GPU%d: %s sm_%d%d SMs=%d blocks=%d warps=%llu result_memory=%zu bytes\n",
               device, p.name, p.major, p.minor, p.multiProcessorCount, blocks,
               static_cast<unsigned long long>(warps), size);
  for (int mode = 0; mode < 5; ++mode) {
    if (!verify(mode, out, blocks)) std::exit(2);
    for (int warm = 0; warm < 3; ++warm) invoke(mode, out, blocks, iterations);
    CUDA_CHECK(cudaDeviceSynchronize());
    const double ops = double(warps) * kStreams * iterations * (2.0 * 16 * 8 * kDimension[mode]);
    std::vector<double> ms;
    for (int tr = 0; tr < trials; ++tr) {
      CUDA_CHECK(cudaEventRecord(start));
      invoke(mode, out, blocks, iterations);
      CUDA_CHECK(cudaEventRecord(stop));
      CUDA_CHECK(cudaEventSynchronize(stop));
      float elapsed_ms=0;
      CUDA_CHECK(cudaEventElapsedTime(&elapsed_ms, start, stop));
      if (!(elapsed_ms > 0)) { std::fprintf(stderr, "Invalid CUDA timing\n"); std::exit(2); }
      ms.push_back(elapsed_ms);
      const double tops = ops / (double(elapsed_ms)*1.0e9);
      std::printf("%d,%s,%d,%d,%d,%d,%llu,%.6f,%.6f,ok\n", device, mode_name[mode], tr, iterations, blocks, kDimension[mode],
                  static_cast<unsigned long long>(warps), double(elapsed_ms), tops);
    }
    std::sort(ms.begin(), ms.end());
    const double med = ms[ms.size()/2];
    std::fprintf(stderr, "GPU%d %s: median %.4f ms, %.2f T%s/s (raw mma.sync, %d trials)\n",
                 device, mode_name[mode], med, ops/(med*1e9), mode == INT8_INT32 ? "OP" : "FLOP", trials);
  }
  CUDA_CHECK(cudaEventDestroy(start));
  CUDA_CHECK(cudaEventDestroy(stop));
  CUDA_CHECK(cudaFree(out));
}

int main(int argc, char **argv) {
  int only_gpu=-1, iters=8192, trials=7, blocks_per_sm=4;
  for (int i=1;i<argc;i++) {
    if (i+1>=argc) { std::fprintf(stderr, "Missing value for %s\n", argv[i]); return 1; }
    const char* flag=argv[i++];
    int val=std::atoi(argv[i]);
    if (!std::strcmp(flag,"--gpu")) only_gpu=val;
    else if (!std::strcmp(flag,"--iterations")) iters=val;
    else if (!std::strcmp(flag,"--trials")) trials=val;
    else if (!std::strcmp(flag,"--blocks-per-sm")) blocks_per_sm=val;
    else { std::fprintf(stderr, "Unknown argument: %s\n", flag); return 1; }
  }
  if (iters<1 || iters>100000 || trials<1 || trials>99 || blocks_per_sm<1 || blocks_per_sm>12) {
    std::fprintf(stderr,"Invalid iterations/trials/blocks-per-sm\n"); return 1;
  }
  int count=0;
  CUDA_CHECK(cudaGetDeviceCount(&count));
  if (only_gpu>=count || only_gpu<-1) { std::fprintf(stderr, "Invalid GPU index\n"); return 1; }
  std::puts("gpu,mode,trial,iterations,blocks,k,warps,ms,tera_ops_per_second,validation");
  for (int i=0;i<count;i++) if (only_gpu<0 || only_gpu==i) bench_device(i, iters, trials, blocks_per_sm);
}
