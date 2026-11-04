@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
  echo ERROR: x64 Visual Studio compiler setup not found: "%VCVARS%"
  exit /b 1
)
call "%VCVARS%"
if errorlevel 1 exit /b 1
if not defined CUDA_PATH (
  echo ERROR: CUDA_PATH is unset
  exit /b 1
)
if not exist "%CUDA_PATH%\bin\nvcc.exe" (
  echo ERROR: nvcc not found under CUDA_PATH
  exit /b 1
)
"%CUDA_PATH%\bin\nvcc.exe" -std=c++17 -O3 -lineinfo -gencode=arch=compute_86,code=sm_86 -gencode=arch=compute_89,code=sm_89 "tensor_core_raw_mma.cu" -o "tensor_core_raw_mma.exe"
if errorlevel 1 (
  echo ERROR: CUDA build failed; do not interpret this as a GPU performance result.
  exit /b 1
)
"%CUDA_PATH%\bin\cuobjdump.exe" --dump-sass "tensor_core_raw_mma.exe" > "tensor-core-raw-mma.sass.txt"
if errorlevel 1 (
  echo ERROR: SASS extraction failed; benchmark binary has not been attested.
  exit /b 1
)
findstr /I /C:"HMMA" /C:"IMMA" "tensor-core-raw-mma.sass.txt" > "tensor-core-raw-mma-instructions.txt"
if errorlevel 1 (
  echo ERROR: Expected HMMA/IMMA instructions not found; inspect generated binary before benchmarking.
  exit /b 1
)
echo BUILD COMPLETE. Review per-architecture HMMA/IMMA in tensor-core-raw-mma.sass.txt.
echo The toolchain and binary were NOT validated on the developer's GPU.
