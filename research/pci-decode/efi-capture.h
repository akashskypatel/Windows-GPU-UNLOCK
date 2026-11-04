/* GPL-2.0-only. Read-only current-boot collector; no entry point or correction. */
#pragma once
#include "efi-binding.h"

typedef struct {
  EFI_HANDLE Handle;
  UINTN Segment,Bus,PathBytes;
  UINT32 PciId,Subsystem,Bar0;
  UINT8 Path[GU_DS_EFI_MAX_PATH];
} GU_DS_CAPTURE_TARGET;

/* One private zero-initialized context. Do not reset/recreate it to retry.
 * Input/context/Boot storage must be disjoint and live throughout the call.
 * Alias/reuse rejection leaves existing storage unchanged. Require this call's
 * EFI_SUCCESS; Ready alone may describe an earlier capture. Ready is observational
 * only: no claim, GPU qualification or write approval. */
typedef struct {
  BOOLEAN Used,Busy,Ready;
  EFI_STATUS Status;
  UINTN Count;
  GU_DS_EFI_BINDING Bindings[1+GU_DS_EFI_MAX_PARENTS];
  GU_DS_SNAPSHOT Snapshot;
} GU_DS_CAPTURE;

EFI_STATUS GuDsEfiCapture(GU_DS_CAPTURE *Context,EFI_BOOT_SERVICES *Boot,const GU_DS_CAPTURE_TARGET *Target);

#if defined(GU_PROBE_GENERIC) && defined(GU_DIAGNOSTIC_ONLY)
/* Diagnostic-only failure location; index 0 is GPU, indices 1..N are parents.
 * A stage is the last operation attempted, NOT proof it was the only failure. */
typedef enum {
  GuDsObserveInput=1,GuDsObserveTarget=2,GuDsObserveLocate=3,
  GuDsObserveInterface=4,GuDsObservePath=5,GuDsObserveLocation=6,
  GuDsObserveConfig=7,GuDsObserveAttributes=8,GuDsObserveSupported=9,
  GuDsObserveTopology=10,GuDsObserveMatch=11,GuDsObserveComplete=12,
  GuDsObserveFinalConfig=13,GuDsObserveCapabilities=14
} GU_DS_OBSERVE_STAGE;
typedef struct {
  UINTN Stage,Pass,Index;
} GU_DS_OBSERVE_TRACE;
EFI_STATUS GuDsEfiObserveParents(GU_DS_CAPTURE *Context,EFI_BOOT_SERVICES *Boot,
  const GU_DS_CAPTURE_TARGET *Target,GU_DS_OBSERVE_TRACE *Trace);
#endif
