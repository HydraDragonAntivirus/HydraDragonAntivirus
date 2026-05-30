#pragma once

/*++

Module Name:

    RootkitDetector.h

Abstract:

    Event-driven rootkit detection engine for HydraDragon / Owlyshield.
    No timer. Detection fires on every new driver event via
    RootkitDetectorOnDriverEvent(), internally debounced to avoid overhead
    on hot event paths.

    Detection capabilities:
      1. SSDT integrity         - entries pointing outside ntoskrnl
      2. Hidden process         - PspCidTable vs EPROCESS list mismatch (DKOM)
      3. Hidden driver          - object directory entry missing from module list
      4. Driver object integrity - DriverInit/AddDevice/MajorFunction mismatch
      5. Kernel inline hook     - FF25 / E9 / mov-rax-jmp-rax on ntoskrnl exports
      6. Object type tampering  - unsupported file-object callbacks enabled

    IRP opcodes (defined in SharedDefs.h):
      IRP_ROOTKIT_SSDT_HOOK       21
      IRP_ROOTKIT_HIDDEN_PROCESS  22
      IRP_ROOTKIT_HIDDEN_DRIVER   23
      IRP_ROOTKIT_KERNEL_HOOK     24

Environment:

    Kernel mode only.

--*/

#include <fltKernel.h>
#include "SharedDefs.h"

#ifdef __cplusplus
extern "C" {
#endif

// -------------------------------------------------------------------------
// Trigger hint passed to RootkitDetectorOnDriverEvent().
// -------------------------------------------------------------------------
typedef enum _RK_TRIGGER
{
    // SSDT + inline-hook only. Cheap, no process enumeration.
    RK_TRIGGER_LIGHT   = 0,

    // Full scan: SSDT + driver-object + inline-hook + hidden-process + hidden-driver.
    RK_TRIGGER_FULL    = 1,

    // Hidden-driver + driver-object + hidden-process. Used on image-load events.
    RK_TRIGGER_DRIVER  = 2,

} RK_TRIGGER;

// -------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------

// Call once from DriverEntry after driverData is initialised.
NTSTATUS  RootkitDetectorInitialize(VOID);

// Register the device object used to queue passive-level work items.
// Must be called before the first RootkitDetectorOnDriverEvent().
VOID      RootkitDetectorSetDeviceObject(_In_ PDEVICE_OBJECT DeviceObject);

// Called by FSfilter on every relevant driver event.
// Debounced internally; safe to call on every IRP.
VOID      RootkitDetectorOnDriverEvent(_In_ RK_TRIGGER Trigger,
                                       _In_ ULONG      EventIrp);

// Run all checks synchronously at PASSIVE_LEVEL. Returns anomaly count.
ULONG     RootkitDetectorRunScan(VOID);

// Call from DriverUnload.
VOID      RootkitDetectorCleanup(VOID);

// -------------------------------------------------------------------------
// Tunables
// -------------------------------------------------------------------------

// Minimum ms between consecutive FULL scans (light/driver scans skip debounce).
#ifndef ROOTKIT_DEBOUNCE_MS
#define ROOTKIT_DEBOUNCE_MS 500
#endif

// Max anomalies per pass (prevents IRP queue flooding).
#define ROOTKIT_MAX_FINDINGS_PER_PASS 32

#ifdef __cplusplus
} // extern "C"
#endif

