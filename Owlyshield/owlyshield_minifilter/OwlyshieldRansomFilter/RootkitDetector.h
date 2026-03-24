#pragma once

/*++

Module Name:

    RootkitDetector.h

Abstract:

    Kernel-mode rootkit detection engine inspired by GMER's detection methods.

    Detection capabilities:
      1. SSDT integrity check  - entries pointing outside ntoskrnl are flagged
      2. Hidden process        - EPROCESS ActiveProcessLinks vs PspCidTable mismatch
      3. Hidden driver         - PsLoadedModuleList vs ZwQuerySystemInformation mismatch
      4. Kernel inline hooks   - first 16 bytes of critical ntoskrnl exports checked
                                 for FF25/E9 redirect patterns

    All findings are forwarded to the IRP queue via the same DRIVER_MESSAGE
    / IRP_ROOTKIT_* opcodes defined in SharedDefs.h so that behavior_engine.rs
    can handle them uniformly.

Environment:

    Kernel mode only.

--*/

#include <fltKernel.h>
#include "SharedDefs.h"

#ifdef __cplusplus
extern "C" {
#endif

// -------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------

//
// Call once from DriverEntry after driverData is initialised.
// Resolves dynamic imports and starts the periodic scan timer.
//
NTSTATUS
RootkitDetectorInitialize(VOID);

//
// Call from DriverUnload / cleanup path.
// Cancels the timer and frees all resources.
//
VOID
RootkitDetectorCleanup(VOID);

//
// Run all checks synchronously. Normally driven by the internal timer,
// but can also be called on-demand from user-mode via a COM_MESSAGE.
// Returns the number of anomalies found.
//
ULONG
RootkitDetectorRunScan(VOID);

// -------------------------------------------------------------------------
// Scan interval (configurable at compile time)
// -------------------------------------------------------------------------

//  How often the periodic scan fires, in seconds.
#ifndef ROOTKIT_SCAN_INTERVAL_SEC
#define ROOTKIT_SCAN_INTERVAL_SEC 60
#endif

// Maximum number of hidden processes / drivers we report per scan pass.
#define ROOTKIT_MAX_FINDINGS_PER_PASS 32

#ifdef __cplusplus
} // extern "C"
#endif
