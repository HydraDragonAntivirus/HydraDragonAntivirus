#pragma once

/*++

Module Name:

    ProcessProtection.h

Abstract:

    Header file for process protection using ObRegisterCallbacks.
    Detects when external processes attempt to terminate other processes.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <ntddk.h>

// Initialize process protection callbacks
NTSTATUS InitProcessProtection();

// Uninitialize process protection callbacks (call during driver unload)
VOID UninitProcessProtection();
