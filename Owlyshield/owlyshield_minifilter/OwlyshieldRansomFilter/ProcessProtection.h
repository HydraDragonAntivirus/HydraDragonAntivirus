#pragma once

/*++

Module Name:

    ProcessProtection.h

Abstract:

    Header file for comprehensive process protection using ObRegisterCallbacks
    and kernel-level API hooks. Detects all process-related events:
    - Process creation
    - Process termination attempts
    - Process exit events
    - Process handle operations
    - Kernel API hooking for injection detection

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <ntddk.h>

// ===================================================================
// Process Creation/Termination/Exit Callbacks
// ===================================================================

// Initialize process protection callbacks
NTSTATUS InitProcessProtection();

// Uninitialize process protection callbacks (call during driver unload)
VOID UninitProcessProtection();

// ===================================================================
// Process Event Detection Functions
// ===================================================================

// Detect process creation events
NTSTATUS OnProcessCreate(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId
);

// Detect process exit/termination
NTSTATUS OnProcessExit(
    _In_ HANDLE ProcessId
);

// Detect process handle operations (open, duplicate)
NTSTATUS OnProcessHandleOperation(
    _In_ HANDLE CallerProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ UCHAR OperationType  // OB_OPERATION_HANDLE_CREATE or OB_OPERATION_HANDLE_DUPLICATE
);

// Detect process termination attempt
NTSTATUS OnProcessTerminationAttempt(
    _In_ HANDLE AttackerPid,
    _In_ HANDLE TargetPid
);

// ===================================================================
// Kernel API Hook Integration Functions
// ===================================================================

// Log kernel-level API hooking events
NTSTATUS OnKernelApiEvent(
    _In_ ULONG EventType,
    _In_ ULONG SourcePid,
    _In_ ULONG TargetPid,
    _In_opt_ PVOID EventData
);

// Specific kernel API event handlers
NTSTATUS OnMemoryWrite(
    _In_ ULONG SourcePid,
    _In_ ULONG TargetPid,
    _In_ PVOID TargetAddress,
    _In_ SIZE_T Size,
    _In_ BOOLEAN IsExecutableMemory
);

NTSTATUS OnMemoryProtectionChange(
    _In_ ULONG SourcePid,
    _In_ ULONG TargetPid,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _In_ ULONG OldProtection
);

NTSTATUS OnThreadCreation(
    _In_ ULONG SourcePid,
    _In_ ULONG TargetPid,
    _In_ PVOID StartRoutine
);

NTSTATUS OnApcQueueing(
    _In_ ULONG SourcePid,
    _In_ ULONG TargetPid,
    _In_ HANDLE ThreadHandle,
    _In_ PVOID ApcRoutine
);

NTSTATUS OnSectionOperation(
    _In_ ULONG SourcePid,
    _In_ ULONG TargetPid,
    _In_opt_ PCWSTR SectionName,
    _In_ UCHAR OperationType  // Create or Map
);

#endif // PROCESS_PROTECTION_H
