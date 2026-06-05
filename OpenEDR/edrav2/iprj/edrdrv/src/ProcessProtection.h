#pragma once

#ifndef PROCESS_PROTECTION_H
#define PROCESS_PROTECTION_H

/*++

Module Name:

    ProcessProtection.h

Abstract:

    Header file for comprehensive process protection using ObRegisterCallbacks
    and kernel-level API hooks. Detects all process-related events:
    - Process termination attempts
    - Process handle operations
    - Kernel API hooking for injection detection

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <ntddk.h>

// ===================================================================
// Init/Uninit
// ===================================================================

NTSTATUS InitProcessProtection();
VOID UninitProcessProtection();
VOID ReloadProcessProtectionExcludeRules(VOID);
NTSTATUS SetProcessProtectionExcludeRulesFromBuffer(
    _In_reads_bytes_(BytesRead) PUCHAR Buffer,
    _In_ ULONG BytesRead);

// ===================================================================
// Process Event Functions (LBVS path) — implemented in namespace cmd
// ===================================================================

namespace cmd {

// Process termination attempt → SysmonEvent::ProcessOpen (0x000D) with PROCESS_TERMINATE
NTSTATUS QueueTerminationAttemptToUserMode(
    _In_ PEPROCESS AttackerProcess,
    _In_ PEPROCESS TargetProcess
);

// Cross-process handle open/duplicate telemetry → SysmonEvent::ProcessOpen (0x000D)
NTSTATUS OnProcessHandleOperation(
    _In_ HANDLE CallerProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ UCHAR OperationType
);

// Kernel/usermode hook events → SysmonEvent::DeviceIoControl (0x000E) via LBVS
NTSTATUS OnKernelApiEvent(
    _In_ ULONG IrpOp,
    _In_ ULONG EventType,
    _In_ ULONG SourcePid,
    _In_ ULONG TargetPid,
    _In_opt_ PCWSTR FunctionName,
    _In_opt_ ULONG_PTR EventArg1,
    _In_opt_ ULONG_PTR EventArg2,
    _In_opt_ ULONG_PTR EventArg3,
    _In_opt_ ULONG_PTR EventArg4
);

} // namespace cmd

// Format a diagnostic process descriptor as "pid:path" when the image path
// can be resolved at PASSIVE_LEVEL, otherwise "pid:<path_unavailable>".
VOID FormatProcessDescriptorByPid(
    _In_ ULONG ProcessId,
    _Out_writes_z_(OutCch) PWCHAR OutBuffer,
    _In_ SIZE_T OutCch
);

VOID NoteRemoteThreadCandidate(
    _In_ ULONG SourcePid,
    _In_ ULONG TargetPid
);

BOOLEAN ResolveRemoteThreadCandidate(
    _In_ ULONG TargetPid,
    _Out_ PULONG SourcePid
);

#endif // PROCESS_PROTECTION_H
