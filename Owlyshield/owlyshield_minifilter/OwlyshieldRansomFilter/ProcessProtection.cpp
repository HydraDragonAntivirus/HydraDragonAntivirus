/*++

Module Name:

    ProcessProtection.cpp

Abstract:

    Process protection implementation using ObRegisterCallbacks.
    Detects when external processes attempt to terminate other processes
    by intercepting handle operations with PROCESS_TERMINATE access.
    
    Based on PYAS_Protection Process.c implementation.

Environment:

    Kernel mode

--*/

#include "ProcessProtection.h"
#include "FsFilter.h"
#include "DriverData.h"
#include "Communication.h"
#include <ntstrsafe.h>

// PROCESS_TERMINATE is defined in ntddk.h but may need explicit definition
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

// Declare PsGetProcessImageFileName (not exported in all headers)
extern "C" UCHAR* PsGetProcessImageFileName(PEPROCESS Process);

//
// --- Globals ---
//

static PVOID g_ObRegistrationHandle = NULL;
static POB_CALLBACK_REGISTRATION g_ObReg = NULL;
static POB_OPERATION_REGISTRATION g_OpReg = NULL;

//
// --- Forward Declarations ---
//

OB_PREOP_CALLBACK_STATUS ProcessHandlePreCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
);

NTSTATUS QueueTerminationAttemptToUserMode(
    PEPROCESS AttackerProcess,
    PEPROCESS TargetProcess
);

BOOLEAN IsSystemProcessPP(PEPROCESS Process);

//
// --- Initialization and Cleanup ---
//

NTSTATUS InitProcessProtection()
{
    NTSTATUS status = STATUS_SUCCESS;

    // Safety: ensure called at PASSIVE_LEVEL
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        DbgPrint("!!! ProcessProtection: InitProcessProtection called at wrong IRQL %u\n", (ULONG)KeGetCurrentIrql());
        return STATUS_INVALID_LEVEL;
    }

    // Allocate operation registration (only for process handles)
    g_OpReg = (POB_OPERATION_REGISTRATION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(OB_OPERATION_REGISTRATION), 'ppOr');
    if (!g_OpReg) {
        DbgPrint("!!! ProcessProtection: Failed to allocate operation registration\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_OpReg, sizeof(OB_OPERATION_REGISTRATION));

    g_ObReg = (POB_CALLBACK_REGISTRATION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(OB_CALLBACK_REGISTRATION), 'ppCr');
    if (!g_ObReg) {
        ExFreePoolWithTag(g_OpReg, 'ppOr');
        g_OpReg = NULL;
        DbgPrint("!!! ProcessProtection: Failed to allocate callback registration\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_ObReg, sizeof(OB_CALLBACK_REGISTRATION));

    // Configure operation registration for process handle operations
    g_OpReg[0].ObjectType = PsProcessType;
    g_OpReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OpReg[0].PreOperation = ProcessHandlePreCallback;
    g_OpReg[0].PostOperation = NULL;

    // Configure callback registration
    g_ObReg->Version = ObGetFilterVersion();
    g_ObReg->OperationRegistrationCount = 1;
    g_ObReg->OperationRegistration = g_OpReg;
    g_ObReg->RegistrationContext = NULL;
    // Use a different altitude than PYAS to avoid conflicts
    RtlInitUnicodeString(&g_ObReg->Altitude, L"321100");

    // Register callbacks
    status = ObRegisterCallbacks(g_ObReg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("!!! ProcessProtection: ObRegisterCallbacks failed: 0x%X\n", status);
        ExFreePoolWithTag(g_OpReg, 'ppOr');
        ExFreePoolWithTag(g_ObReg, 'ppCr');
        g_OpReg = NULL;
        g_ObReg = NULL;
        return status;
    }

    DbgPrint("!!! ProcessProtection: ObRegisterCallbacks succeeded\n");
    return STATUS_SUCCESS;
}

VOID UninitProcessProtection()
{
    // Unregister the object callback
    if (g_ObRegistrationHandle) {
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObRegistrationHandle = NULL;
        DbgPrint("!!! ProcessProtection: ObUnRegisterCallbacks completed\n");
    }

    // Free the allocated registration memory
    if (g_OpReg) {
        ExFreePoolWithTag(g_OpReg, 'ppOr');
        g_OpReg = NULL;
    }
    if (g_ObReg) {
        ExFreePoolWithTag(g_ObReg, 'ppCr');
        g_ObReg = NULL;
    }

    DbgPrint("!!! ProcessProtection: Unloaded\n");
}

//
// --- Callback Implementation ---
//

OB_PREOP_CALLBACK_STATUS ProcessHandlePreCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // 1. Skip kernel handles - always allow
    if (pOperationInformation->KernelHandle)
        return OB_PREOP_SUCCESS;

    // Safety check - ensure communication is ready
    if (commHandle == NULL || commHandle->CommClosed)
        return OB_PREOP_SUCCESS;

    PEPROCESS currentProc = PsGetCurrentProcess();
    PEPROCESS targetProc = (PEPROCESS)pOperationInformation->Object;

    // 2. Skip self-access - THIS IS THE KEY CHECK
    // If the caller is the same as the target, this is not external termination
    if (currentProc == targetProc)
        return OB_PREOP_SUCCESS;

    HANDLE callerPid = PsGetProcessId(currentProc);
    HANDLE targetPid = PsGetProcessId(targetProc);

    // 3. PID equality check (redundant but safe)
    if (callerPid == targetPid)
        return OB_PREOP_SUCCESS;

    // 4. Skip system processes
    if (IsSystemProcessPP(currentProc))
        return OB_PREOP_SUCCESS;

    // 5. Check if PROCESS_TERMINATE access is being requested
    ACCESS_MASK desiredAccess = 0;
    if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        desiredAccess = pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desiredAccess = pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    }

    // Only interested in termination attempts
    if (!(desiredAccess & PROCESS_TERMINATE))
        return OB_PREOP_SUCCESS;

    // 6. Queue event to usermode (don't block the operation)
    QueueTerminationAttemptToUserMode(currentProc, targetProc);

    // Always allow the operation to proceed - we're just observing
    return OB_PREOP_SUCCESS;
}

//
// --- Helper Functions ---
//

BOOLEAN IsSystemProcessPP(PEPROCESS Process)
{
    HANDLE pid = PsGetProcessId(Process);

    // Check for standard system PIDs (System and Idle)
    if (pid == (HANDLE)4 || pid == (HANDLE)0) {
        return TRUE;
    }

    // Check for critical subsystem processes using the process name
    // PsGetProcessImageFileName is safe (doesn't open handles)
    UCHAR* processName = PsGetProcessImageFileName(Process);

    if (processName) {
        if (_stricmp((char*)processName, "csrss.exe") == 0 ||
            _stricmp((char*)processName, "lsass.exe") == 0 ||
            _stricmp((char*)processName, "services.exe") == 0 ||
            _stricmp((char*)processName, "wininit.exe") == 0 ||
            _stricmp((char*)processName, "smss.exe") == 0 ||
            _stricmp((char*)processName, "System") == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

NTSTATUS QueueTerminationAttemptToUserMode(
    PEPROCESS AttackerProcess,
    PEPROCESS TargetProcess
)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    HANDLE attackerPid = PsGetProcessId(AttackerProcess);
    HANDLE targetPid = PsGetProcessId(TargetProcess);

    // Get GIDs if processes are tracked
    BOOLEAN attackerFound = FALSE;
    BOOLEAN targetFound = FALSE;
    ULONGLONG attackerGid = driverData->GetProcessGid((ULONG)(ULONG_PTR)attackerPid, &attackerFound);
    ULONGLONG targetGid = driverData->GetProcessGid((ULONG)(ULONG_PTR)targetPid, &targetFound);

    // Skip if neither process is tracked by us
    if (!attackerFound && !targetFound)
        return STATUS_SUCCESS;

    // Allocate IRP entry
    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;

    // Set the message fields
    // The "main" PID/GID is the TARGET (the process being terminated)
    newItem->PID = (ULONG)(ULONG_PTR)targetPid;
    newItem->Gid = targetGid;
    newItem->IRP_OP = IRP_PROCESS_TERMINATE_ATTEMPT;
    
    // The attacker info goes in the new fields
    newItem->AttackerPID = (ULONG)(ULONG_PTR)attackerPid;
    newItem->AttackerGid = attackerGid;

    // Try to get target process path for the filepath field
    PUNICODE_STRING targetPath = NULL;
    NTSTATUS status = SeLocateProcessImageName(TargetProcess, &targetPath);
    if (NT_SUCCESS(status) && targetPath && targetPath->Buffer && targetPath->Length > 0) {
        USHORT copyLen = (targetPath->Length < MAX_FILE_NAME_SIZE) 
            ? targetPath->Length 
            : (MAX_FILE_NAME_SIZE - sizeof(WCHAR));
        RtlCopyMemory(newEntry->Buffer, targetPath->Buffer, copyLen);
        newEntry->Buffer[copyLen / sizeof(WCHAR)] = L'\0';
        newEntry->filePath.Length = copyLen;
        newEntry->filePath.MaximumLength = MAX_FILE_NAME_SIZE;
        newEntry->filePath.Buffer = newEntry->Buffer;
        ExFreePool(targetPath);
    } else {
        // No path available, use empty string
        newEntry->Buffer[0] = L'\0';
        newEntry->filePath.Length = 0;
        newEntry->filePath.MaximumLength = MAX_FILE_NAME_SIZE;
        newEntry->filePath.Buffer = newEntry->Buffer;
    }

    DbgPrint("!!! ProcessProtection: Termination attempt detected - Attacker PID %d (GID %llu) -> Target PID %d (GID %llu)\n",
        (ULONG)(ULONG_PTR)attackerPid, attackerGid, 
        (ULONG)(ULONG_PTR)targetPid, targetGid);

    // Add to IRP queue
    if (!driverData->AddIrpMessage(newEntry)) {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}
