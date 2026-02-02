/*++

Module Name:

    ProcessProtection.cpp

Abstract:

    Comprehensive process protection implementation using ObRegisterCallbacks and
    kernel-level API hooks. Detects all process-related events:
    - Process creation
    - Process termination attempts
    - Process exit/cleanup
    - Process handle operations
    - Kernel API injection attempts

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

// Process-related access rights
#define PROCESS_CREATE_PROCESS 0x0080
#define PROCESS_CREATE_THREAD 0x0002
#define PROCESS_VM_WRITE 0x0020
#define PROCESS_VM_READ 0x0010
#ifndef PROCESS_ALL_ACCESS
#define PROCESS_ALL_ACCESS 0x001FFFFF
#endif

// Declare PsGetProcessImageFileName (not exported in all headers)
extern "C" UCHAR* PsGetProcessImageFileName(PEPROCESS Process);

//
// --- Globals for ObRegisterCallbacks ---
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

    // 2. Skip self-access - REMOVED to allow behavior engine to decide
    // If the caller is the same as the target, this is self-termination
    /*
    if (currentProc == targetProc)
        return OB_PREOP_SUCCESS;
    */

    // 3. PID equality check (redundant but safe) - REMOVED
    /*
    if (callerPid == targetPid)
        return OB_PREOP_SUCCESS;
    */

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
//
// --- New Event Detection Functions for Comprehensive Process Monitoring ---
//

NTSTATUS OnProcessCreate(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId
)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
    ULONG parentPid = (ULONG)(ULONG_PTR)ParentProcessId;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;
    newItem->PID = pid;
    newItem->ParentPid = parentPid;
    newItem->IRP_OP = IRP_PROCESS_CREATE;

    BOOLEAN found = FALSE;
    newItem->Gid = driverData->GetProcessGid(pid, &found);

    DbgPrint("!!! ProcessProtection: Process created - PID %lu (Parent: %lu, GID: %llu)\n",
        pid, parentPid, newItem->Gid);

    if (!driverData->AddIrpMessage(newEntry)) {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS OnProcessExit(
    _In_ HANDLE ProcessId
)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;
    newItem->PID = pid;
    newItem->IRP_OP = IRP_PROCESS_EXIT;

    BOOLEAN found = FALSE;
    newItem->Gid = driverData->GetProcessGid(pid, &found);

    DbgPrint("!!! ProcessProtection: Process exited - PID %lu (GID: %llu)\n",
        pid, newItem->Gid);

    if (!driverData->AddIrpMessage(newEntry)) {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS OnProcessHandleOperation(
    _In_ HANDLE CallerProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ UCHAR OperationType
)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    ULONG callerPid = (ULONG)(ULONG_PTR)CallerProcessId;
    ULONG targetPid = (ULONG)(ULONG_PTR)TargetProcessId;

    // Get GIDs if processes are tracked
    BOOLEAN callerFound = FALSE;
    BOOLEAN targetFound = FALSE;
    ULONGLONG callerGid = driverData->GetProcessGid(callerPid, &callerFound);
    ULONGLONG targetGid = driverData->GetProcessGid(targetPid, &targetFound);

    // Skip if neither process is tracked
    if (!callerFound && !targetFound)
        return STATUS_SUCCESS;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;
    newItem->PID = targetPid;
    newItem->Gid = targetGid;
    newItem->AttackerPID = callerPid;
    newItem->AttackerGid = callerGid;
    newItem->IRP_OP = IRP_PROCESS_HANDLE_OPEN;

    // Store access mask and operation type in KernelEventInfo
    newItem->KernelEventInfo.AccessMask = DesiredAccess;
    newItem->KernelEventInfo.SourceProcessId = callerPid;
    newItem->KernelEventInfo.TargetProcessId = targetPid;

    DbgPrint("!!! ProcessProtection: Process handle opened - Caller PID %lu -> Target PID %lu (Access: 0x%X, Op: %u)\n",
        callerPid, targetPid, DesiredAccess, OperationType);

    if (!driverData->AddIrpMessage(newEntry)) {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS OnProcessTerminationAttempt(
    _In_ HANDLE AttackerPid,
    _In_ HANDLE TargetPid
)
{
    // Delegate to existing function
    return QueueTerminationAttemptToUserMode((PEPROCESS)AttackerPid, (PEPROCESS)TargetPid);
}

//
// --- Kernel API Hook Integration Functions ---
//

NTSTATUS OnKernelApiEvent(
    _In_ ULONG EventType,
    _In_ ULONG SourcePid,
    _In_ ULONG TargetPid,
    _In_opt_ PVOID EventData
)
{
    UNREFERENCED_PARAMETER(EventData);
    
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    BOOLEAN sourceFound = FALSE;
    BOOLEAN targetFound = FALSE;
    ULONGLONG sourceGid = driverData->GetProcessGid(SourcePid, &sourceFound);
    ULONGLONG targetGid = driverData->GetProcessGid(TargetPid, &targetFound);

    // Skip if neither process is tracked
    if (!sourceFound && !targetFound)
        return STATUS_SUCCESS;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;
    newItem->PID = TargetPid;
    newItem->Gid = targetGid;
    newItem->AttackerPID = SourcePid;
    newItem->AttackerGid = sourceGid;
    newItem->IRP_OP = (UCHAR)EventType;

    // Store event type
    newItem->KernelEventInfo.EventType = EventType;
    newItem->KernelEventInfo.SourceProcessId = SourcePid;
    newItem->KernelEventInfo.TargetProcessId = TargetPid;

    DbgPrint("!!! ProcessProtection: Kernel API event detected - Type: %lu, Source PID: %lu, Target PID: %lu\n",
        EventType, SourcePid, TargetPid);

    if (!driverData->AddIrpMessage(newEntry)) {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS OnMemoryWrite(
    _In_ ULONG SourcePid,
    _In_ ULONG TargetPid,
    _In_ PVOID TargetAddress,
    _In_ SIZE_T Size,
    _In_ BOOLEAN IsExecutableMemory
)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    BOOLEAN sourceFound = FALSE;
    BOOLEAN targetFound = FALSE;
    ULONGLONG sourceGid = driverData->GetProcessGid(SourcePid, &sourceFound);
    ULONGLONG targetGid = driverData->GetProcessGid(TargetPid, &targetFound);

    if (!sourceFound && !targetFound)
        return STATUS_SUCCESS;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;
    newItem->PID = TargetPid;
    newItem->Gid = targetGid;
    newItem->AttackerPID = SourcePid;
    newItem->AttackerGid = sourceGid;
    newItem->IRP_OP = IRP_KERNEL_WRITE_MEMORY;

    newItem->KernelEventInfo.EventType = IRP_KERNEL_WRITE_MEMORY;
    newItem->KernelEventInfo.SourceProcessId = SourcePid;
    newItem->KernelEventInfo.TargetProcessId = TargetPid;
    newItem->KernelEventInfo.MemoryAddress = TargetAddress;
    newItem->KernelEventInfo.MemorySize = Size;
    newItem->KernelEventInfo.IsExecutableMemory = IsExecutableMemory;

    DbgPrint("!!! ProcessProtection: Memory write detected - Source PID %lu -> Target PID %lu (Address: %p, Size: %zu, Executable: %u)\n",
        SourcePid, TargetPid, TargetAddress, Size, IsExecutableMemory);

    if (!driverData->AddIrpMessage(newEntry)) {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS OnMemoryProtectionChange(
    _In_ ULONG SourcePid,
    _In_ ULONG TargetPid,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _In_ ULONG OldProtection
)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    BOOLEAN sourceFound = FALSE;
    BOOLEAN targetFound = FALSE;
    ULONGLONG sourceGid = driverData->GetProcessGid(SourcePid, &sourceFound);
    ULONGLONG targetGid = driverData->GetProcessGid(TargetPid, &targetFound);

    if (!sourceFound && !targetFound)
        return STATUS_SUCCESS;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;
    newItem->PID = TargetPid;
    newItem->Gid = targetGid;
    newItem->AttackerPID = SourcePid;
    newItem->AttackerGid = sourceGid;
    newItem->IRP_OP = IRP_KERNEL_PROTECT_MEMORY;

    newItem->KernelEventInfo.EventType = IRP_KERNEL_PROTECT_MEMORY;
    newItem->KernelEventInfo.SourceProcessId = SourcePid;
    newItem->KernelEventInfo.TargetProcessId = TargetPid;
    newItem->KernelEventInfo.MemoryAddress = BaseAddress;
    newItem->KernelEventInfo.MemorySize = RegionSize;
    newItem->KernelEventInfo.MemoryProtection = NewProtection;
    newItem->KernelEventInfo.IsExecutableMemory = IsExecutableProtection(NewProtection);

    DbgPrint("!!! ProcessProtection: Memory protection change - Source PID %lu -> Target PID %lu (Old: 0x%X, New: 0x%X, Executable: %u)\n",
        SourcePid, TargetPid, OldProtection, NewProtection, IsExecutableProtection(NewProtection));

    if (!driverData->AddIrpMessage(newEntry)) {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS OnThreadCreation(
    _In_ ULONG SourcePid,
    _In_ ULONG TargetPid,
    _In_ PVOID StartRoutine
)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    BOOLEAN sourceFound = FALSE;
    BOOLEAN targetFound = FALSE;
    ULONGLONG sourceGid = driverData->GetProcessGid(SourcePid, &sourceFound);
    ULONGLONG targetGid = driverData->GetProcessGid(TargetPid, &targetFound);

    if (!sourceFound && !targetFound)
        return STATUS_SUCCESS;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;
    newItem->PID = TargetPid;
    newItem->Gid = targetGid;
    newItem->AttackerPID = SourcePid;
    newItem->AttackerGid = sourceGid;
    newItem->IRP_OP = IRP_KERNEL_CREATE_THREAD;

    newItem->KernelEventInfo.EventType = IRP_KERNEL_CREATE_THREAD;
    newItem->KernelEventInfo.SourceProcessId = SourcePid;
    newItem->KernelEventInfo.TargetProcessId = TargetPid;
    newItem->KernelEventInfo.ThreadStartRoutine = StartRoutine;

    DbgPrint("!!! ProcessProtection: Remote thread creation - Source PID %lu -> Target PID %lu (Start: %p)\n",
        SourcePid, TargetPid, StartRoutine);

    if (!driverData->AddIrpMessage(newEntry)) {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS OnApcQueueing(
    _In_ ULONG SourcePid,
    _In_ ULONG TargetPid,
    _In_ HANDLE ThreadHandle,
    _In_ PVOID ApcRoutine
)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    BOOLEAN sourceFound = FALSE;
    BOOLEAN targetFound = FALSE;
    ULONGLONG sourceGid = driverData->GetProcessGid(SourcePid, &sourceFound);
    ULONGLONG targetGid = driverData->GetProcessGid(TargetPid, &targetFound);

    if (!sourceFound && !targetFound)
        return STATUS_SUCCESS;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;
    newItem->PID = TargetPid;
    newItem->Gid = targetGid;
    newItem->AttackerPID = SourcePid;
    newItem->AttackerGid = sourceGid;
    newItem->IRP_OP = IRP_KERNEL_QUEUE_APC;

    newItem->KernelEventInfo.EventType = IRP_KERNEL_QUEUE_APC;
    newItem->KernelEventInfo.SourceProcessId = SourcePid;
    newItem->KernelEventInfo.TargetProcessId = TargetPid;
    newItem->KernelEventInfo.ThreadHandle = ThreadHandle;
    newItem->KernelEventInfo.ThreadStartRoutine = ApcRoutine;

    DbgPrint("!!! ProcessProtection: APC queued - Source PID %lu -> Target PID %lu (Thread: %p, APC: %p)\n",
        SourcePid, TargetPid, ThreadHandle, ApcRoutine);

    if (!driverData->AddIrpMessage(newEntry)) {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS OnSectionOperation(
    _In_ ULONG SourcePid,
    _In_ ULONG TargetPid,
    _In_opt_ PCWSTR SectionName,
    _In_ UCHAR OperationType
)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    BOOLEAN sourceFound = FALSE;
    BOOLEAN targetFound = FALSE;
    ULONGLONG sourceGid = driverData->GetProcessGid(SourcePid, &sourceFound);
    ULONGLONG targetGid = driverData->GetProcessGid(TargetPid, &targetFound);

    if (!sourceFound && !targetFound)
        return STATUS_SUCCESS;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;
    newItem->PID = TargetPid;
    newItem->Gid = targetGid;
    newItem->AttackerPID = SourcePid;
    newItem->AttackerGid = sourceGid;

    UCHAR irpOp = (OperationType == 1) ? (UCHAR)IRP_KERNEL_CREATE_SECTION : (UCHAR)IRP_KERNEL_MAP_SECTION;
    newItem->IRP_OP = irpOp;

    newItem->KernelEventInfo.EventType = irpOp;
    newItem->KernelEventInfo.SourceProcessId = SourcePid;
    newItem->KernelEventInfo.TargetProcessId = TargetPid;

    if (SectionName != NULL) {
        USHORT copyLen = (USHORT)wcslen(SectionName) * sizeof(WCHAR);
        if (copyLen > (MAX_FILE_NAME_LENGTH - 1) * sizeof(WCHAR))
            copyLen = (MAX_FILE_NAME_LENGTH - 1) * sizeof(WCHAR);
        RtlStringCchCopyW(newItem->KernelEventInfo.ObjectName, MAX_FILE_NAME_LENGTH, SectionName);
    }

    DbgPrint("!!! ProcessProtection: Section operation - Source PID %lu -> Target PID %lu (Type: %u, Name: %ws)\n",
        SourcePid, TargetPid, OperationType, SectionName ? SectionName : L"<unnamed>");

    if (!driverData->AddIrpMessage(newEntry)) {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

//
// --- Helper function for memory protection checking ---
//

static BOOLEAN IsExecutableProtection(ULONG Protect)
{
    return (Protect & PAGE_EXECUTE) ||
           (Protect & PAGE_EXECUTE_READ) ||
           (Protect & PAGE_EXECUTE_READWRITE) ||
           (Protect & PAGE_EXECUTE_WRITECOPY);
}