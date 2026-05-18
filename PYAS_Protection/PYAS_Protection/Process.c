// Process.c - Process & Thread protection with PID tracking and system process
#include "Driver.h"
#include "Driver_Process.h"
#include "Driver_Common.h" // Include common helpers
#include "ProtectionRules.h"

//
// --- Globals ---
//

LIST_ENTRY g_ProtectedPidsList;
KSPIN_LOCK g_ProtectedPidsLock;
PVOID g_ObRegistrationHandle = NULL;

// Globals for registration structures (static to manage lifespan)
static POB_CALLBACK_REGISTRATION g_ObReg = NULL;
static POB_OPERATION_REGISTRATION g_OpReg = NULL;

static BOOLEAN g_ProtectedPidTrackingInitialized = FALSE;

static GENERIC_MAPPING g_ProcessGenericMapping =
{
    0x21410,            // GenericRead
    0x20BEA,            // GenericWrite
    0x121001,           // GenericExecute
    PROCESS_ALL_ACCESS  // GenericAll
};

static GENERIC_MAPPING g_ThreadGenericMapping =
{
    STANDARD_RIGHTS_READ | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
    STANDARD_RIGHTS_WRITE | THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_ALERT |
        THREAD_SET_INFORMATION | THREAD_SET_CONTEXT | THREAD_SET_THREAD_TOKEN |
        THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION,
    STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
    THREAD_ALL_ACCESS
};

static ACCESS_MASK ExpandDesiredAccess(_In_ ACCESS_MASK DesiredAccess, _In_ PGENERIC_MAPPING Mapping)
{
    RtlMapGenericMask(&DesiredAccess, Mapping);
    return DesiredAccess;
}

static ACCESS_MASK RestrictProcessAccessLikeOpenEdr(_In_ ACCESS_MASK DesiredAccess)
{
    ACCESS_MASK expandedAccess = ExpandDesiredAccess(DesiredAccess, &g_ProcessGenericMapping);

    if ((expandedAccess & PROCESS_DANGEROUS_MASK) == 0)
        return DesiredAccess;

    ACCESS_MASK restrictedAccess = expandedAccess & ~PROCESS_DANGEROUS_MASK;
    if (restrictedAccess == 0)
        restrictedAccess = PROCESS_QUERY_LIMITED_INFORMATION;

    return restrictedAccess;
}

static ACCESS_MASK RestrictThreadAccessLikeOpenEdr(_In_ ACCESS_MASK DesiredAccess)
{
    ACCESS_MASK expandedAccess = ExpandDesiredAccess(DesiredAccess, &g_ThreadGenericMapping);

    if ((expandedAccess & THREAD_DANGEROUS_MASK) == 0)
        return DesiredAccess;

    ACCESS_MASK restrictedAccess = expandedAccess & ~THREAD_DANGEROUS_MASK;
    if (restrictedAccess == 0)
        restrictedAccess = THREAD_QUERY_LIMITED_INFORMATION;

    return restrictedAccess;
}

static BOOLEAN IsProtectedProcessByPidEx(_In_ HANDLE ProcessId, _Out_opt_ PHANDLE ParentProcessId);
static BOOLEAN IsProtectedProcessByPidOrPath(_In_ HANDLE ProcessId, _In_ PEPROCESS Process, _Out_opt_ PHANDLE ParentProcessId);
static BOOLEAN IsParentChildAccess(_In_ HANDLE CallerPid, _In_opt_ HANDLE DuplicateTargetPid, _In_opt_ HANDLE TargetParentPid);


//
// --- Driver Entry and Unload ---
//

NTSTATUS ProcessDriverEntry() {
    NTSTATUS status = ProtectProcess();
    if (NT_SUCCESS(status)) {
        DbgPrint("[Process-Protection] Initialized successfully\r\n");
    }
    else {
        DbgPrint("[Process-Protection] Failed to initialize: 0x%X\r\n", status);
    }
    return status;
}

NTSTATUS ProcessDriverUnload() {
    // Unregister the object callback first
    if (g_ObRegistrationHandle) {
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObRegistrationHandle = NULL;
    }

    // Unregister the process creation notification routine
    // The second parameter TRUE indicates removal of the routine.
    PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);

    // Free the allocated registration memory (prevent pool leak)
    if (g_OpReg) {
        ExFreePoolWithTag(g_OpReg, 'gOpR');
        g_OpReg = NULL;
    }
    if (g_ObReg) {
        ExFreePoolWithTag(g_ObReg, 'gObR');
        g_ObReg = NULL;
    }

    g_ProtectedPidTrackingInitialized = FALSE;

    // Clean up the protected PID list
    KLOCK_QUEUE_HANDLE lockHandle;
    // DriverUnload is at PASSIVE_LEVEL, so this is safe.
    KeAcquireInStackQueuedSpinLock(&g_ProtectedPidsLock, &lockHandle);

    while (!IsListEmpty(&g_ProtectedPidsList)) {
        PLIST_ENTRY pEntry = RemoveHeadList(&g_ProtectedPidsList);
        PPROTECTED_PID_ENTRY pPidEntry = CONTAINING_RECORD(pEntry, PROTECTED_PID_ENTRY, ListEntry);
        ExFreePoolWithTag(pPidEntry, PID_LIST_TAG);
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);

    // Release dynamically loaded rules
    CleanupProtectionRules();

    DbgPrint("[Process-Protection] Unloaded\r\n");
    return STATUS_SUCCESS;
}

//
// --- Initialization ---
//

NTSTATUS ProtectProcess(void)
{
    NTSTATUS status = STATUS_SUCCESS;

    // DO NOT call InitializeProtectionRules() here.
    // Dynamic rules are pushed by the user-mode service through
    // IOCTL_HYDRADRAGON_SET_RULES. This keeps DriverEntry and callbacks free
    // from synchronous disk I/O.

    // Safety: ensure called at PASSIVE_LEVEL
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        DbgPrint("ProtectProcess: wrong IRQL %u\n", (ULONG)KeGetCurrentIrql());
        return STATUS_INVALID_LEVEL;
    }

    // Init list/spinlock
    InitializeListHead(&g_ProtectedPidsList);
    KeInitializeSpinLock(&g_ProtectedPidsLock);
    g_ProtectedPidTrackingInitialized = TRUE;

    // Register process notify
    // The second parameter FALSE indicates registration.
    status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Process-Protection] PsSetCreateProcessNotifyRoutineEx failed: 0x%X\n", status);
        return status;
    }

    // Allocate heap registrations
    g_OpReg = (POB_OPERATION_REGISTRATION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(OB_OPERATION_REGISTRATION) * 2, 'gOpR');
    if (!g_OpReg) {
        // Cleanup on failure
        PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_ObReg = (POB_CALLBACK_REGISTRATION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(OB_CALLBACK_REGISTRATION), 'gObR');
    if (!g_ObReg) {
        // Cleanup on failure
        ExFreePoolWithTag(g_OpReg, 'gOpR');
        g_OpReg = NULL;
        PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Fill g_OpReg: Operation 0 - Process Handle Operations
    g_OpReg[0].ObjectType = PsProcessType;
    g_OpReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OpReg[0].PreOperation = preCall;
    g_OpReg[0].PostOperation = NULL;

    // Fill g_OpReg: Operation 1 - Thread Handle Operations
    g_OpReg[1].ObjectType = PsThreadType;
    g_OpReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OpReg[1].PreOperation = threadPreCall;
    g_OpReg[1].PostOperation = NULL;

    // Fill g_ObReg
    g_ObReg->Version = ObGetFilterVersion();
    g_ObReg->OperationRegistrationCount = 2;
    g_ObReg->OperationRegistration = g_OpReg;
    g_ObReg->RegistrationContext = NULL;
    RtlInitUnicodeString(&g_ObReg->Altitude, L"321000");

    // Register callbacks
    status = ObRegisterCallbacks(g_ObReg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Process-Protection] ObRegisterCallbacks failed: 0x%X\n", status);
        // Cleanup on failure
        ExFreePoolWithTag(g_OpReg, 'gOpR');
        ExFreePoolWithTag(g_ObReg, 'gObR');
        g_OpReg = NULL;
        g_ObReg = NULL;
        PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
        return status;
    }

    DbgPrint("[Process-Protection] ObRegisterCallbacks succeeded\n");
    return STATUS_SUCCESS;
}

//
// --- Core Protection Logic ---
//

// NOTIFICATION ROUTINE: Called on every process creation and exit.
VOID CreateProcessNotifyRoutine(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    if (CreateInfo) { // Process is starting
        if (IsProtectedProcessByPath(Process)) {
            PPROTECTED_PID_ENTRY pNewEntry = ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeof(PROTECTED_PID_ENTRY), PID_LIST_TAG
            );

            if (pNewEntry) {
                pNewEntry->ProcessId = ProcessId;
                pNewEntry->ParentProcessId = CreateInfo->ParentProcessId;

                KLOCK_QUEUE_HANDLE lockHandle;
                KeAcquireInStackQueuedSpinLock(&g_ProtectedPidsLock, &lockHandle);
                InsertTailList(&g_ProtectedPidsList, &pNewEntry->ListEntry);
                KeReleaseInStackQueuedSpinLock(&lockHandle);

                DbgPrint("[Process-Protection] Protected process started: PID %llu\r\n",
                    (unsigned long long)(ULONG_PTR)ProcessId);
            }
        }
    }
    else { // Process is exiting
        KLOCK_QUEUE_HANDLE lockHandle;
        KeAcquireInStackQueuedSpinLock(&g_ProtectedPidsLock, &lockHandle);

        PLIST_ENTRY pCurrent = g_ProtectedPidsList.Flink;
        while (pCurrent != &g_ProtectedPidsList) {
            PPROTECTED_PID_ENTRY pEntry = CONTAINING_RECORD(pCurrent, PROTECTED_PID_ENTRY, ListEntry);
            PLIST_ENTRY pNext = pCurrent->Flink; // Save next pointer before removal

            if (pEntry->ProcessId == ProcessId) {
                RemoveEntryList(&pEntry->ListEntry);
                ExFreePoolWithTag(pEntry, PID_LIST_TAG);
                DbgPrint("[Process-Protection] Protected process terminated: PID %llu\r\n",
                    (unsigned long long)(ULONG_PTR)ProcessId);
                // Exit loop since we found and removed the entry
                break;
            }
            pCurrent = pNext;
        }

        KeReleaseInStackQueuedSpinLock(&lockHandle);
    }
}

// CALLBACK: Intercepts process handle operations (improved - preserves resume bits)
OB_PREOP_CALLBACK_STATUS preCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // 1. Kernel Handle Check: Always allow kernel-mode requests first.
    if (pOperationInformation->KernelHandle)
        return OB_PREOP_SUCCESS;

    PEPROCESS currentProc = PsGetCurrentProcess();
    PEPROCESS targetProc = (PEPROCESS)pOperationInformation->Object;

    // 2. POINTER EQUALITY CHECK
    if (currentProc == targetProc)
        return OB_PREOP_SUCCESS;

    HANDLE callerPid = PsGetProcessId(currentProc);
    HANDLE targetPid = PsGetProcessId(targetProc);

    PACCESS_MASK desiredAccess = NULL;
    HANDLE duplicateTargetPid = NULL;

    if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
    {
        desiredAccess = &pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    }
    else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
    {
        desiredAccess = &pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        if (pOperationInformation->Parameters->DuplicateHandleInformation.TargetProcess)
        {
            duplicateTargetPid = PsGetProcessId((PEPROCESS)pOperationInformation->Parameters->DuplicateHandleInformation.TargetProcess);
        }
    }
    else
    {
        return OB_PREOP_SUCCESS;
    }

    // 3. PID EQUALITY CHECK
    if (callerPid == targetPid)
        return OB_PREOP_SUCCESS;

    // 4. SYSTEM PROCESS CHECK
    // Must be done WITHOUT opening handles to avoid recursion.
    // Only PID 0/4 bypass protection.
    if (IsSystemProcess(currentProc))
        return OB_PREOP_SUCCESS;

    HANDLE targetParentPid = NULL;
    BOOLEAN targetIsProtected = IsProtectedProcessByPidOrPath(targetPid, targetProc, &targetParentPid);

    // If the target is not protected, leave normal processing
    if (!targetIsProtected)
        return OB_PREOP_SUCCESS;

    // OpenEDR allows parent-to-child process access.
    if (IsParentChildAccess(callerPid, duplicateTargetPid, targetParentPid))
        return OB_PREOP_SUCCESS;

    // Product/protected processes keep their originally requested access.
    if (IsProtectedProcessByPidOrPath(callerPid, currentProc, NULL))
        return OB_PREOP_SUCCESS;

    ACCESS_MASK originalAccess = *desiredAccess;
    ACCESS_MASK restrictedAccess = RestrictProcessAccessLikeOpenEdr(originalAccess);

    if (restrictedAccess != originalAccess)
    {
        QueueProcessAlertToUserMode(targetProc, currentProc, L"PROCESS_ACCESS_BLOCKED");
        *desiredAccess = restrictedAccess;
    }

    return OB_PREOP_SUCCESS;
}


OB_PREOP_CALLBACK_STATUS threadPreCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // 1. Kernel Handle Check
    if (pOperationInformation->KernelHandle)
        return OB_PREOP_SUCCESS;

    PEPROCESS currentProc = PsGetCurrentProcess();

    HANDLE callerPid = PsGetProcessId(currentProc);

    PETHREAD targetThread = (PETHREAD)pOperationInformation->Object;
    PEPROCESS targetProc = PsGetThreadProcess(targetThread);

    if (!targetProc)
        return OB_PREOP_SUCCESS;

    HANDLE targetPid = PsGetProcessId(targetProc);

    PACCESS_MASK desiredAccess = NULL;
    HANDLE duplicateTargetPid = NULL;

    if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
    {
        desiredAccess = &pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    }
    else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
    {
        desiredAccess = &pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        if (pOperationInformation->Parameters->DuplicateHandleInformation.TargetProcess)
        {
            duplicateTargetPid = PsGetProcessId((PEPROCESS)pOperationInformation->Parameters->DuplicateHandleInformation.TargetProcess);
        }
    }
    else
    {
        return OB_PREOP_SUCCESS;
    }

    // 2. SELF-ACCESS CHECK
    if (callerPid == targetPid)
        return OB_PREOP_SUCCESS;

    // 3. SYSTEM PROCESS CHECK
    if (IsSystemProcess(currentProc))
        return OB_PREOP_SUCCESS;

    HANDLE targetParentPid = NULL;
    BOOLEAN targetIsProtected = IsProtectedProcessByPidOrPath(targetPid, targetProc, &targetParentPid);

    if (!targetIsProtected)
        return OB_PREOP_SUCCESS;

    if (IsParentChildAccess(callerPid, duplicateTargetPid, targetParentPid))
        return OB_PREOP_SUCCESS;

    if (IsProtectedProcessByPidOrPath(callerPid, currentProc, NULL))
        return OB_PREOP_SUCCESS;

    ACCESS_MASK originalAccess = *desiredAccess;
    ACCESS_MASK restrictedAccess = RestrictThreadAccessLikeOpenEdr(originalAccess);

    if (restrictedAccess != originalAccess)
    {
        QueueProcessAlertToUserMode(targetProc, currentProc, L"THREAD_ACCESS_BLOCKED");
        *desiredAccess = restrictedAccess;
    }

    return OB_PREOP_SUCCESS;
}

//
// --- Helper Functions ---
//

static BOOLEAN IsProtectedProcessByPidEx(_In_ HANDLE ProcessId, _Out_opt_ PHANDLE ParentProcessId)
{
    BOOLEAN isProtected = FALSE;

    if (ParentProcessId)
        *ParentProcessId = NULL;

    if (!g_ProtectedPidTrackingInitialized)
        return FALSE;

    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_ProtectedPidsLock, &lockHandle);

    PLIST_ENTRY pCurrent = g_ProtectedPidsList.Flink;
    while (pCurrent != &g_ProtectedPidsList) {
        PPROTECTED_PID_ENTRY pEntry = CONTAINING_RECORD(pCurrent, PROTECTED_PID_ENTRY, ListEntry);
        if (pEntry->ProcessId == ProcessId) {
            isProtected = TRUE;
            if (ParentProcessId)
                *ParentProcessId = pEntry->ParentProcessId;
            break;
        }
        pCurrent = pCurrent->Flink;
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return isProtected;
}

// CHECKS: Checks if a PID is in our protected list. (Fast)
BOOLEAN IsProtectedProcessByPid(HANDLE ProcessId) {
    return IsProtectedProcessByPidEx(ProcessId, NULL);
}

static BOOLEAN IsProtectedProcessByPidOrPath(_In_ HANDLE ProcessId, _In_ PEPROCESS Process, _Out_opt_ PHANDLE ParentProcessId)
{
    if (IsProtectedProcessByPidEx(ProcessId, ParentProcessId))
        return TRUE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return FALSE;

    return IsProtectedProcessByPath(Process);
}

static BOOLEAN IsParentChildAccess(_In_ HANDLE CallerPid, _In_opt_ HANDLE DuplicateTargetPid, _In_opt_ HANDLE TargetParentPid)
{
    if (!TargetParentPid)
        return FALSE;

    return (TargetParentPid == CallerPid) ||
           (DuplicateTargetPid && TargetParentPid == DuplicateTargetPid);
}

// CHECKS: Checks if a process path is one we should protect.
BOOLEAN IsProtectedProcessByPath(PEPROCESS Process) {
    PUNICODE_STRING pImageName = NULL;
    NTSTATUS status;
    BOOLEAN result = FALSE;

    status = SeLocateProcessImageName(Process, &pImageName);
    if (!NT_SUCCESS(status) || !pImageName) {
        return FALSE;
    }

    // Normalize from \Device\HarddiskVolumeX to \??\C: before checking rules
    NormalizeDevicePathToDos(pImageName);

    // Delegate protection decision to the dynamic rule engine
    result = IsPathProtectedByType(pImageName->Buffer, RuleTypeProcess);

    if (pImageName) {
        ExFreePool(pImageName);
    }
    return result;
}

BOOLEAN IsSystemProcess(PEPROCESS Process)
{
    if (!Process)
        return FALSE;

    HANDLE pid = PsGetProcessId(Process);
    return (pid == (HANDLE)4 || pid == (HANDLE)0);
}



//
// IsProcessTrusted
//
// Kernel/system pseudo-processes are the only caller trust bypass.
//
BOOLEAN IsProcessTrusted(_In_ HANDLE ProcessId)
{
    return (ProcessId == (HANDLE)0 || ProcessId == (HANDLE)4);
}



// Case-insensitive check to see if 'Source' string ENDS WITH 'Pattern'.
BOOLEAN UnicodeStringEndsWithInsensitive(PUNICODE_STRING Source, PCWSTR Pattern) {
    if (!Source || !Source->Buffer || !Pattern) return FALSE;

    UNICODE_STRING patternString;
    RtlInitUnicodeString(&patternString, Pattern);

    if (Source->Length < patternString.Length) return FALSE;

    // Create a temporary UNICODE_STRING for the suffix of the source string
    UNICODE_STRING sourceSuffix;
    sourceSuffix.Length = patternString.Length;
    sourceSuffix.MaximumLength = patternString.Length;
    sourceSuffix.Buffer = (PWCH)((PCHAR)Source->Buffer + Source->Length - patternString.Length);

    // Compare case-insensitively
    return (RtlCompareUnicodeString(&sourceSuffix, &patternString, TRUE) == 0);
}

//
// --- User-Mode Alerting ---
//

NTSTATUS QueueProcessAlertToUserMode(
    PEPROCESS TargetProcess,
    PEPROCESS AttackerProcess,
    PCWSTR AttackType
)
{
    PPROCESS_ALERT_WORK_ITEM workItem;
    PUNICODE_STRING targetPath = NULL;
    PUNICODE_STRING attackerPath = NULL;
    NTSTATUS status;

    // Allocate work item
    workItem = (PPROCESS_ALERT_WORK_ITEM)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(PROCESS_ALERT_WORK_ITEM),
        'crpA'
    );

    if (!workItem)
        return STATUS_INSUFFICIENT_RESOURCES;


    // Get process paths
    status = SeLocateProcessImageName(TargetProcess, &targetPath);
    if (NT_SUCCESS(status) && targetPath && targetPath->Buffer && targetPath->Length > 0)
    {
        workItem->TargetPath.Length = targetPath->Length;
        workItem->TargetPath.MaximumLength = targetPath->Length + sizeof(WCHAR);
        workItem->TargetPath.Buffer = (PWCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            workItem->TargetPath.MaximumLength,
            'crpA'
        );

        if (workItem->TargetPath.Buffer)
        {
            RtlCopyMemory(workItem->TargetPath.Buffer, targetPath->Buffer, targetPath->Length);
            workItem->TargetPath.Buffer[targetPath->Length / sizeof(WCHAR)] = L'\0';

            // Normalize path for user-mode reporting
            UNICODE_STRING uTarget;
            uTarget.Buffer = workItem->TargetPath.Buffer;
            uTarget.Length = workItem->TargetPath.Length;
            uTarget.MaximumLength = workItem->TargetPath.MaximumLength;
            NormalizeDevicePathToDos(&uTarget);
            workItem->TargetPath.Length = uTarget.Length;
        }
    }

    status = SeLocateProcessImageName(AttackerProcess, &attackerPath);
    if (NT_SUCCESS(status) && attackerPath && attackerPath->Buffer && attackerPath->Length > 0)
    {
        workItem->AttackerPath.Length = attackerPath->Length;
        workItem->AttackerPath.MaximumLength = attackerPath->Length + sizeof(WCHAR);
        workItem->AttackerPath.Buffer = (PWCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            workItem->AttackerPath.MaximumLength,
            'crpA'
        );

        if (workItem->AttackerPath.Buffer)
        {
            RtlCopyMemory(workItem->AttackerPath.Buffer, attackerPath->Buffer, attackerPath->Length);
            workItem->AttackerPath.Buffer[attackerPath->Length / sizeof(WCHAR)] = L'\0';

            // Normalize path for user-mode reporting
            UNICODE_STRING uAttacker;
            uAttacker.Buffer = workItem->AttackerPath.Buffer;
            uAttacker.Length = workItem->AttackerPath.Length;
            uAttacker.MaximumLength = workItem->AttackerPath.MaximumLength;
            NormalizeDevicePathToDos(&uAttacker);
            workItem->AttackerPath.Length = uAttacker.Length;
        }
    }

    // Free the allocated paths from SeLocateProcessImageName
    if (targetPath)   ExFreePool(targetPath);
    if (attackerPath) ExFreePool(attackerPath);

    // Copy PIDs and attack type
    workItem->TargetPid = PsGetProcessId(TargetProcess);
    workItem->AttackerPid = PsGetProcessId(AttackerProcess);
    // RtlStringCbCopyW ensures null termination within bounds
    RtlStringCbCopyW(workItem->AttackType, sizeof(workItem->AttackType), AttackType);

    // Queue work item
#pragma warning(suppress: 4996)
    ExInitializeWorkItem(&workItem->WorkItem, ProcessAlertWorker, workItem);
#pragma warning(suppress: 4996)
    ExQueueWorkItem(&workItem->WorkItem, DelayedWorkQueue);

    return STATUS_SUCCESS;
}


VOID ProcessAlertWorker(PVOID Context)
{
    PPROCESS_ALERT_WORK_ITEM workItem = (PPROCESS_ALERT_WORK_ITEM)Context;
    NTSTATUS status;
    WCHAR messageBuffer[2048];
    WCHAR escapedTarget[512];
    WCHAR escapedAttacker[512];

    if (!workItem)
        return;

    // Use safe pointer checks
    PCWSTR targetName = workItem->TargetPath.Buffer ? workItem->TargetPath.Buffer : L"Unknown";
    PCWSTR attackerName = workItem->AttackerPath.Buffer ? workItem->AttackerPath.Buffer : L"Unknown";

    // Escape the paths for valid JSON
    if (!EscapeJsonString(escapedTarget, sizeof(escapedTarget), targetName)) {
        RtlStringCbCopyW(escapedTarget, sizeof(escapedTarget), L"ErrorEscapingPath");
    }
    if (!EscapeJsonString(escapedAttacker, sizeof(escapedAttacker), attackerName)) {
        RtlStringCbCopyW(escapedAttacker, sizeof(escapedAttacker), L"ErrorEscapingPath");
    }

    // Build JSON message
    RtlZeroMemory(messageBuffer, sizeof(messageBuffer));
    // NOTE: Using the escaped strings now
    status = RtlStringCbPrintfW(
        messageBuffer,
        sizeof(messageBuffer),
        L"{\"source\":\"simplepyas\",\"category\":\"process\",\"action\":\"blocked\",\"protected_file\":\"%ws\",\"attacker_path\":\"%ws\",\"attacker_pid\":%llu,\"attack_type\":\"%ws\",\"target_pid\":%llu}",
        escapedTarget,
        escapedAttacker,
        (unsigned long long)(ULONG_PTR)workItem->AttackerPid,
        workItem->AttackType,
        (unsigned long long)(ULONG_PTR)workItem->TargetPid
    );

    if (NT_SUCCESS(status))
    {
        SIZE_T messageLength = wcslen(messageBuffer) * sizeof(WCHAR);
        status = SendAlertToPipe(messageBuffer, messageLength);

        if (!NT_SUCCESS(status))
        {
            DbgPrint("[Process-Protection] Failed to send alert: 0x%X\r\n", status);
        }
    }
    else
    {
        DbgPrint("[Process-Protection] Failed to format alert: 0x%X\r\n", status);
    }

    // Free allocated strings
    if (workItem->TargetPath.Buffer)   ExFreePool(workItem->TargetPath.Buffer);
    if (workItem->AttackerPath.Buffer) ExFreePool(workItem->AttackerPath.Buffer);

    ExFreePoolWithTag(workItem, 'crpA');
}
