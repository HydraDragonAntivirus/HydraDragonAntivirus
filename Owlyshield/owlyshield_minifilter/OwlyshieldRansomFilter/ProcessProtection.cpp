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
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif
#ifndef PROCESS_ALL_ACCESS
#define PROCESS_ALL_ACCESS 0x001FFFFF
#endif

// Thread-related access rights (used to infer APC/context abuse without user-mode hooks)
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT 0x0010
#endif
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION 0x0020
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME 0x0002
#endif
#ifndef THREAD_GET_CONTEXT
#define THREAD_GET_CONTEXT 0x0008
#endif

// Declare PsGetProcessImageFileName (not exported in all headers)
extern "C" UCHAR* PsGetProcessImageFileName(PEPROCESS Process);
extern "C" NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(
    _In_ PEPROCESS FromProcess,
    _In_ PVOID FromAddress,
    _In_ PEPROCESS ToProcess,
    _Out_writes_bytes_(BufferSize) PVOID ToAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T NumberOfBytesCopied
);

// Forward declaration for helper function
static BOOLEAN IsExecutableProtection(ULONG Protect);
static BOOLEAN IsExecutableProtectionMask(ULONG Protect);
static VOID EmitProcessHandleIntentEvents(_In_ ULONG CallerPid, _In_ ULONG TargetPid, _In_ ACCESS_MASK DesiredAccess);
static VOID EmitThreadHandleIntentEvents(
    _In_ ULONG CallerPid,
    _In_ ULONG TargetPid,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE ThreadHandle
);
static VOID AssemblyScanWorker(_In_ PVOID StartContext);
static VOID DrainAssemblyScanQueue(VOID);
static VOID ProcessAssemblyScanTask(_In_ ULONG SourcePid, _In_ ULONG TargetPid, _In_ ACCESS_MASK ReasonMask);
static ULONG DetectAssemblySignatureFlags(_In_reads_bytes_(BufferSize) const UCHAR* Buffer, _In_ SIZE_T BufferSize);
static NTSTATUS CopyProcessBytesSafe(
    _In_ PEPROCESS SourceProcess,
    _In_ PVOID SourceAddress,
    _Out_writes_bytes_(DestinationSize) PUCHAR Destination,
    _In_ SIZE_T DestinationSize,
    _Out_ PSIZE_T BytesCopied
);

//
// --- Globals for ObRegisterCallbacks ---
//

static PVOID g_ObRegistrationHandle = NULL;
static POB_CALLBACK_REGISTRATION g_ObReg = NULL;
static POB_OPERATION_REGISTRATION g_OpReg = NULL;

typedef struct _ASSEMBLY_SCAN_TASK {
    LIST_ENTRY Entry;
    ULONG SourcePid;
    ULONG TargetPid;
    ACCESS_MASK ReasonMask;
} ASSEMBLY_SCAN_TASK, *PASSEMBLY_SCAN_TASK;

static LIST_ENTRY g_AssemblyScanQueue;
static KSPIN_LOCK g_AssemblyScanQueueLock;
static KEVENT g_AssemblyScanEvent;
static HANDLE g_AssemblyScanThreadHandle = NULL;
static volatile LONG g_AssemblyScanStop = 0;
static volatile LONG g_AssemblyScanQueueDepth = 0;

#define OWLY_MAX_ASSEMBLY_SCAN_QUEUE 256
#define OWLY_MAX_ASSEMBLY_SCAN_REGIONS 96
#define OWLY_ASSEMBLY_SAMPLE_BYTES 32

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

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

    // Allocate operation registration (process + thread handles)
    g_OpReg = (POB_OPERATION_REGISTRATION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(OB_OPERATION_REGISTRATION) * 2, 'ppOr');
    if (!g_OpReg) {
        DbgPrint("!!! ProcessProtection: Failed to allocate operation registration\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_OpReg, sizeof(OB_OPERATION_REGISTRATION) * 2);

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

    // Configure operation registration for thread handle operations
    g_OpReg[1].ObjectType = PsThreadType;
    g_OpReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OpReg[1].PreOperation = ProcessHandlePreCallback;
    g_OpReg[1].PostOperation = NULL;

    // Configure callback registration
    g_ObReg->Version = ObGetFilterVersion();
    g_ObReg->OperationRegistrationCount = (PsThreadType != NULL) ? 2 : 1;
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

    InitializeListHead(&g_AssemblyScanQueue);
    KeInitializeSpinLock(&g_AssemblyScanQueueLock);
    KeInitializeEvent(&g_AssemblyScanEvent, NotificationEvent, FALSE);
    InterlockedExchange(&g_AssemblyScanStop, 0);
    InterlockedExchange(&g_AssemblyScanQueueDepth, 0);

    status = PsCreateSystemThread(
        &g_AssemblyScanThreadHandle,
        GENERIC_ALL,
        NULL,
        NULL,
        NULL,
        AssemblyScanWorker,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        g_AssemblyScanThreadHandle = NULL;
        DbgPrint("!!! ProcessProtection: Assembly scan worker not started (0x%X)\n", status);
        DbgPrint("!!! ProcessProtection: Continuing with callback-only telemetry\n");
    } else {
        DbgPrint("!!! ProcessProtection: Assembly scan worker started\n");
    }

    DbgPrint("!!! ProcessProtection: ObRegisterCallbacks succeeded\n");
    return STATUS_SUCCESS;
}

VOID UninitProcessProtection()
{
    if (g_AssemblyScanThreadHandle != NULL) {
        InterlockedExchange(&g_AssemblyScanStop, 1);
        KeSetEvent(&g_AssemblyScanEvent, IO_NO_INCREMENT, FALSE);
        (VOID)ZwWaitForSingleObject(g_AssemblyScanThreadHandle, FALSE, NULL);
        ZwClose(g_AssemblyScanThreadHandle);
        g_AssemblyScanThreadHandle = NULL;
    }

    DrainAssemblyScanQueue();

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
    if (IsSystemProcessPP(currentProc))
        return OB_PREOP_SUCCESS;

    HANDLE callerPid = PsGetCurrentProcessId();
    UCHAR operationType = (UCHAR)pOperationInformation->Operation;

    ACCESS_MASK desiredAccess = 0;
    if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        desiredAccess = pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desiredAccess = pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    }

    // Process handle telemetry
    if (PsProcessType != NULL && pOperationInformation->ObjectType == *PsProcessType) {
        PEPROCESS targetProc = (PEPROCESS)pOperationInformation->Object;
        HANDLE targetPid = PsGetProcessId(targetProc);

        if (targetPid != NULL && callerPid != targetPid) {
            (VOID)OnProcessHandleOperation(callerPid, targetPid, desiredAccess, operationType);
            EmitProcessHandleIntentEvents((ULONG)(ULONG_PTR)callerPid, (ULONG)(ULONG_PTR)targetPid, desiredAccess);
            if (desiredAccess & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME)) {
                (VOID)QueueAssemblyMemoryScan(
                    (ULONG)(ULONG_PTR)callerPid,
                    (ULONG)(ULONG_PTR)targetPid,
                    desiredAccess
                );
            }

            // Keep explicit terminate-attempt signal for policy logic
            if (desiredAccess & PROCESS_TERMINATE) {
                QueueTerminationAttemptToUserMode(currentProc, targetProc);
            }
        }

        return OB_PREOP_SUCCESS;
    }

    // Thread handle telemetry (APC/context/suspend intents)
    if (PsThreadType != NULL && pOperationInformation->ObjectType == *PsThreadType) {
        PETHREAD targetThread = (PETHREAD)pOperationInformation->Object;
        PEPROCESS targetThreadProc = IoThreadToProcess(targetThread);
        HANDLE targetPid = targetThreadProc ? PsGetProcessId(targetThreadProc) : NULL;

        if (targetPid != NULL && callerPid != targetPid) {
            EmitThreadHandleIntentEvents(
                (ULONG)(ULONG_PTR)callerPid,
                (ULONG)(ULONG_PTR)targetPid,
                desiredAccess,
                (HANDLE)targetThread
            );
            if (desiredAccess & (THREAD_SET_CONTEXT | THREAD_SET_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT)) {
                (VOID)QueueAssemblyMemoryScan(
                    (ULONG)(ULONG_PTR)callerPid,
                    (ULONG)(ULONG_PTR)targetPid,
                    desiredAccess
                );
            }
        }
    }

    // Always allow the operation to proceed - we're just observing
    return OB_PREOP_SUCCESS;
}

NTSTATUS QueueAssemblyMemoryScan(
    _In_ ULONG SourcePid,
    _In_ ULONG TargetPid,
    _In_ ACCESS_MASK ReasonMask
)
{
    if (TargetPid == 0 || driverData == NULL || driverData->isFilterClosed()) {
        return STATUS_SUCCESS;
    }

    if (g_AssemblyScanThreadHandle == NULL) {
        return STATUS_SUCCESS;
    }

    LONG depth = InterlockedIncrement(&g_AssemblyScanQueueDepth);
    if (depth > OWLY_MAX_ASSEMBLY_SCAN_QUEUE) {
        InterlockedDecrement(&g_AssemblyScanQueueDepth);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PASSEMBLY_SCAN_TASK task = (PASSEMBLY_SCAN_TASK)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(ASSEMBLY_SCAN_TASK),
        'ppSc'
    );
    if (task == NULL) {
        InterlockedDecrement(&g_AssemblyScanQueueDepth);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(task, sizeof(*task));
    task->SourcePid = SourcePid;
    task->TargetPid = TargetPid;
    task->ReasonMask = ReasonMask;

    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_AssemblyScanQueueLock, &oldIrql);
    InsertTailList(&g_AssemblyScanQueue, &task->Entry);
    KeReleaseSpinLock(&g_AssemblyScanQueueLock, oldIrql);

    KeSetEvent(&g_AssemblyScanEvent, IO_NO_INCREMENT, FALSE);
    return STATUS_SUCCESS;
}

static VOID AssemblyScanWorker(_In_ PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);

    while (InterlockedCompareExchange(&g_AssemblyScanStop, 0, 0) == 0) {
        (VOID)KeWaitForSingleObject(&g_AssemblyScanEvent, Executive, KernelMode, FALSE, NULL);
        if (InterlockedCompareExchange(&g_AssemblyScanStop, 0, 0) != 0) {
            break;
        }

        for (;;) {
            PASSEMBLY_SCAN_TASK task = NULL;
            KIRQL oldIrql = PASSIVE_LEVEL;

            KeAcquireSpinLock(&g_AssemblyScanQueueLock, &oldIrql);
            if (!IsListEmpty(&g_AssemblyScanQueue)) {
                PLIST_ENTRY entry = RemoveHeadList(&g_AssemblyScanQueue);
                task = CONTAINING_RECORD(entry, ASSEMBLY_SCAN_TASK, Entry);
            } else {
                KeClearEvent(&g_AssemblyScanEvent);
            }
            KeReleaseSpinLock(&g_AssemblyScanQueueLock, oldIrql);

            if (task == NULL) {
                break;
            }

            ProcessAssemblyScanTask(task->SourcePid, task->TargetPid, task->ReasonMask);
            ExFreePoolWithTag(task, 'ppSc');
            InterlockedDecrement(&g_AssemblyScanQueueDepth);

            if (InterlockedCompareExchange(&g_AssemblyScanStop, 0, 0) != 0) {
                break;
            }
        }
    }

    DrainAssemblyScanQueue();
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID DrainAssemblyScanQueue(VOID)
{
    for (;;) {
        PASSEMBLY_SCAN_TASK task = NULL;
        KIRQL oldIrql = PASSIVE_LEVEL;

        KeAcquireSpinLock(&g_AssemblyScanQueueLock, &oldIrql);
        if (!IsListEmpty(&g_AssemblyScanQueue)) {
            PLIST_ENTRY entry = RemoveHeadList(&g_AssemblyScanQueue);
            task = CONTAINING_RECORD(entry, ASSEMBLY_SCAN_TASK, Entry);
        }
        KeReleaseSpinLock(&g_AssemblyScanQueueLock, oldIrql);

        if (task == NULL) {
            break;
        }

        ExFreePoolWithTag(task, 'ppSc');
        InterlockedDecrement(&g_AssemblyScanQueueDepth);
    }
}

static NTSTATUS CopyProcessBytesSafe(
    _In_ PEPROCESS SourceProcess,
    _In_ PVOID SourceAddress,
    _Out_writes_bytes_(DestinationSize) PUCHAR Destination,
    _In_ SIZE_T DestinationSize,
    _Out_ PSIZE_T BytesCopied
)
{
    if (SourceProcess == NULL || Destination == NULL || BytesCopied == NULL || DestinationSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *BytesCopied = 0;
    return MmCopyVirtualMemory(
        SourceProcess,
        SourceAddress,
        PsGetCurrentProcess(),
        Destination,
        DestinationSize,
        KernelMode,
        BytesCopied
    );
}

static ULONG DetectAssemblySignatureFlags(_In_reads_bytes_(BufferSize) const UCHAR* Buffer, _In_ SIZE_T BufferSize)
{
    if (Buffer == NULL || BufferSize == 0) {
        return 0;
    }

    ULONG flags = 0;

    // Near/short JMP at the start of the sampled region.
    if (Buffer[0] == 0xE9 || Buffer[0] == 0xEB) {
        flags |= 0x00000001;
    }

    // jmp/call register patterns (ff e0..e7 / ff d0..d7).
    if (BufferSize >= 2 && Buffer[0] == 0xFF) {
        if ((Buffer[1] >= 0xE0 && Buffer[1] <= 0xE7) || (Buffer[1] >= 0xD0 && Buffer[1] <= 0xD7)) {
            flags |= 0x00000002;
        }
    }

    // mov rax, imm64; jmp rax
    if (BufferSize >= 12 &&
        Buffer[0] == 0x48 &&
        Buffer[1] == 0xB8 &&
        Buffer[10] == 0xFF &&
        Buffer[11] == 0xE0) {
        flags |= 0x00000004;
    }

    // push imm32; ret
    if (BufferSize >= 6 &&
        Buffer[0] == 0x68 &&
        Buffer[5] == 0xC3) {
        flags |= 0x00000008;
    }

    // int3 sled.
    ULONG int3Count = 0;
    for (SIZE_T i = 0; i < BufferSize && i < 8; i++) {
        if (Buffer[i] == 0xCC) {
            int3Count++;
        } else {
            break;
        }
    }
    if (int3Count >= 4) {
        flags |= 0x00000010;
    }

    return flags;
}

static BOOLEAN IsExecutableProtectionMask(ULONG Protect)
{
    return (Protect & PAGE_EXECUTE) ||
           (Protect & PAGE_EXECUTE_READ) ||
           (Protect & PAGE_EXECUTE_READWRITE) ||
           (Protect & PAGE_EXECUTE_WRITECOPY);
}

static VOID ProcessAssemblyScanTask(_In_ ULONG SourcePid, _In_ ULONG TargetPid, _In_ ACCESS_MASK ReasonMask)
{
    HANDLE processHandle = NULL;
    PEPROCESS targetProcess = NULL;
    OBJECT_ATTRIBUTES objAttrs;
    CLIENT_ID cid;
    NTSTATUS status;

    InitializeObjectAttributes(&objAttrs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)TargetPid;
    cid.UniqueThread = 0;

    status = ZwOpenProcess(
        &processHandle,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
        &objAttrs,
        &cid
    );
    if (!NT_SUCCESS(status)) {
        KERNEL_API_EVENT_AUX aux = { 0 };
        aux.AccessMask = ReasonMask;
        aux.OperationStatus = status;
        (VOID)OnKernelApiEvent(
            IRP_NT_GENERIC_API_CALL,
            SourcePid,
            TargetPid,
            L"kernel.generic_api",
            &aux
        );
        return;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)TargetPid, &targetProcess);
    if (!NT_SUCCESS(status)) {
        KERNEL_API_EVENT_AUX aux = { 0 };
        aux.AccessMask = ReasonMask;
        aux.OperationStatus = status;
        (VOID)OnKernelApiEvent(
            IRP_NT_GENERIC_API_CALL,
            SourcePid,
            TargetPid,
            L"kernel.generic_api",
            &aux
        );
        ZwClose(processHandle);
        return;
    }

    {
        KERNEL_API_EVENT_AUX aux = { 0 };
        aux.AccessMask = ReasonMask;
        aux.OperationStatus = STATUS_SUCCESS;
        (VOID)OnKernelApiEvent(
            IRP_NT_GENERIC_API_CALL,
            SourcePid,
            TargetPid,
            L"kernel.generic_api",
            &aux
        );
    }

    PVOID queryAddress = 0;
    for (ULONG regionCount = 0; regionCount < OWLY_MAX_ASSEMBLY_SCAN_REGIONS; regionCount++) {
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        SIZE_T outLen = 0;
        status = ZwQueryVirtualMemory(
            processHandle,
            queryAddress,
            (MEMORY_INFORMATION_CLASS)0, // MemoryBasicInformation
            &mbi,
            sizeof(mbi),
            &outLen
        );
        if (!NT_SUCCESS(status)) {
            break;
        }

        ULONG_PTR nextAddressValue = (ULONG_PTR)mbi.BaseAddress + (ULONG_PTR)mbi.RegionSize;
        if (mbi.RegionSize == 0 || nextAddressValue <= (ULONG_PTR)queryAddress) {
            break;
        }

        if (mbi.State == MEM_COMMIT &&
            !(mbi.Protect & PAGE_GUARD) &&
            IsExecutableProtectionMask((ULONG)mbi.Protect)) {

            UCHAR sample[OWLY_ASSEMBLY_SAMPLE_BYTES] = { 0 };
            SIZE_T bytesRead = 0;
            ULONG signatureFlags = 0;
            BOOLEAN suspicious = FALSE;

            if (mbi.Type == MEM_PRIVATE &&
                (((ULONG)mbi.Protect & PAGE_EXECUTE_READWRITE) || ((ULONG)mbi.Protect & PAGE_EXECUTE_WRITECOPY))) {
                signatureFlags |= 0x00000100; // RWX private executable memory
                suspicious = TRUE;
            }

            if (NT_SUCCESS(CopyProcessBytesSafe(targetProcess, mbi.BaseAddress, sample, sizeof(sample), &bytesRead)) &&
                bytesRead > 0) {
                signatureFlags |= DetectAssemblySignatureFlags(sample, bytesRead);
                if (signatureFlags != 0) {
                    suspicious = TRUE;
                }
            }

            if (suspicious) {
                KERNEL_API_EVENT_AUX aux = { 0 };
                aux.MemoryAddress = mbi.BaseAddress;
                aux.MemorySize = mbi.RegionSize;
                aux.MemoryProtection = (ULONG)mbi.Protect;
                aux.IsExecutableMemory = TRUE;
                aux.AccessMask = ReasonMask;
                aux.ThreadHandle = (HANDLE)(ULONG_PTR)signatureFlags;
                aux.OperationStatus = STATUS_SUCCESS;
                (VOID)OnKernelApiEvent(
                    IRP_NT_GENERIC_ASSEMBLY_EVENT,
                    SourcePid,
                    TargetPid,
                    L"kernel.generic_assembly",
                    &aux
                );
            }
        }

        queryAddress = (PVOID)nextAddressValue;
    }

    if (targetProcess != NULL) {
        ObDereferenceObject(targetProcess);
    }
    ZwClose(processHandle);
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

static VOID EmitProcessHandleIntentEvents(
    _In_ ULONG CallerPid,
    _In_ ULONG TargetPid,
    _In_ ACCESS_MASK DesiredAccess
)
{
    KERNEL_API_EVENT_AUX aux = { 0 };
    aux.AccessMask = DesiredAccess;
    aux.OperationStatus = STATUS_SUCCESS;

    // Generic API telemetry bucket (opcode 13).
    (VOID)OnKernelApiEvent(IRP_NT_GENERIC_API_CALL, CallerPid, TargetPid, L"kernel.generic_api", &aux);

    if (DesiredAccess & PROCESS_VM_WRITE) {
        (VOID)OnKernelApiEvent(IRP_NT_GENERIC_ASSEMBLY_EVENT, CallerPid, TargetPid, L"kernel.generic_assembly", &aux);
    }

    if (DesiredAccess & PROCESS_VM_OPERATION) {
        (VOID)OnKernelApiEvent(IRP_NT_GENERIC_ASSEMBLY_EVENT, CallerPid, TargetPid, L"kernel.generic_assembly", &aux);
    }

    if (DesiredAccess & PROCESS_CREATE_THREAD) {
        (VOID)OnKernelApiEvent(IRP_NT_GENERIC_ASSEMBLY_EVENT, CallerPid, TargetPid, L"kernel.generic_assembly", &aux);
        (VOID)OnThreadCreation(CallerPid, TargetPid, NULL);
    }

    if (DesiredAccess & PROCESS_SUSPEND_RESUME) {
        (VOID)OnKernelApiEvent(IRP_NT_GENERIC_ASSEMBLY_EVENT, CallerPid, TargetPid, L"kernel.generic_assembly", &aux);
    }
}

static VOID EmitThreadHandleIntentEvents(
    _In_ ULONG CallerPid,
    _In_ ULONG TargetPid,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE ThreadHandle
)
{
    KERNEL_API_EVENT_AUX aux = { 0 };
    aux.AccessMask = DesiredAccess;
    aux.ThreadHandle = ThreadHandle;
    aux.OperationStatus = STATUS_SUCCESS;

    (VOID)OnKernelApiEvent(IRP_NT_GENERIC_API_CALL, CallerPid, TargetPid, L"kernel.generic_api", &aux);

    if (DesiredAccess & THREAD_SET_CONTEXT) {
        (VOID)OnKernelApiEvent(IRP_NT_GENERIC_ASSEMBLY_EVENT, CallerPid, TargetPid, L"kernel.generic_assembly", &aux);
    }

    if (DesiredAccess & THREAD_SET_INFORMATION) {
        (VOID)OnKernelApiEvent(IRP_NT_GENERIC_ASSEMBLY_EVENT, CallerPid, TargetPid, L"kernel.generic_assembly", &aux);
    }

    if (DesiredAccess & THREAD_SUSPEND_RESUME) {
        (VOID)OnKernelApiEvent(IRP_NT_GENERIC_ASSEMBLY_EVENT, CallerPid, TargetPid, L"kernel.generic_assembly", &aux);
    }

    if (DesiredAccess & THREAD_GET_CONTEXT) {
        (VOID)OnKernelApiEvent(IRP_NT_GENERIC_ASSEMBLY_EVENT, CallerPid, TargetPid, L"kernel.generic_assembly", &aux);
    }
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
    newItem->KernelEventInfo.EventType = IRP_PROCESS_HANDLE_OPEN;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&newItem->KernelEventInfo.Timestamp);
    newItem->KernelEventInfo.AccessMask = DesiredAccess;
    newItem->KernelEventInfo.SourceProcessId = callerPid;
    newItem->KernelEventInfo.TargetProcessId = targetPid;
    newItem->KernelEventInfo.OperationStatus = STATUS_SUCCESS;
    newItem->KernelEventInfo.ThreadHandle = (HANDLE)(ULONG_PTR)OperationType;
    // 1-12 must not carry API/assembly labels.
    newItem->KernelEventInfo.ObjectName[0] = L'\0';

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
    PEPROCESS attackerProcess = NULL;
    PEPROCESS targetProcess = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(AttackerPid, &attackerProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = PsLookupProcessByProcessId(TargetPid, &targetProcess);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(attackerProcess);
        return status;
    }

    status = QueueTerminationAttemptToUserMode(attackerProcess, targetProcess);
    ObDereferenceObject(targetProcess);
    ObDereferenceObject(attackerProcess);
    return status;
}

//
// --- Kernel API Hook Integration Functions ---
//

NTSTATUS OnKernelApiEvent(
    _In_ ULONG EventType,
    _In_ ULONG SourcePid,
    _In_ ULONG TargetPid,
    _In_opt_ PCWSTR FunctionName,
    _In_opt_ PVOID EventData
)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    BOOLEAN sourceFound = FALSE;
    BOOLEAN targetFound = FALSE;
    ULONGLONG sourceGid = driverData->GetProcessGid(SourcePid, &sourceFound);
    ULONGLONG targetGid = driverData->GetProcessGid(TargetPid, &targetFound);

    // Keep user-mode hook events (built-in + dynamic custom EventIds) even when
    // process GID tracking is not yet established. User mode can recover by PID.
    const BOOLEAN isUserHookEvent = (EventType >= IRP_NT_GENERIC_API_CALL);
    if (!sourceFound && !targetFound && !isUserHookEvent)
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
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&newItem->KernelEventInfo.Timestamp);

    // Optional auxiliary payload for richer kernel telemetry.
    if (EventData != NULL) {
        PKERNEL_API_EVENT_AUX aux = (PKERNEL_API_EVENT_AUX)EventData;
        newItem->KernelEventInfo.MemoryAddress = aux->MemoryAddress;
        newItem->KernelEventInfo.MemorySize = aux->MemorySize;
        newItem->KernelEventInfo.MemoryProtection = aux->MemoryProtection;
        newItem->KernelEventInfo.IsExecutableMemory = aux->IsExecutableMemory;
        newItem->KernelEventInfo.ThreadHandle = aux->ThreadHandle;
        newItem->KernelEventInfo.ThreadStartRoutine = aux->ThreadStartRoutine;
        newItem->KernelEventInfo.AccessMask = aux->AccessMask;
        newItem->KernelEventInfo.OperationStatus = aux->OperationStatus;
    }

    if (EventType <= IRP_KERNEL_REMOTE_THREAD) {
        // Keep non-API opcodes (1-12) empty by design.
        newItem->KernelEventInfo.ObjectName[0] = L'\0';
    } else if (EventType == IRP_NT_GENERIC_API_CALL) {
        if (FunctionName != NULL && FunctionName[0] != L'\0') {
            RtlStringCchCopyW(newItem->KernelEventInfo.ObjectName, MAX_FILE_NAME_LENGTH, FunctionName);
        } else {
            RtlStringCchCopyW(newItem->KernelEventInfo.ObjectName, MAX_FILE_NAME_LENGTH, L"kernel.generic_api");
        }
    } else if (EventType == IRP_NT_GENERIC_ASSEMBLY_EVENT) {
        if (FunctionName != NULL && FunctionName[0] != L'\0') {
            RtlStringCchCopyW(newItem->KernelEventInfo.ObjectName, MAX_FILE_NAME_LENGTH, FunctionName);
        } else {
            RtlStringCchCopyW(newItem->KernelEventInfo.ObjectName, MAX_FILE_NAME_LENGTH, L"kernel.generic_assembly");
        }
    } else if (FunctionName != NULL && FunctionName[0] != L'\0') {
        RtlStringCchCopyW(newItem->KernelEventInfo.ObjectName, MAX_FILE_NAME_LENGTH, FunctionName);
    } else {
        newItem->KernelEventInfo.ObjectName[0] = L'\0';
    }

    DbgPrint("!!! ProcessProtection: Kernel API event detected - Type: %lu, Name: %ls, Source PID: %lu, Target PID: %lu\n",
        EventType, FunctionName ? FunctionName : L"Unknown", SourcePid, TargetPid);

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
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&newItem->KernelEventInfo.Timestamp);
    newItem->KernelEventInfo.MemoryAddress = TargetAddress;
    newItem->KernelEventInfo.MemorySize = Size;
    newItem->KernelEventInfo.IsExecutableMemory = IsExecutableMemory;
    newItem->KernelEventInfo.OperationStatus = STATUS_SUCCESS;
    RtlStringCchCopyW(newItem->KernelEventInfo.ObjectName, MAX_FILE_NAME_LENGTH, L"kernel.generic_assembly");

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
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&newItem->KernelEventInfo.Timestamp);
    newItem->KernelEventInfo.MemoryAddress = BaseAddress;
    newItem->KernelEventInfo.MemorySize = RegionSize;
    newItem->KernelEventInfo.MemoryProtection = NewProtection;
    newItem->KernelEventInfo.IsExecutableMemory = IsExecutableProtection(NewProtection);
    newItem->KernelEventInfo.OperationStatus = STATUS_SUCCESS;
    RtlStringCchCopyW(newItem->KernelEventInfo.ObjectName, MAX_FILE_NAME_LENGTH, L"kernel.generic_assembly");

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
    newItem->IRP_OP = IRP_KERNEL_REMOTE_THREAD;

    newItem->KernelEventInfo.EventType = IRP_KERNEL_REMOTE_THREAD;
    newItem->KernelEventInfo.SourceProcessId = SourcePid;
    newItem->KernelEventInfo.TargetProcessId = TargetPid;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&newItem->KernelEventInfo.Timestamp);
    newItem->KernelEventInfo.ThreadStartRoutine = StartRoutine;
    newItem->KernelEventInfo.OperationStatus = STATUS_SUCCESS;
    // 1-12 must not carry API/assembly labels.
    newItem->KernelEventInfo.ObjectName[0] = L'\0';

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
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&newItem->KernelEventInfo.Timestamp);
    newItem->KernelEventInfo.ThreadHandle = ThreadHandle;
    newItem->KernelEventInfo.ThreadStartRoutine = ApcRoutine;
    newItem->KernelEventInfo.OperationStatus = STATUS_SUCCESS;
    RtlStringCchCopyW(newItem->KernelEventInfo.ObjectName, MAX_FILE_NAME_LENGTH, L"kernel.generic_assembly");

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
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&newItem->KernelEventInfo.Timestamp);
    newItem->KernelEventInfo.OperationStatus = STATUS_SUCCESS;
    RtlStringCchCopyW(newItem->KernelEventInfo.ObjectName, MAX_FILE_NAME_LENGTH, L"kernel.generic_assembly");

    if (SectionName != NULL) {
        USHORT copyLen = (USHORT)wcslen(SectionName) * sizeof(WCHAR);
        if (copyLen > (MAX_FILE_NAME_LENGTH - 1) * sizeof(WCHAR)) {
            copyLen = (MAX_FILE_NAME_LENGTH - 1) * sizeof(WCHAR);
        }
        RtlCopyMemory(newEntry->Buffer, SectionName, copyLen);
        newEntry->Buffer[copyLen / sizeof(WCHAR)] = L'\0';
        newEntry->filePath.Length = copyLen;
        newEntry->filePath.MaximumLength = MAX_FILE_NAME_SIZE;
        newEntry->filePath.Buffer = newEntry->Buffer;
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
