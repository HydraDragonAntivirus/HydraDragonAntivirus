/*++

Module Name:

    FsFilter.c

Abstract:

    This is the main module of the FsFilter miniFilter driver.
    
    UPDATED: Replaced process hooking path with hypervisor/VMM monitoring
             and proper Windows notification callbacks.

Environment:

    Kernel mode

--*/

#include "FsFilter.h"
#include "Regedit.h"
#include "ProcessProtection.h"
#include "UserModeHookEngine.h"
#include "OwlyVmmBridge.h"
#include "RootkitDetector.h"

#pragma prefast(disable : __WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//  Structure that contains all the global data structures used throughout the driver.

// FIX: Make this volatile to prevent compiler optimizations that could cause issues
volatile QUERY_INFO_PROCESS ZwQueryInformationProcess = NULL;

// Global variable definition
UNICODE_STRING GvolumeData;

EXTERN_C_START

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

DRIVER_INITIALIZE DriverEntry;

EXTERN_C_END

//
// Forward declarations for new callback functions
//

VOID ThreadCreationCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
);

VOID ImageLoadCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
);

// FIX: Forward declaration added because it is used before definition
FLT_POSTOP_CALLBACK_STATUS
FSProcessPostReadSafe(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                      _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

BOOLEAN
FSShouldIgnorePyasWhitelistPath(_In_ PCUNICODE_STRING Path);

static BOOLEAN
FSShouldBypassReadTelemetry(_In_ PFLT_CALLBACK_DATA Data)
{
    ULONG requestorPid;
    PEPROCESS requestorProcess = NULL;

    if (Data == NULL || Data->Iopb == NULL || Data->Iopb->MajorFunction != IRP_MJ_READ)
    {
        return FALSE;
    }

    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO))
    {
        return TRUE;
    }

    if (Data->RequestorMode == KernelMode)
    {
        return TRUE;
    }

    requestorPid = FltGetRequestorProcessId(Data);
    if (requestorPid == 0 || requestorPid == 4)
    {
        return TRUE;
    }

    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)requestorPid, &requestorProcess)))
    {
        UCHAR *processName = PsGetProcessImageFileName(requestorProcess);
        if (processName != NULL &&
            (_stricmp((const char *)processName, "MemCompression") == 0 ||
             _stricmp((const char *)processName, "System") == 0))
        {
            ObDereferenceObject(requestorProcess);
            return TRUE;
        }

        ObDereferenceObject(requestorProcess);
    }

    return FALSE;
}

static BOOLEAN
FSIsKernelDebuggerAttached(VOID)
{
    return (KD_DEBUGGER_ENABLED != FALSE && KD_DEBUGGER_NOT_PRESENT == FALSE);
}

// CDO Dispatch Routines
// HookDevice* dispatch functions are now in Communication.cpp.
// Use InitHookNotifyDevice() / CleanupHookNotifyDevice() instead.

// g_HookDeviceObject removed: hook device owned by Communication.cpp
static PDRIVER_OBJECT g_DriverObject = NULL;   // set in DriverEntry
static PDEVICE_OBJECT g_WorkItemDeviceObject = NULL; // dedicated CDO for IoAllocateWorkItem

// Public definition of g_DeviceObject — extern-declared in Regedit.cpp so that
// QueueRegistryBackup (Bug #1 fix) can call IoAllocateWorkItem safely from within
// the CmCallback work-item deferral. Assigned from g_WorkItemDeviceObject in
// DriverEntry, after IoCreateDevice succeeds.
PDEVICE_OBJECT g_DeviceObject = NULL;
static BOOLEAN g_UseLegacyProcessNotify = FALSE;
static BOOLEAN g_ProcessNotifyRegistered = FALSE;
static BOOLEAN g_ThreadNotifyRegistered = FALSE;
static BOOLEAN g_ImageNotifyRegistered = FALSE;

// Work item used to offload UserModeHookProcess from ImageLoadCallback.
// ImageLoadCallback runs in a loader lock path; calling heavy kernel operations
// (KeStackAttachProcess, ZwAllocateVirtualMemory, ZwCreateFile) directly causes freezes.
typedef struct _HOOK_PROCESS_WORK_ITEM {
    PIO_WORKITEM WorkItem;   // <-- handle, not embedded struct
    ULONG        ProcessId;
} HOOK_PROCESS_WORK_ITEM, *PHOOK_PROCESS_WORK_ITEM;

static VOID HookProcessWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Parameter)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PHOOK_PROCESS_WORK_ITEM ctx = (PHOOK_PROCESS_WORK_ITEM)Parameter;
    if (ctx == NULL) return;

    (VOID)UserModeHookProcess(ctx->ProcessId);

    IoFreeWorkItem(ctx->WorkItem); // free the IO_WORKITEM first
    ExFreePoolWithTag(ctx, 'wHuM');
}

#define PYAS_RULE_POOL_TAG 'rPyO'
#define PYAS_RULE_MAX_FILE_SIZE (64 * 1024)
#define PYAS_RULE_MAX_LINE_CHARS 512

typedef struct _PYAS_WHITELIST_RULE_SET
{
    PWSTR *Rules;
    ULONG Count;
    ULONG Capacity;
    FAST_MUTEX Mutex;
    volatile LONG MutexInitialized; // FIX Bug4: 0=uninit, 1=initializing, 2=ready
    BOOLEAN Loaded;
} PYAS_WHITELIST_RULE_SET, *PPYAS_WHITELIST_RULE_SET;

static PYAS_WHITELIST_RULE_SET g_PyasWhitelistRules = {0};

static VOID FSEnsurePyasRuleMutex(VOID)
{
    volatile LONG *pState = (volatile LONG *)&g_PyasWhitelistRules.MutexInitialized;

    // Fast path: already ready.
    if (InterlockedCompareExchange(pState, 0, 0) == 2)
    {
        KeMemoryBarrier();
        return;
    }

    // Race to become the initializing thread (0 -> 1).
    if (InterlockedCompareExchange(pState, 1, 0) == 0)
    {
        // WINNER: We have exclusive rights to initialize.
        // Initialize the global mutex directly in-place. No memcpy!
        ExInitializeFastMutex(&g_PyasWhitelistRules.Mutex);
        
        KeMemoryBarrier(); // Ensure all FAST_MUTEX bytes are visible globally
        InterlockedExchange(pState, 2); // Publish ready state
        return;
    }

    // LOSER: spin until winner publishes 2.
    while (InterlockedCompareExchange(pState, 0, 0) != 2)
    {
        YieldProcessor();
    }
    KeMemoryBarrier();
}

static VOID FSFreePyasWhitelistRulesUnlocked(VOID)
{
    if (g_PyasWhitelistRules.Rules != NULL)
    {
        for (ULONG i = 0; i < g_PyasWhitelistRules.Count; ++i)
        {
            PWSTR rule = g_PyasWhitelistRules.Rules[i];
            if (rule != NULL)
            {
                ExFreePoolWithTag(rule, PYAS_RULE_POOL_TAG);
            }
        }
        ExFreePoolWithTag(g_PyasWhitelistRules.Rules, PYAS_RULE_POOL_TAG);
    }

    g_PyasWhitelistRules.Rules = NULL;
    g_PyasWhitelistRules.Count = 0;
    g_PyasWhitelistRules.Capacity = 0;
}

static NTSTATUS FSEnsurePyasRuleCapacityUnlocked(_In_ ULONG RequiredCount)
{
    PWSTR *newArray;
    SIZE_T allocSize;
    ULONG newCapacity;

    if (g_PyasWhitelistRules.Capacity >= RequiredCount)
    {
        return STATUS_SUCCESS;
    }

    newCapacity = (g_PyasWhitelistRules.Capacity == 0) ? 8 : g_PyasWhitelistRules.Capacity * 2;
    if (newCapacity < RequiredCount)
    {
        newCapacity = RequiredCount;
    }

    allocSize = sizeof(PWSTR) * newCapacity;
    newArray = (PWSTR *)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, PYAS_RULE_POOL_TAG);
    if (newArray == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(newArray, allocSize);
    if (g_PyasWhitelistRules.Rules != NULL && g_PyasWhitelistRules.Count > 0)
    {
        RtlCopyMemory(newArray, g_PyasWhitelistRules.Rules, sizeof(PWSTR) * g_PyasWhitelistRules.Count);
        ExFreePoolWithTag(g_PyasWhitelistRules.Rules, PYAS_RULE_POOL_TAG);
    }

    g_PyasWhitelistRules.Rules = newArray;
    g_PyasWhitelistRules.Capacity = newCapacity;
    return STATUS_SUCCESS;
}

static NTSTATUS FSAddPyasWhitelistRuleNormalizedUnlocked(_In_reads_(RuleChars) PCWSTR RuleText, _In_ SIZE_T RuleChars)
{
    WCHAR normalizedLine[PYAS_RULE_MAX_LINE_CHARS];
    SIZE_T lineLen = 0;
    NTSTATUS status;

    if (!OwlyNormalizeRuleLineForMatch(RuleText,
                                       RuleChars,
                                       normalizedLine,
                                       RTL_NUMBER_OF(normalizedLine),
                                       FALSE,
                                       &lineLen) ||
        lineLen == 0)
    {
        return STATUS_SUCCESS;
    }

    for (ULONG i = 0; i < g_PyasWhitelistRules.Count; ++i)
    {
        if (_wcsicmp(g_PyasWhitelistRules.Rules[i], normalizedLine) == 0)
        {
            return STATUS_SUCCESS;
        }
    }

    status = FSEnsurePyasRuleCapacityUnlocked(g_PyasWhitelistRules.Count + 1);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    {
        SIZE_T allocSize = (lineLen + 1) * sizeof(WCHAR);
        PWSTR newRule = (PWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, PYAS_RULE_POOL_TAG);
        if (newRule == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(newRule, allocSize);
        RtlCopyMemory(newRule, normalizedLine, lineLen * sizeof(WCHAR));
        newRule[lineLen] = L'\0';
        g_PyasWhitelistRules.Rules[g_PyasWhitelistRules.Count++] = newRule;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS FSAppendPyasRulesFromBufferUnlocked(_In_reads_bytes_(BytesRead) PUCHAR Buffer, _In_ ULONG BytesRead)
{
    if (Buffer == NULL || BytesRead == 0)
    {
        return STATUS_SUCCESS;
    }

    if (BytesRead >= 2 && Buffer[0] == 0xFF && Buffer[1] == 0xFE)
    {
        PWCHAR utf16Buffer = (PWCHAR)(Buffer + 2);
        ULONG utf16Chars = (BytesRead - 2) / sizeof(WCHAR);
        ULONG start = 0;
        for (ULONG i = 0; i <= utf16Chars; ++i)
        {
            BOOLEAN isDelimiter = (i == utf16Chars) || utf16Buffer[i] == L'\n' || utf16Buffer[i] == L'\r';
            if (isDelimiter)
            {
                if (i > start)
                {
                    (VOID)FSAddPyasWhitelistRuleNormalizedUnlocked(&utf16Buffer[start], i - start);
                }
                start = i + 1;
            }
        }
        return STATUS_SUCCESS;
    }

    {
        ULONG start = 0;
        for (ULONG i = 0; i <= BytesRead; ++i)
        {
            BOOLEAN isDelimiter = (i == BytesRead) || Buffer[i] == '\n' || Buffer[i] == '\r';
            if (isDelimiter)
            {
                if (i > start)
                {
                    WCHAR lineBuffer[PYAS_RULE_MAX_LINE_CHARS];
                    SIZE_T lineLen = 0;
                    for (ULONG j = start; j < i && lineLen + 1 < RTL_NUMBER_OF(lineBuffer); ++j)
                    {
                        lineBuffer[lineLen++] = (WCHAR)Buffer[j];
                    }
                    lineBuffer[lineLen] = L'\0';
                    (VOID)FSAddPyasWhitelistRuleNormalizedUnlocked(lineBuffer, lineLen);
                }
                start = i + 1;
            }
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS FSLoadPyasWhitelistRulesFromFileUnlocked(_In_ PCUNICODE_STRING FilePath)
{
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK ioStatus;
    FILE_STANDARD_INFORMATION fileInfo;
    HANDLE fileHandle = NULL;
    PUCHAR buffer = NULL;
    ULONG bufferSize;
    NTSTATUS status;

    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    InitializeObjectAttributes(&oa, (PUNICODE_STRING)FilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    RtlZeroMemory(&ioStatus, sizeof(ioStatus));
    status = ZwCreateFile(&fileHandle,
                          GENERIC_READ,
                          &oa,
                          &ioStatus,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ,
                          FILE_OPEN,
                          FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL,
                          0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    RtlZeroMemory(&fileInfo, sizeof(fileInfo));
    status = ZwQueryInformationFile(fileHandle,
                                    &ioStatus,
                                    &fileInfo,
                                    sizeof(fileInfo),
                                    FileStandardInformation);
    if (!NT_SUCCESS(status))
    {
        ZwClose(fileHandle);
        return status;
    }

    if (fileInfo.EndOfFile.QuadPart <= 0 || fileInfo.EndOfFile.QuadPart > PYAS_RULE_MAX_FILE_SIZE)
    {
        ZwClose(fileHandle);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    bufferSize = (ULONG)fileInfo.EndOfFile.QuadPart;
    buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, PYAS_RULE_POOL_TAG);
    if (buffer == NULL)
    {
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(buffer, bufferSize);

    RtlZeroMemory(&ioStatus, sizeof(ioStatus));
    status = ZwReadFile(fileHandle,
                        NULL,
                        NULL,
                        NULL,
                        &ioStatus,
                        buffer,
                        bufferSize,
                        NULL,
                        NULL);
    if (NT_SUCCESS(status))
    {
        (VOID)FSAppendPyasRulesFromBufferUnlocked(buffer, (ULONG)ioStatus.Information);
    }

    ExFreePoolWithTag(buffer, PYAS_RULE_POOL_TAG);
    ZwClose(fileHandle);
    return status;
}

static VOID FSLoadPyasWhitelistRules(VOID)
{
    //
    // FIX: FAST_MUTEX raises IRQL to APC_LEVEL which disables kernel APCs.
    // ZwCreateFile with FILE_SYNCHRONOUS_IO_NONALERT needs a kernel APC to
    // signal I/O completion. Holding the mutex during the file read causes
    // a deadlock. Do ALL file I/O before acquiring the mutex.
    //
    FSEnsurePyasRuleMutex();

    // Fast path check without I/O (safe to do under the mutex briefly)
    ExAcquireFastMutex(&g_PyasWhitelistRules.Mutex);
    BOOLEAN alreadyLoaded = g_PyasWhitelistRules.Loaded;
    ExReleaseFastMutex(&g_PyasWhitelistRules.Mutex);

    if (alreadyLoaded)
        return;

    // Do file I/O entirely at PASSIVE_LEVEL, outside any mutex
    UNICODE_STRING ruleFilePath;
    NTSTATUS loadStatus;
    RtlInitUnicodeString(&ruleFilePath, OWLY_FSFILTER_RULE_FILE_KERNEL);

    ExAcquireFastMutex(&g_PyasWhitelistRules.Mutex);
    FSFreePyasWhitelistRulesUnlocked();
    ExReleaseFastMutex(&g_PyasWhitelistRules.Mutex);

    // File I/O happens here with no mutex held
    loadStatus = FSLoadPyasWhitelistRulesFromFileUnlocked(&ruleFilePath);

    // Only latch the cache as loaded after a successful file read. If the
    // rules file is not present yet, keep the cache retryable.
    ExAcquireFastMutex(&g_PyasWhitelistRules.Mutex);
    g_PyasWhitelistRules.Loaded = NT_SUCCESS(loadStatus);
    ExReleaseFastMutex(&g_PyasWhitelistRules.Mutex);
}

static VOID FSCleanupPyasWhitelistRules(VOID)
{
    FSEnsurePyasRuleMutex();
    ExAcquireFastMutex(&g_PyasWhitelistRules.Mutex);
    FSFreePyasWhitelistRulesUnlocked();
    g_PyasWhitelistRules.Loaded = FALSE;
    ExReleaseFastMutex(&g_PyasWhitelistRules.Mutex);
}

VOID FSReloadPyasWhitelistRules(VOID)
{
    FSCleanupPyasWhitelistRules();
    FSLoadPyasWhitelistRules();
}

//
//  Constant FLT_REGISTRATION structure for our filter.
//  initializes the callback routines our filter wants to register
//  for.  This is only used to register with the filter manager
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {{IRP_MJ_CREATE, 0, FSPreOperation, FSPostOperation},
                                                //{IRP_MJ_CLOSE, 0, FSPreOperation, FSPostOperation},
                                                {IRP_MJ_READ, 0, FSPreOperation, FSPostOperation},
                                                {IRP_MJ_CLEANUP, 0, FSPreOperation, NULL},
                                                {IRP_MJ_WRITE, 0, FSPreOperation, NULL},
                                                {IRP_MJ_SET_INFORMATION, 0, FSPreOperation, NULL},
                                                {IRP_MJ_OPERATION_END}};

/*++

FilterRegistration Defines what we want to filter with the driver

--*/
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),   //  Size
    FLT_REGISTRATION_VERSION,   //  Version
    0,                          //  Flags
    NULL,                       //  Context Registration.
    Callbacks,                  //  Operation callbacks
    NULL,                       //  FilterUnload (disabled to prevent runtime unload requests)
    FSInstanceSetup,            //  InstanceSetup
    FSInstanceQueryTeardown,    //  InstanceQueryTeardown
    FSInstanceTeardownStart,    //  InstanceTeardownStart
    FSInstanceTeardownComplete, //  InstanceTeardownComplete
    NULL,                       //  GenerateFileName
    NULL,                       //  GenerateDestinationFileName
    NULL                        //  NormalizeNameComponent
};

////////////////////////////////////////////////////////////////////////////
//
//    Filter initialization and unload routines.
//
////////////////////////////////////////////////////////////////////////////

extern "C" NTSTATUS RedDbgDriverEntry(_In_ PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath);
extern "C" NTSTATUS RedDbgStartStandaloneControlDriver(VOID);
extern "C" VOID RedDbgStopStandaloneControlDriver(VOID);

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
/*++

Routine Description:

    This is the initialization routine for the Filter driver.  This
    registers the Filter with the filter manager and initializes all
    its global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Returns STATUS_SUCCESS.
--*/
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    // Store DriverObject globally so IoAllocateWorkItem can reference it later.
    // FltMgr attaches a device object to this driver after FltRegisterFilter,
    // making DriverObject->DeviceObject valid for the driver's lifetime.
    g_DriverObject = DriverObject;

    //
    // --- FIX: Initialize required function pointers FIRST and verify. ---
    //
    if (ZwQueryInformationProcess == NULL)
    {
        UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");

        ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

        if (ZwQueryInformationProcess == NULL)
        {
            DbgPrint("Cannot resolve ZwQueryInformationProcess. Driver will not load.\n");
            return STATUS_UNSUCCESSFUL;
        }

        // FIX: Add a small delay and re-verify to ensure it's properly set
        KeStallExecutionProcessor(100); // 100 microseconds

        if (ZwQueryInformationProcess == NULL)
        {
            DbgPrint("ZwQueryInformationProcess became NULL after initialization. Driver will not load.\n");
            return STATUS_UNSUCCESSFUL;
        }
    }

    // Resolve ZwQuerySystemInformation dynamically - not reliably declared in WDK headers
    if (g_fnZwQuerySystemInformation == NULL)
    {
        UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
        g_fnZwQuerySystemInformation = (PZW_QUERY_SYSTEM_INFORMATION)MmGetSystemRoutineAddress(&routineName);
        if (g_fnZwQuerySystemInformation == NULL)
        {
            DbgPrint("!!! FsFilter: Cannot resolve ZwQuerySystemInformation. Driver will not load.\n");
            return STATUS_UNSUCCESSFUL;
        }
    }

    //
    //  Default to NonPagedPoolNx for non paged pool allocations where supported.
    //
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    //
    //  Register with filter manager.
    //
    
    // -----------------------------------------------------------------------
    // Hook notification device (\Device\OwlyshieldHook) is created by
    // Communication.cpp::InitHookNotifyDevice() via IoCreateDriver().
    // Do NOT create it here with IoCreateDevice() on this DriverObject:
    // FltRegisterFilter() overwrites MajorFunction[IRP_MJ_DEVICE_CONTROL]
    // with its own wrapper, so every shellcode IOCTL would get
    // STATUS_INVALID_DEVICE_REQUEST -- killing all hook I/O events.
    // -----------------------------------------------------------------------

    driverData = new DriverData(DriverObject);
    if (driverData == NULL)
    {
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    PFLT_FILTER *FilterAdd = driverData->getFilterAdd();

    status = FltRegisterFilter(DriverObject, &FilterRegistration, FilterAdd);

    // Create a dedicated unnamed CDO on this DriverObject for IoAllocateWorkItem.
    // FltRegisterFilter does NOT create a device on the minifilter's device chain,
    // so DriverObject->DeviceObject stays NULL. We need a valid DeviceObject to
    // pass to IoAllocateWorkItem (which references it to pin the driver).
    if (NT_SUCCESS(status))
    {
        NTSTATUS cdoStatus = IoCreateDevice(DriverObject, 0, NULL,
                                             FILE_DEVICE_UNKNOWN, 0, FALSE,
                                             &g_WorkItemDeviceObject);
        if (!NT_SUCCESS(cdoStatus))
        {
            DbgPrint("!!! FsFilter: IoCreateDevice for work-item CDO failed 0x%X (non-fatal)\n", cdoStatus);
            g_WorkItemDeviceObject = NULL; // ImageLoadCallback will skip hook deferral
        }
        else
        {
            g_WorkItemDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
            // Wire the public g_DeviceObject pointer so Regedit.cpp's
            // QueueRegistryBackup can call IoAllocateWorkItem.
            // Must be assigned before RegeditDriverEntry() below.
            g_DeviceObject = g_WorkItemDeviceObject;
        }
    }

    if (!NT_SUCCESS(status))
    {
        delete driverData;
        return status;
    }

    commHandle = new CommHandler(driverData->getFilter());
    if (commHandle == NULL)
    {
        // Clean up FltRegisterFilter
        FltUnregisterFilter(*FilterAdd);
        delete driverData;
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    status = InitCommData();

    if (!NT_SUCCESS(status))
    {
        FltUnregisterFilter(driverData->getFilter());
        delete driverData;
        delete commHandle;
        return status;
    }
    //
    //  Start filtering I/O.
    //
    status = FltStartFiltering(driverData->getFilter());

    if (!NT_SUCCESS(status))
    {
        CommClose();
        FltUnregisterFilter(driverData->getFilter());
        delete driverData;
        delete commHandle;
        return status;
    }
    driverData->setFilterStart();

    // Create the hook notification device AFTER FltStartFiltering so FltMgr's
    // own dispatch is fully installed. InitHookNotifyDevice uses IoCreateDriver
    // (independent DRIVER_OBJECT) so FltMgr never overwrites its dispatch table.
    status = InitHookNotifyDevice(DriverObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("!!! FsFilter: InitHookNotifyDevice failed 0x%X\n", status);
        // Non-fatal: minifilter still works; only shellcode IOCTL events are lost.
        status = STATUS_SUCCESS;
    }

    //
    // FIX: Register the process notification callback AFTER all dependencies are initialized
    // and double-check ZwQueryInformationProcess is still valid.
    //
    if (ZwQueryInformationProcess == NULL)
    {
        DbgPrint("!!! FsFilter: CRITICAL - ZwQueryInformationProcess is NULL before callback registration!\n");
        CommClose();
        FltUnregisterFilter(driverData->getFilter());
        delete driverData;
        delete commHandle;
        return STATUS_UNSUCCESSFUL;
    }

    status = PsSetCreateProcessNotifyRoutineEx(AddRemProcessRoutineEx, FALSE);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("!!! FsFilter: PsSetCreateProcessNotifyRoutineEx failed: %#010x, falling back to legacy callback.\n", status);
        status = PsSetCreateProcessNotifyRoutine(AddRemProcessRoutineLegacy, FALSE);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("!!! FsFilter: Failed to register any process notify routine: %#010x\n", status);
            CommClose();
            FltUnregisterFilter(driverData->getFilter());
            delete driverData;
            delete commHandle;
            return status;
        }
        g_UseLegacyProcessNotify = TRUE;
        g_ProcessNotifyRegistered = TRUE;
    }
    else
    {
        g_UseLegacyProcessNotify = FALSE;
        g_ProcessNotifyRegistered = TRUE;
    }

    DbgPrint("loaded scanner successfully");
    
    // Initialize Registry Protection
    RegeditDriverEntry();

    // Initialize Process Protection (ObRegisterCallbacks for termination detection)
    status = InitProcessProtection();
    if (!NT_SUCCESS(status)) {
        DbgPrint("!!! FsFilter: InitProcessProtection failed: 0x%X (non-fatal, continuing)\n", status);
        // Don't fail driver load - this is an enhancement, not critical
    }

    // Set the quarantine path
    UNICODE_STRING quarantinePathString;
    RtlInitUnicodeString(&quarantinePathString, L"\\??\\C:\\ProgramData\\HydraDragonAntivirus\\Quarantine");
    driverData->SetQuarantinePath(&quarantinePathString);

    // Load PYAS whitelist rules once at startup; FsFilter uses these to ignore incoming whitelist scope.
    FSLoadPyasWhitelistRules();

    // ====================================================================
    // Initialize monitoring systems
    // - Hypervisor/VMM monitoring backend
    // - Thread creation callbacks
    // - Image load callbacks
    // ====================================================================

    DbgPrint("!!! FsFilter: Initializing advanced monitoring systems...\n");

    // 1. Initialize user-mode hook engine for dynamic API hook events.
    status = UserModeHookEngineInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrint("!!! FsFilter: Failed to initialize user-mode hook engine: 0x%X (non-fatal)\n", status);
    }

    // 2. Initialize RedDbg hypervisor subsystem on an independent DRIVER_OBJECT.
    // RedDbgDriverEntry remains the actual initialization entrypoint; the
    // standalone wrapper simply prevents the minifilter's dispatch table from
    // being repurposed for RedDbg's control device.
    status = RedDbgStartStandaloneControlDriver();
    if (!NT_SUCCESS(status))
    {
        DbgPrint("!!! FsFilter: RedDbgStartStandaloneControlDriver failed: 0x%X (non-fatal)\n", status);
    }
    else
    {
        DbgPrint("!!! FsFilter: RedDbg hypervisor initialized successfully\n");
    }

    // 3. Initialize the VMM monitoring backend.
    //
    // Live KD sessions already own low-level debug/NMI plumbing. On AMD, bringing
    // up the Owly/HyperDbg VMM while KD is attached has been observed to surface
    // as NMI_HARDWARE_FAILURE bugchecks, so we skip only the VMM backend in that
    // specific configuration while leaving the rest of the monitoring stack alive.
    if (FSIsKernelDebuggerAttached())
    {
        DbgPrint("!!! FsFilter: Kernel debugger attached; skipping OwlyVmm initialization for this boot\n");
    }
    else
    {
        status = OwlyVmmInitialize();
        if (!NT_SUCCESS(status))
        {
            if (status == STATUS_NOT_SUPPORTED)
            {
                DbgPrint("!!! FsFilter: VMM initialization skipped (HyperDbg components unavailable, not linked, or unsupported on this target)\n");
            }
            else
            {
                DbgPrint("!!! FsFilter: VMM initialization failed: 0x%X (non-fatal)\n", status);
            }
        }
        else
        {
            DbgPrint("!!! FsFilter: VMM monitoring core initialized\n");
        }
    }

    DbgPrint("!!! FsFilter: Enumerating existing processes for initial process baseline\n");
    EnumerateExistingProcesses();

    // 3. Register thread creation callback
    //    Detects remote thread injection (NtCreateThreadEx from different process)
    status = PsSetCreateThreadNotifyRoutine(ThreadCreationCallback);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("!!! FsFilter: Failed to register thread creation callback: 0x%X\n", status);
    }
    else
    {
        g_ThreadNotifyRegistered = TRUE;
        DbgPrint("!!! FsFilter: Thread creation monitoring enabled\n");
    }

    // 4. Register image load callback
    //    Detects DLL injection and driver loading
    status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("!!! FsFilter: Failed to register image load callback: 0x%X\n", status);
    }
    else
    {
        g_ImageNotifyRegistered = TRUE;
        DbgPrint("!!! FsFilter: Image load monitoring enabled (DLL/driver detection)\n");
    }

    DbgPrint("!!! FsFilter: ========================================\n");
    DbgPrint("!!! FsFilter: MONITORING COVERAGE:\n");
    DbgPrint("!!! FsFilter: - Process creation/termination (PsSetCreateProcessNotifyRoutine)\n");
    DbgPrint("!!! FsFilter: - Process/thread handle operations (ObRegisterCallbacks)\n");
    DbgPrint("!!! FsFilter: - Thread creation (PsSetCreateThreadNotifyRoutine)\n");
    DbgPrint("!!! FsFilter: - DLL/driver loading (PsSetLoadImageNotifyRoutine)\n");
    DbgPrint("!!! FsFilter: - File operations (Minifilter callbacks)\n");
    DbgPrint("!!! FsFilter: - Registry operations (CmRegisterCallback)\n");
    DbgPrint("!!! FsFilter: - Memory operations (VMM/hypervisor + dynamic API hooks)\n");
    DbgPrint("!!! FsFilter: ========================================\n");

    // ====================================================================
    // End of monitoring initialization
    // ====================================================================
    
    // Initialize Rootkit Detector
    RootkitDetectorInitialize();
    if (g_WorkItemDeviceObject != NULL) {
        RootkitDetectorSetDeviceObject(g_WorkItemDeviceObject);
    }
    DbgPrint("!!! FsFilter: Rootkit detection engine initialized\n");

    return STATUS_SUCCESS;
}

//
// NEW: Thread creation callback
// Detects remote thread injection
//

VOID ThreadCreationCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
)
{
    UNREFERENCED_PARAMETER(ThreadId);
    
    if (!Create) {
        return; // Only monitor thread creation, not termination
    }
    
    if (driverData == NULL || driverData->isFilterClosed()) {
        return;
    }
    
    HANDLE currentPid = PsGetCurrentProcessId();
    {
        ULONG correlatedSourcePid = 0;
        if (ResolveRemoteThreadCandidate((ULONG)(ULONG_PTR)ProcessId, &correlatedSourcePid))
        {
            currentPid = (HANDLE)(ULONG_PTR)correlatedSourcePid;
        }
        else
        {
            // Keep the legacy code below intact, but only execute it when we
            // have a real creator/target correlation from PROCESS_CREATE_THREAD
            // telemetry. The raw thread notify callback alone cannot identify
            // the creator process reliably.
            return;
        }
    }
    
    // If the thread is being created in a different process, this is remote thread injection
    if (currentPid != ProcessId) {
        DbgPrint("!!! FsFilter: Remote thread creation detected!\n");
        DbgPrint("!!!   Source PID: %lu -> Target PID: %lu, Thread ID: %lu\n",
                 (ULONG)(ULONG_PTR)currentPid,
                 (ULONG)(ULONG_PTR)ProcessId,
                 (ULONG)(ULONG_PTR)ThreadId);
        
        // Check if either process is monitored
        BOOLEAN sourceFound = FALSE;
        BOOLEAN targetFound = FALSE;
        ULONGLONG sourceGid = driverData->GetProcessGid((ULONG)(ULONG_PTR)currentPid, &sourceFound);
        ULONGLONG targetGid = driverData->GetProcessGid((ULONG)(ULONG_PTR)ProcessId, &targetFound);
        
        if (sourceFound || targetFound) {
            NTSTATUS onThreadStatus = OnThreadCreation((ULONG)(ULONG_PTR)currentPid,
                                                      (ULONG)(ULONG_PTR)ProcessId,
                                                      NULL);
            if (NT_SUCCESS(onThreadStatus))
            {
                return;
            }

            // Log to usermode via dedicated remote-thread callback opcode
            PIRP_ENTRY newEntry = new IRP_ENTRY();
            if (newEntry != NULL) {
                PDRIVER_MESSAGE newItem = &newEntry->data;
                newItem->IRP_OP = IRP_KERNEL_REMOTE_THREAD; // 13
                
                // Attribute to the attacker (source process)
                if (sourceFound) {
                    newItem->PID = (ULONG)(ULONG_PTR)currentPid;
                    newItem->Gid = sourceGid;
                } else {
                    newItem->PID = (ULONG)(ULONG_PTR)ProcessId;
                    newItem->Gid = targetGid;
                }
                
                newItem->AttackerPID = (ULONG)(ULONG_PTR)currentPid;
                newItem->AttackerGid = sourceFound ? sourceGid : 0;
                
                // Fill in kernel event info
                newItem->KernelEventInfo.EventType = IRP_KERNEL_REMOTE_THREAD;
                newItem->KernelEventInfo.SourceProcessId = (ULONG)(ULONG_PTR)currentPid;
                newItem->KernelEventInfo.TargetProcessId = (ULONG)(ULONG_PTR)ProcessId;
                KeQuerySystemTimePrecise((PLARGE_INTEGER)&newItem->KernelEventInfo.Timestamp);
                newItem->KernelEventInfo.ThreadHandle = ThreadId;
                newItem->KernelEventInfo.RawArgument1 = (ULONG_PTR)ThreadId;
                newItem->KernelEventInfo.AccessMask = 0x0002; // PROCESS_CREATE_THREAD
                newItem->KernelEventInfo.OperationStatus = STATUS_SUCCESS;
                (VOID)RtlStringCchCopyW(newItem->KernelEventInfo.ObjectName,
                                        RTL_NUMBER_OF(newItem->KernelEventInfo.ObjectName),
                                        L"IRP_KERNEL_REMOTE_THREAD");
                
                if (!driverData->AddIrpMessage(newEntry)) {
                    delete newEntry;
                }
            }
        }
    }
}

//
// NEW: Image load callback
// Detects DLL injection and driver loading
//

VOID ImageLoadCallback(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo)
{
    if (FullImageName == NULL || ImageInfo == NULL || ProcessId == 0)
    {
        return;
    }

    // 1. Detect Kernel Driver Loading (System Mode)
    if (ImageInfo->SystemModeImage)
    {
        DbgPrint("!!! FsFilter: Kernel driver loaded: %wZ\n", FullImageName);
        // ... (logging omitted as per existing code)
        return;
    }


    if (driverData == NULL || driverData->isFilterClosed())
    {
        return;
    }

    // 2. User mode image load telemetry + dynamic API hook refresh.
    // Avoid running full hook refresh on every DLL load; this can stall process loader paths.
    // Keep refresh for main process image only (.exe).
    BOOLEAN isProcessImage = FALSE;
    if (FullImageName->Length > 8) // At least ".exe"
    {
        PWCH pathEnd = (PWCH)((PUCHAR)FullImageName->Buffer + FullImageName->Length - (4 * sizeof(WCHAR)));
        if (_wcsnicmp(pathEnd, L".exe", 4) == 0)
        {
            isProcessImage = TRUE;
        }
    }

    if (isProcessImage)
    {
        BOOLEAN found = FALSE;
        (VOID)driverData->GetProcessGid((ULONG)(ULONG_PTR)ProcessId, &found);
        if (found)
        {
            //
            // FIX: Never call UserModeHookProcess directly from ImageLoadCallback.
            // ImageLoadCallback runs while the process loader lock is held, at an
            // elevated call depth. UserModeHookProcess does KeStackAttachProcess,
            // ZwAllocateVirtualMemory, and ZwCreateFile - all of which can block
            // waiting for APCs or locks already owned on the loader path -> freeze.
            // Queue a DelayedWorkQueue item so it runs on a system worker thread
            // at PASSIVE_LEVEL with no loader lock held.
            //
            // In ImageLoadCallback only — loader lock path genuinely requires deferral
            if (g_WorkItemDeviceObject != NULL)
            {
                PHOOK_PROCESS_WORK_ITEM ctx = (PHOOK_PROCESS_WORK_ITEM)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, sizeof(HOOK_PROCESS_WORK_ITEM), 'wHuM');
                if (ctx != NULL)
                {
                    // IoAllocateWorkItem pins the driver via DeviceObject reference count
                    ctx->WorkItem = IoAllocateWorkItem(g_WorkItemDeviceObject);
                    if (ctx->WorkItem == NULL) {
                        ExFreePoolWithTag(ctx, 'wHuM');
                    } else {
                        ctx->ProcessId = (ULONG)(ULONG_PTR)ProcessId;
                        IoQueueWorkItem(ctx->WorkItem, HookProcessWorkItemRoutine,
                                        DelayedWorkQueue, ctx);
                    }
                }
            }
        }
    }
}

VOID EnumerateExistingProcesses(VOID)
{
    //
    // FIX: Replace the brute-force PID loop (65535 iterations of PsLookupProcessByProcessId)
    // with a single ZwQuerySystemInformation(SystemProcessInformation) call. The old loop
    // caused DriverEntry to block for several seconds, causing sc start to time out.
    //
    if (g_fnZwQuerySystemInformation == NULL)
    {
        DbgPrint("!!! FsFilter: EnumerateExistingProcesses: ZwQuerySystemInformation not resolved\n");
        return;
    }

    NTSTATUS status;
    ULONG bufferSize = 64 * 1024; // Start at 64 KB; grow if needed
    PVOID buffer = NULL;
    ULONG returnLength = 0;

    // Retry up to 4 times in case the snapshot grows between calls
    for (int attempt = 0; attempt < 4; ++attempt)
    {
        buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'EPrW');
        if (buffer == NULL)
        {
            DbgPrint("!!! FsFilter: EnumerateExistingProcesses: allocation failed\n");
            return;
        }

        status = g_fnZwQuerySystemInformation(SystemProcessInformationLocal,
                                              buffer, bufferSize, &returnLength);
        if (status != STATUS_INFO_LENGTH_MISMATCH)
            break;

        // Buffer too small - free and grow
        ExFreePoolWithTag(buffer, 'EPrW');
        buffer = NULL;
        bufferSize = returnLength + 4096;
    }

    if (!NT_SUCCESS(status) || buffer == NULL)
    {
        DbgPrint("!!! FsFilter: EnumerateExistingProcesses: ZwQuerySystemInformation failed 0x%X\n", status);
        if (buffer != NULL)
            ExFreePoolWithTag(buffer, 'EPrW');
        return;
    }

    PSYSTEM_PROCESS_INFORMATION entry = (PSYSTEM_PROCESS_INFORMATION)buffer;
    for (;;)
    {
        ULONG pidNum = (ULONG)(ULONG_PTR)entry->UniqueProcessId;
        ULONG parentPid = (ULONG)(ULONG_PTR)entry->InheritedFromUniqueProcessId;

        // Skip Idle (0) and System (4)
        if (pidNum > 4 && entry->ImageName.Buffer != NULL && entry->ImageName.Length > 0)
        {
            // Allocate a UNICODE_STRING copy for RecordNewProcess (it takes ownership)
            USHORT allocLen = entry->ImageName.Length + sizeof(WCHAR);
            PUNICODE_STRING procName = (PUNICODE_STRING)ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                sizeof(UNICODE_STRING) + allocLen,
                'RW');

            if (procName != NULL)
            {
                procName->Buffer = (PWCH)((PUCHAR)procName + sizeof(UNICODE_STRING));
                procName->Length = entry->ImageName.Length;
                procName->MaximumLength = allocLen;
                RtlCopyMemory(procName->Buffer, entry->ImageName.Buffer, entry->ImageName.Length);
                procName->Buffer[entry->ImageName.Length / sizeof(WCHAR)] = L'\0';

                // No loader lock here; call directly at PASSIVE_LEVEL
                ULONGLONG gid = driverData->RecordNewProcess(procName, pidNum, parentPid);
                (VOID)UserModeHookProcess(pidNum); // direct call, safe here

                PIRP_ENTRY newEntry = new IRP_ENTRY();
                if (newEntry != NULL)
                {
                    newEntry->data.PID = pidNum;
                    newEntry->data.Gid = gid;
                    newEntry->data.ParentPid = parentPid;
                    newEntry->data.IRP_OP = IRP_PROCESS_CREATE;

                    PCWSTR srcPath2 = procName->Buffer;
                    USHORT srcLen2  = procName->Length;
                    WCHAR  dosPathBuf2[MAX_FILE_NAME_LENGTH] = {0};
                    if (srcPath2 != NULL &&
                        NtPathToDosPath(srcPath2, dosPathBuf2, RTL_NUMBER_OF(dosPathBuf2))) {
                        srcPath2 = dosPathBuf2;
                        srcLen2  = (USHORT)(wcslen(dosPathBuf2) * sizeof(WCHAR));
                    }
                    USHORT copyLen = (srcLen2 < MAX_FILE_NAME_SIZE - sizeof(WCHAR))
                                         ? srcLen2
                                         : (MAX_FILE_NAME_SIZE - sizeof(WCHAR));

                    RtlCopyMemory(newEntry->Buffer, srcPath2, copyLen);
                    newEntry->Buffer[copyLen / sizeof(WCHAR)] = L'\0';
                    newEntry->filePath.Length = copyLen;
                    newEntry->filePath.MaximumLength = MAX_FILE_NAME_SIZE;
                    newEntry->filePath.Buffer = newEntry->Buffer;

                    if (!driverData->AddIrpMessage(newEntry))
                    {
                        delete newEntry;
                    }
                }
                // procName is owned by RecordNewProcess, don't free here
            }
        }

        if (entry->NextEntryOffset == 0)
            break;
        entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)entry + entry->NextEntryOffset);
    }

    ExFreePoolWithTag(buffer, 'EPrW');
}

NTSTATUS
 FSUnloadDriver(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
/*++

Routine Description:

    This is the unload routine for the Filter driver.  This unregisters the
    Filter with the filter manager and frees any allocated global data
    structures.

Arguments:

    None.

Return Value:

    Returns the final status of the deallocation routines.

--*/

{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    DbgPrint("FsFilter: Unloading driver\n");

    // Stop new activity first, then detach callbacks to avoid concurrent work
    // while teardown is in progress.
    if (driverData) {
        driverData->setFilterStop();
    }

    if (g_ImageNotifyRegistered) {
        NTSTATUS rmImageStatus = PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
        DbgPrint("!!! FsFilter: PsRemoveLoadImageNotifyRoutine => 0x%X\n", rmImageStatus);
        g_ImageNotifyRegistered = FALSE;
    }

    if (g_ThreadNotifyRegistered) {
        NTSTATUS rmThreadStatus = PsRemoveCreateThreadNotifyRoutine(ThreadCreationCallback);
        DbgPrint("!!! FsFilter: PsRemoveCreateThreadNotifyRoutine => 0x%X\n", rmThreadStatus);
        g_ThreadNotifyRegistered = FALSE;
    }

    if (g_ProcessNotifyRegistered) {
        NTSTATUS rmProcStatus;
        if (g_UseLegacyProcessNotify) {
            rmProcStatus = PsSetCreateProcessNotifyRoutine(AddRemProcessRoutineLegacy, TRUE);
        } else {
            rmProcStatus = PsSetCreateProcessNotifyRoutineEx(AddRemProcessRoutineEx, TRUE);
        }
        DbgPrint("!!! FsFilter: Process notify unregister => 0x%X\n", rmProcStatus);
        g_ProcessNotifyRegistered = FALSE;
    }

    // Process Protection Cleanup (ObUnRegisterCallbacks)
    UninitProcessProtection();

    UserModeHookEngineCleanup();
    FSCleanupPyasWhitelistRules();

    // VMM Cleanup
    OwlyVmmUninitialize();

    // RedDbg control-device cleanup
    RedDbgStopStandaloneControlDriver();

    // Registry Cleanup
    RegeditUnloadDriver();

    // Rootkit detector owns a shared work item and caches the dedicated CDO
    // pointer. Tear it down before freeing driverData or deleting the CDO.
    RootkitDetectorCleanup();

    // Close Communication
    if (commHandle) {
        if (!IsCommClosed()) {
            CommClose();
        }

        // Do not call FltUnregisterFilter() here: we are already running in
        // FilterUnload callback context, and Filter Manager owns unregister.
        commHandle->Filter = NULL;
        delete commHandle;
        commHandle = NULL;
    }

    // Cleanup DriverData
    if (driverData) {
        delete driverData;
        driverData = NULL;
    }
    
    // Delete the dedicated work-item CDO before hook device teardown
    if (g_WorkItemDeviceObject != NULL) {
        IoDeleteDevice(g_WorkItemDeviceObject);
        g_WorkItemDeviceObject = NULL;
    }

    // Tear down independent hook device BEFORE FltUnregisterFilter so the
    // saved FltMgr dispatch pointers stay valid for teardown IRPs.
    CleanupHookNotifyDevice();

    return STATUS_SUCCESS;
}

NTSTATUS
FSInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
/*++

Routine Description:

This routine is called whenever a new instance is created on a volume. This
gives us a chance to decide if we need to attach to this volume or not.

If this routine is not defined in the registration structure, automatic
instances are always created.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Flags describing the reason for this attach request.

Return Value:

STATUS_SUCCESS - attach
STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    DbgPrint("FSFIlter: Entered FSInstanceSetup\n");

    // BUG FIX: NMI_HARDWARE_FAILURE (0x80)
    //
    // The previous code did:
    //   WCHAR newTemp[40];
    //   GvolumeData.Buffer = newTemp;   // <-- stack address
    //   IoVolumeDeviceToDosName(..., &GvolumeData);
    //   if (!NT_SUCCESS(hr)) return;    // <-- returns with GvolumeData.Buffer still = newTemp!
    //
    // IoVolumeDeviceToDosName allocates a new pool buffer and writes it into
    // GvolumeData.Buffer when it SUCCEEDS.  When it FAILS (network shares,
    // named pipes, etc.) it does NOT touch GvolumeData.Buffer — so the
    // pointer remained pointing at newTemp, a stack frame that no longer
    // exists once FSInstanceSetup returned.  GvolumeData is a global, so
    // every subsequent filter callback reading GvolumeData.Buffer dereferenced
    // that dangling pointer, corrupting kernel memory → NMI.
    //
    // Secondary bug: on the success path IoVolumeDeviceToDosName replaces
    // GvolumeData.Buffer with a pool allocation.  The next FSInstanceSetup
    // call overwrote that pointer with a new stack buffer before freeing
    // the old one → non-paged pool leak.
    //
    // Fix:
    //   1. Free any pool buffer left by a prior successful call.
    //   2. Zero GvolumeData BEFORE calling IoVolumeDeviceToDosName so that
    //      Buffer is NULL if the call fails — no dangling pointer possible.
    //   3. Never pre-assign a stack buffer to GvolumeData.Buffer.

    if (GvolumeData.Buffer != NULL)
    {
        // Was allocated by IoVolumeDeviceToDosName in a prior successful call.
        ExFreePool(GvolumeData.Buffer);
    }
    RtlZeroMemory(&GvolumeData, sizeof(GvolumeData));

    NTSTATUS hr = STATUS_SUCCESS;
    PDEVICE_OBJECT devObject;
    hr = FltGetDiskDeviceObject(FltObjects->Volume, &devObject);
    if (!NT_SUCCESS(hr))
    {
        // Not a disk device - skip attachment (e.g., named pipes, network shares)
        return STATUS_SUCCESS;
    }

    // Validate device object before calling IoVolumeDeviceToDosName
    // to avoid STATUS_OBJECT_NAME_NOT_FOUND on non-disk volumes.
    if (!devObject)
    {
        return STATUS_SUCCESS;
    }

    hr = IoVolumeDeviceToDosName(devObject, &GvolumeData);
    ObDereferenceObject(devObject);
    if (!NT_SUCCESS(hr))
    {
        // GvolumeData.Buffer is NULL (zeroed above) — no dangling pointer.
        // Return success: volumes without DOS names (network shares, pipes)
        // are silently skipped; the filter still attaches to them.
        return STATUS_SUCCESS;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
FSInstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
/*++

Routine Description:

This is called when an instance is being manually deleted by a
call to FltDetachVolume or FilterDetach thereby giving us a
chance to fail that detach request.

If this routine is not defined in the registration structure, explicit
detach requests via FltDetachVolume or FilterDetach will always be
failed.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Indicating where this detach request came from.

Return Value:

Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    DbgPrint("FSFIlter: Entered FSInstanceQueryTeardown\n");

    return STATUS_SUCCESS;
}

VOID FSInstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
/*++

Routine Description:

This routine is called at the start of instance teardown.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Reason why this instance is being deleted.

Return Value:

None.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    DbgPrint("FSFIlter: Entered FSInstanceTeardownStart\n");
}

VOID FSInstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
/*++

Routine Description:

This routine is called at the end of instance teardown.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Reason why this instance is being deleted.

Return Value:

None.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    DbgPrint("FSFIlter: Entered FSInstanceTeardownComplete\n");
}

FLT_PREOP_CALLBACK_STATUS
FSPreOperation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
               _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
/*++

Routine Description:

    Pre operations callback

Arguments:

    Data - The structure which describes the operation parameters.

    FltObject - The structure which describes the objects affected by this
        operation.

    CompletionContext - Output parameter which can be used to pass a context
        from this pre-create callback to the post-create callback.

    Return Value:

   FLT_PREOP_SUCCESS_WITH_CALLBACK - If this is not our user-mode process.
   FLT_PREOP_SUCCESS_NO_CALLBACK - All other threads.

--*/
{
    NTSTATUS hr = STATUS_SUCCESS;
    if (FltGetRequestorProcessId(Data) == 4)
        return FLT_PREOP_SUCCESS_NO_CALLBACK; // system process -  skip
    if (FltGetRequestorProcessId(Data) == driverData->getPID())
    {
        if (IS_DEBUG_IRP)
            DbgPrint("!!! FsFilter: Allowing pre op for trusted process, no post op\n");

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (FltObjects->FileObject == NULL)
    { // no file object
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    // create tested only on post op, cant check here
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE)
    {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    
    hr = FSProcessPreOperation(Data, FltObjects, CompletionContext);
    if (hr == FLT_PREOP_SUCCESS_WITH_CALLBACK || hr == FLT_PREOP_COMPLETE)
        return (FLT_PREOP_CALLBACK_STATUS)hr;

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS
FSProcessPreOperation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                       _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    // NO COMMUNICATION CHECK (kept same as original)
    if (driverData->isFilterClosed() || IsCommClosed())
    {
        // Debug logging is commented out or controlled by IS_DEBUG_IRP
        // DbgPrint("!!! FsFilter: Filter is closed or Port is closed, skipping data\n"); // Keeping user's DbgPrint
        // here
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    NTSTATUS hr = FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION nameInfo;
    hr = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
                                   &nameInfo);
    if (!NT_SUCCESS(hr))
        return hr;

    BOOLEAN isDir;
    hr = FltIsDirectory(Data->Iopb->TargetFileObject, Data->Iopb->TargetInstance, &isDir);
    if (!NT_SUCCESS(hr))
    {
        FltReleaseFileNameInformation(nameInfo);
        return hr;
    }
    if (isDir)
    {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL)
    {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_INSUFFICIENT_RESOURCES; // Return error on alloc failure
    }

    // reset
    PDRIVER_MESSAGE newItem = &newEntry->data;
    PUNICODE_STRING FilePath = &(newEntry->filePath);

    // FltGetFileNameInformation returns a referenced pointer.
    // Ownership stays with this caller and must be released exactly once on every exit path.

    hr = GetFileNameInfo(FltObjects, FilePath, nameInfo);
    if (!NT_SUCCESS(hr))
    {
        FltReleaseFileNameInformation(nameInfo);
        delete newEntry;
        return hr;
    }

    // Check if the file is in the quarantine directory
    if (driverData->IsPathInQuarantineDir(FilePath)) {
        // If the requesting process is NOT the trusted Owlyshield process
        if (FltGetRequestorProcessId(Data) != driverData->getPID()) {
            DbgPrint("!!! FsFilter: Blocking access to quarantine folder for untrusted process (PID: %u)\n", FltGetRequestorProcessId(Data));
            FltReleaseFileNameInformation(nameInfo);
            delete newEntry;
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE; // Block the operation
        } else {
            DbgPrint("!!! FsFilter: Allowing access to quarantine folder for trusted Owlyshield process (PID: %u)\n", FltGetRequestorProcessId(Data));
            // Allow Owlyshield to perform operations on files in quarantine
            // We still need to release nameInfo and delete newEntry if we're not going to process it further
            FltReleaseFileNameInformation(nameInfo);
            delete newEntry;
            return FLT_PREOP_SUCCESS_NO_CALLBACK; // Allow and don't send to post-op
        }
    }
    if (FSShouldIgnorePyasWhitelistPath(FilePath))
    {
        FltReleaseFileNameInformation(nameInfo);
        delete newEntry;
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // --- KERNEL-MODE PATH BLOCKING ---
    if (driverData->IsPathBlocked(FilePath)) {
        DbgPrint("!!! FsFilter: BLOCKING access to path: %wZ (Kernel-Mode Block)\n", FilePath);
        FltReleaseFileNameInformation(nameInfo);
        delete newEntry;
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    const BOOLEAN isProtectedPath = driverData->IsContainingDirectory(FilePath);

    // get pid
    newItem->PID = FltGetRequestorProcessId(Data);

    BOOLEAN isGidFound;
    ULONGLONG gid = driverData->GetProcessGid(newItem->PID, &isGidFound);
    if (gid == 0 || !isGidFound)
    {
        // --- START DISCOVERY LOGIC ---
        // If the PID is not tracked, it might be a process that was already running 
        // when the driver loaded. Let's try to discover it now.
        PEPROCESS process = NULL;
        hr = PsLookupProcessByProcessId((HANDLE)newItem->PID, &process);
        if (NT_SUCCESS(hr)) {
            PUNICODE_STRING procPath = NULL;
            // SeLocateProcessImageName is safe to call here
            hr = SeLocateProcessImageName(process, &procPath);
            if (NT_SUCCESS(hr) && procPath != NULL) {
                // Record the process in our system
                gid = driverData->RecordNewProcess(procPath, newItem->PID, 0); // Use 0 for ParentPid as we don't know it
                isGidFound = TRUE;
                DbgPrint("!!! FsFilter: DISCOVERED untracked process. PID: %u, Path: %wZ, GID: %llu\n", newItem->PID, procPath, gid);

                // Inform usermode about this new process discovery
                PIRP_ENTRY discoveryEntry = new IRP_ENTRY();
                if (discoveryEntry != NULL) {
                    PDRIVER_MESSAGE discoveryMsg = &discoveryEntry->data;
                    discoveryMsg->PID = newItem->PID;
                    discoveryMsg->Gid = gid;
                    discoveryMsg->IRP_OP = IRP_PROCESS_CREATE; // Treat as a creation event

                    USHORT copyLen = (procPath->Length < MAX_FILE_NAME_SIZE) ? procPath->Length : (MAX_FILE_NAME_SIZE - sizeof(WCHAR));
                    RtlCopyMemory(discoveryEntry->Buffer, procPath->Buffer, copyLen);
                    discoveryEntry->Buffer[copyLen / 2] = L'\0';
                    discoveryEntry->filePath.Length = copyLen;
                    discoveryEntry->filePath.MaximumLength = MAX_FILE_NAME_SIZE;
                    discoveryEntry->filePath.Buffer = discoveryEntry->Buffer;

                    if (!driverData->AddIrpMessage(discoveryEntry)) {
                        delete discoveryEntry;
                    }
                }
            }
            ObDereferenceObject(process);
        }

        if (!isGidFound) {
            if (IS_DEBUG_IRP)
                DbgPrint("!!! FsFilter: Item does not have a gid, skipping after discovery attempt\n");
            FltReleaseFileNameInformation(nameInfo);
            delete newEntry;
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }

    if (IS_DEBUG_IRP)
        DbgPrint("!!! FsFilter: Registring new irp for Gid: %d with pid: %d\n", (ULONG)gid, newItem->PID);
    newItem->Gid = gid;

    // get file id
    hr = CopyFileIdInfo(Data, newItem);
    if (!NT_SUCCESS(hr))
    {
        FltReleaseFileNameInformation(nameInfo);
        delete newEntry;
        return hr;
    }

    if (isProtectedPath)
    {
        // Keeping user's DbgPrint here
        if (IS_DEBUG_IRP)
            DbgPrint("!!! FsFilter: File in scan area \n");
        newItem->FileLocationInfo = FILE_PROTECTED;
    }

    if (Data->Iopb->MajorFunction == IRP_MJ_READ || Data->Iopb->MajorFunction == IRP_MJ_WRITE)
    {
        CopyExtension(newItem->Extension, nameInfo);
    }

    // Keeping user's DbgPrint here
    if (IS_DEBUG_IRP)
        DbgPrint("!!! FsFilter: Logging IRP op: %s \n", FltGetIrpName(Data->Iopb->MajorFunction));

    // Release nameInfo only if not IRP_MJ_SET_INFORMATION (which might need it later)
    if (Data->Iopb->MajorFunction != IRP_MJ_SET_INFORMATION)
        FltReleaseFileNameInformation(nameInfo);

    switch (Data->Iopb->MajorFunction)
    {
    case IRP_MJ_READ: {
        newItem->IRP_OP = IRP_READ;
        if (Data->Iopb->Parameters.Read.Length == 0) // no data to read
        {
            // Fix: Clean up memory before returning (user's original code leaked memory here)
            delete newEntry;
            // Keeping user's DbgPrint here
            DbgPrint("FsFilter: IRP READ NOCALLBACK LENGTH IS ZERO! \n");
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        if (FSShouldBypassReadTelemetry(Data))
        {
            delete newEntry;
            if (IS_DEBUG_IRP)
                DbgPrint("!!! FsFilter: Skipping post-read telemetry for paging/kernel MM read path\n");
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        // Keeping user's DbgPrint here
        if (IS_DEBUG_IRP)
            DbgPrint("!!! FsFilter: Preop IRP_MJ_READ, return with postop \n");
        // save context for post, we calculate the entropy of read, we pass the irp to application on post op
        *CompletionContext = newEntry;
        // Keeping user's DbgPrint here
        if (IS_DEBUG_IRP)
            DbgPrint("FsFilter: IRP READ WITH CALLBACK! ****************** \n");
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    case IRP_MJ_CLEANUP:
        newItem->IRP_OP = IRP_CLEANUP;
        break;
    case IRP_MJ_WRITE: {
        newItem->IRP_OP = IRP_WRITE;


        if (Data->Iopb->Parameters.Write.Length == 0) // no data to write
        {
            // Fix: Clean up memory and return
            delete newEntry;
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        PVOID writeBuffer = NULL;
        // prepare buffer for entropy calc
        if (Data->Iopb->Parameters.Write.MdlAddress == NULL)
        { // there's mdl buffer, we use it
            writeBuffer = Data->Iopb->Parameters.Write.WriteBuffer;
        }
        else
        {
            writeBuffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Write.MdlAddress,
                                                       NormalPagePriority | MdlMappingNoExecute);
        }
        if (writeBuffer == NULL)
        { // alloc failed
            delete newEntry;
            // fail the irp request
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        newItem->MemSizeUsed = Data->Iopb->Parameters.Write.Length;

        // CRITICAL FIX: Floating Point State Protection for RECURSIVE_NMI (0x111)
        KFLOATING_SAVE floatingSave;
        BOOLEAN fpuStateSaved = FALSE;
        NTSTATUS fpStatus = STATUS_SUCCESS;

        // 1. Try to save FPU state
        fpStatus = KeSaveFloatingPointState(&floatingSave);

        if (NT_SUCCESS(fpStatus))
        {
            fpuStateSaved = TRUE;
            // 2. Perform the floating point operation (entropy calculation)
            __try
            {
                newItem->Entropy = shannonEntropy((PUCHAR)writeBuffer, newItem->MemSizeUsed);
                newItem->isEntropyCalc = TRUE;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                // Keeping user's DbgPrint here
                if (IS_DEBUG_IRP)
                    DbgPrint("!!! FsFilter: Failed to calc entropy (Exception caught, IRP failing)\n");

                // CRITICAL: Ensure FPU state is restored even on exception path before returning
                if (fpuStateSaved)
                {
                    KeRestoreFloatingPointState(&floatingSave);
                    fpuStateSaved = FALSE; // Mark as restored
                }

                delete newEntry;
                // fail the irp request, as requested by original logic
                Data->IoStatus.Status = STATUS_INTERNAL_ERROR;
                Data->IoStatus.Information = 0;
                return FLT_PREOP_COMPLETE;
            }
            // 3. Restore FPU state if the try block succeeded
            if (fpuStateSaved)
            {
                KeRestoreFloatingPointState(&floatingSave);
                fpuStateSaved = FALSE; // Mark as restored
            }
        }
        else
        {
            // If FPU state couldn't be saved, skip calculation and continue without entropy.
            if (IS_DEBUG_IRP)
                DbgPrint("!!! FsFilter: Failed to save FPU state (Status: 0x%X), skipping entropy calculation\n",
                         fpStatus);
            newItem->isEntropyCalc = FALSE;
            newItem->Entropy = 0;
            // Note: fpuStateSaved is false, so no restore needed.
        }
    }
    break;
    case IRP_MJ_SET_INFORMATION: {
        newItem->IRP_OP = IRP_SETINFO;
        // we check for delete later and renaming
        FILE_INFORMATION_CLASS fileInfo = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

        if (fileInfo == FileDispositionInformation && // handle delete later
            (((PFILE_DISPOSITION_INFORMATION)(Data->Iopb->Parameters.SetFileInformation.InfoBuffer))->DeleteFile))
        {
            newItem->FileChange = FILE_CHANGE_DELETE_FILE;
        } // end delete 1

        else if (fileInfo == FileDispositionInformationEx &&
                 FlagOn(
                     ((PFILE_DISPOSITION_INFORMATION_EX)(Data->Iopb->Parameters.SetFileInformation.InfoBuffer))->Flags,
                     FILE_DISPOSITION_DELETE))
        {
            newItem->FileChange = FILE_CHANGE_DELETE_FILE;
        } // end delete 2

        else if (fileInfo == FileRenameInformation || fileInfo == FileRenameInformationEx)
        {
            // OPTIONAL: get new name?

            newItem->FileChange = FILE_CHANGE_RENAME_FILE;
            PFILE_RENAME_INFORMATION renameInfo =
                (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            PFLT_FILE_NAME_INFORMATION newNameInfo;
            WCHAR Buffer[MAX_FILE_NAME_LENGTH];
            UNICODE_STRING NewFilePath;
            NewFilePath.Buffer = Buffer;
            NewFilePath.Length = 0;
            NewFilePath.MaximumLength = MAX_FILE_NAME_SIZE;

            hr = FltGetDestinationFileNameInformation(
                FltObjects->Instance, FltObjects->FileObject, renameInfo->RootDirectory, renameInfo->FileName,
                renameInfo->FileNameLength,
                FLT_FILE_NAME_QUERY_DEFAULT | FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER | FLT_FILE_NAME_OPENED,
                &newNameInfo);
            if (!NT_SUCCESS(hr))
            {
                delete newEntry;
                FltReleaseFileNameInformation(nameInfo);
                return hr;
            }

            NTSTATUS status = GetFileNameInfo(FltObjects, &NewFilePath, newNameInfo);
            if (!NT_SUCCESS(status))
            {
                delete newEntry;
                FltReleaseFileNameInformation(nameInfo);
                FltReleaseFileNameInformation(newNameInfo);
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }

            RtlCopyBytes(newEntry->Buffer, Buffer,
                         MAX_FILE_NAME_SIZE); // replace buffer data with new file
            newItem->FileLocationInfo = FILE_MOVED_OUT;
            /*
        if (FSIsFileNameInScanDirs(&NewFilePath)) {
            if (newItem->FileLocationInfo == FILE_NOT_PROTECTED) { // moved in - report new file name
                newItem->FileLocationInfo = FILE_MOVED_IN;
                //newEntry->filePath = NewFilePath; // remember file moved in
                RtlCopyBytes(newEntry->Buffer, Buffer, MAX_FILE_NAME_SIZE); // replace buffer data with new file
            } // else we still report old file name so we know it was changed
        }
        else { // new file name not protected
            if (newItem->FileLocationInfo == FILE_PROTECTED) { // moved out - report old file name
                newItem->FileLocationInfo = FILE_MOVED_OUT;
            }
            /*else { // we dont care - rename of file in unprotected area to unprotected area
                delete newEntry;
                FltReleaseFileNameInformation(nameInfo);
                FltReleaseFileNameInformation(newNameInfo);
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
        }
        */

            CopyExtension(newItem->Extension, newNameInfo);
            FltReleaseFileNameInformation(newNameInfo);
            for (LONG i = 0; i < FILE_OBJEC_MAX_EXTENSION_SIZE; i++)
            {
                if (i == (nameInfo->Extension.Length / 2))
                    break;
                if (newItem->Extension[i] != nameInfo->Extension.Buffer[i])
                {
                    newItem->FileChange = FILE_CHANGE_EXTENSION_CHANGED;
                    break;
                }
            }
            FltReleaseFileNameInformation(nameInfo);
        } // end rename
        else // not rename or delete (set info)
        {
            // Note: nameInfo was not released outside the switch block, so we release it here if we abandon the IRP
            delete newEntry;
            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        break;
    }
    default:
        // Note: nameInfo was not released outside the switch block, so we release it here if we abandon the IRP
        if (Data->Iopb->MajorFunction != IRP_MJ_SET_INFORMATION) // Already released if not SET_INFORMATION
        {                                                        /* Do nothing */
        }
        else
        {
            FltReleaseFileNameInformation(nameInfo);
        }
        delete newEntry;
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Keeping user's DbgPrint here
    if (IS_DEBUG_IRP)
        DbgPrint("!!! FsFilter: Adding entry to irps %s\n", FltGetIrpName(Data->Iopb->MajorFunction));

    if (!driverData->AddIrpMessage(newEntry))
    {
        delete newEntry;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
FSPostOperation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
/*++

Routine Description:

    Post opeartion callback. we reach here in case of IRP_MJ_CREATE or IRP_MJ_READ

Arguments:

    Data - The structure which describes the operation parameters.

    FltObject - The structure which describes the objects affected by this
        operation.

    CompletionContext - The operation context passed fron the pre-create
        callback.

    Flags - Flags to say why we are getting this post-operation callback.

Return Value:

    FLT_POSTOP_FINISHED_PROCESSING - ok to open the file or we wish to deny
                                     access to this file, hence undo the open

--*/
{
    // DbgPrint("!!! FsFilter: Enter post op for irp: %s, pid of process: %u\n",
    // FltGetIrpName(Data->Iopb->MajorFunction), FltGetRequestorProcessId(Data));

    if (!NT_SUCCESS(Data->IoStatus.Status) || (STATUS_REPARSE == Data->IoStatus.Status))
    {
        // DbgPrint("!!! FsFilter: finished post operation, already failed \n");
        if (CompletionContext != nullptr && Data->Iopb->MajorFunction == IRP_MJ_READ)
        {
            delete (PIRP_ENTRY)CompletionContext;
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE)
    {
        return FSProcessCreateIrp(Data, FltObjects);
    }
    else if (Data->Iopb->MajorFunction == IRP_MJ_READ)
    {
        // FIX: Ensure CompletionContext exists before using it
        if (CompletionContext == nullptr) {
             return FLT_POSTOP_FINISHED_PROCESSING;
        }

        if (FSShouldBypassReadTelemetry(Data)) {
            delete (PIRP_ENTRY)CompletionContext;
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        if (Data->Iopb->Parameters.Read.Length == 0)
        {
            // FIX: 'newEntry' is undefined here. We delete the context passed in.
            delete (PIRP_ENTRY)CompletionContext;
            
            // FIX: Must return POSTOP status, not PREOP status
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
        
        // FIX: In PostOp, we don't assign *CompletionContext = ... 
        // We simply pass the existing CompletionContext to our helper function.
        // *CompletionContext = newEntry; 

        // DEBUG LOG ONLY IF NOT IN RECURSIVE CONTEXT
        // FIX: Ensure IS_DEBUG_IRP is defined in your header
        #ifdef IS_DEBUG_IRP
        if (!KeIsExecutingDpc()) // prevent recursion in DPC or debug trap
            DbgPrint("FsFilter: IRP READ WITH CALLBACK! ****************** \n");
        #endif

        // FIX: Removed early 'return FLT_PREOP_SUCCESS_WITH_CALLBACK' here 
        // so the code below can actually execute.

        // return FLT_POSTOP_FINISHED_PROCESSING;
        return FSProcessPostReadIrp(Data, FltObjects, CompletionContext, Flags);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
FSProcessCreateIrp(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    NTSTATUS hr;
    if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY) ||
        FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (driverData->isFilterClosed() || IsCommClosed())
    {
        // DbgPrint("!!! FsFilter: filter closed or comm closed, skip irp\n");
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    BOOLEAN isDir;
    hr = FltIsDirectory(Data->Iopb->TargetFileObject, Data->Iopb->TargetInstance, &isDir);
    if (!NT_SUCCESS(hr))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo;
    hr = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
                                   &nameInfo);
    if (!NT_SUCCESS(hr))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL)
    {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    PDRIVER_MESSAGE newItem = &newEntry->data;

    newItem->PID = FltGetRequestorProcessId(Data);
    newItem->IRP_OP = IRP_CREATE;
    PUNICODE_STRING FilePath = &(newEntry->filePath);

    BOOLEAN isGidFound;
    ULONGLONG gid = driverData->GetProcessGid(newItem->PID, &isGidFound);
    if (gid == 0 || !isGidFound)
    {
        // --- START DISCOVERY LOGIC ---
        PEPROCESS process = NULL;
        hr = PsLookupProcessByProcessId((HANDLE)newItem->PID, &process);
        if (NT_SUCCESS(hr)) {
            PUNICODE_STRING procPath = NULL;
            hr = SeLocateProcessImageName(process, &procPath);
            if (NT_SUCCESS(hr) && procPath != NULL) {
                gid = driverData->RecordNewProcess(procPath, newItem->PID, 0);
                isGidFound = TRUE;
                DbgPrint("!!! FsFilter: DISCOVERED untracked process in PostCreate. PID: %u, Path: %wZ, GID: %llu\n", newItem->PID, procPath, gid);
            }
            ObDereferenceObject(process);
        }

        if (!isGidFound) {
            // DbgPrint("!!! FsFilter: Item does not have a gid, skipping\n");
            FltReleaseFileNameInformation(nameInfo);
            delete newEntry;
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
    }
    newItem->Gid = gid;
    if (IS_DEBUG_IRP)
        DbgPrint("!!! FsFilter: Registring new irp for Gid: %llu with pid: %d\n", gid,
                 newItem->PID); // TODO: incase it doesnt exist we can add it with our method that checks for system process

    // get file id
    hr = CopyFileIdInfo(Data, newItem);
    if (!NT_SUCCESS(hr))
    {
        FltReleaseFileNameInformation(nameInfo);
        delete newEntry;
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    hr = GetFileNameInfo(FltObjects, FilePath, nameInfo);
    if (!NT_SUCCESS(hr))
    {
        FltReleaseFileNameInformation(nameInfo);
        delete newEntry;
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    CopyExtension(newItem->Extension, nameInfo);

    if (FSShouldIgnorePyasWhitelistPath(FilePath))
    {
        FltReleaseFileNameInformation(nameInfo);
        delete newEntry;
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (driverData->IsContainingDirectory(FilePath))
    {
        newItem->FileLocationInfo = FILE_PROTECTED;
    }

    FltReleaseFileNameInformation(nameInfo);

    /*
    if (!FSIsFileNameInScanDirs(FilePath)) {
        if (IS_DEBUG_IRP) DbgPrint("!!! FsFilter: Skipping uninterented file, not in scan area \n");
        delete newEntry;
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    */

    if (isDir && (Data->IoStatus.Information) == FILE_OPENED)
    {
        if (IS_DEBUG_IRP)
            DbgPrint("!!! FsFilter: Dir listing opened on existing directory\n");
        newItem->FileChange = FILE_OPEN_DIRECTORY;
    }
    else if (isDir)
    {
        if (IS_DEBUG_IRP)
            DbgPrint("!!! FsFilter: Dir but not listing, not importent \n");
        delete newEntry;
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    else if ((Data->IoStatus.Information) == FILE_OVERWRITTEN || (Data->IoStatus.Information) == FILE_SUPERSEDED)
    {
        newItem->FileChange = FILE_CHANGE_OVERWRITE_FILE;
    }
    else if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE))
    {
        newItem->FileChange = FILE_CHANGE_DELETE_FILE;
        if ((Data->IoStatus.Information) == FILE_CREATED)
        {
            newItem->FileChange = FILE_CHANGE_DELETE_NEW_FILE;
        }
    }
    else if ((Data->IoStatus.Information) == FILE_CREATED)
    {
        newItem->FileChange = FILE_CHANGE_NEW_FILE;
    }
    if (IS_DEBUG_IRP)
        DbgPrint("!!! FsFilter: Adding entry to irps\n");
    if (!driverData->AddIrpMessage(newEntry))
    {
        delete newEntry;
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
FSProcessPostReadIrp(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                     _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    if (CompletionContext == NULL)
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PIRP_ENTRY entry = (PIRP_ENTRY)CompletionContext;

    if (FSShouldBypassReadTelemetry(Data))
    {
        delete entry;
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (driverData->isFilterClosed() || IsCommClosed())
    {
        if (IS_DEBUG_IRP)
            DbgPrint("!!! FsFilter: Post op read, comm or filter closed\n");
        delete entry;
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    FLT_POSTOP_CALLBACK_STATUS status = FLT_POSTOP_FINISHED_PROCESSING;

    PVOID ReadBuffer = NULL;

    // prepare buffer for entropy calc
    if (Data->Iopb->Parameters.Read.MdlAddress != NULL)
    { // there's mdl buffer, we use it
        ReadBuffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Read.MdlAddress,
                                                  NormalPagePriority | MdlMappingNoExecute);
    }
    else if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER)) // safe
    {
        ReadBuffer = Data->Iopb->Parameters.Read.ReadBuffer;
    }
    else
    {
        if (FltDoCompletionProcessingWhenSafe(Data, FltObjects, CompletionContext, Flags, FSProcessPostReadSafe,
                                              &status))
        { // post to worker thread or run if irql is ok
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
        else
        {
            entry->data.isEntropyCalc = FALSE;
            entry->data.Entropy = 0;
            entry->data.MemSizeUsed = (ULONG)Data->IoStatus.Information;
            if (!driverData->AddIrpMessage(entry))
            {
                delete entry;
            }
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
    }
    if (!ReadBuffer)
    {
        entry->data.isEntropyCalc = FALSE;
        entry->data.Entropy = 0;
        entry->data.MemSizeUsed = (ULONG)Data->IoStatus.Information;
        if (!driverData->AddIrpMessage(entry))
        {
            delete entry;
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    entry->data.MemSizeUsed = (ULONG)Data->IoStatus.Information; // successful read data
    // we catch EXCEPTION_EXECUTE_HANDLER so to prevent crash when calculating
    KFLOATING_SAVE floatingSave;
    BOOLEAN fpuStateSaved = FALSE;
    NTSTATUS fpStatus = KeSaveFloatingPointState(&floatingSave);

    if (NT_SUCCESS(fpStatus))
    {
        fpuStateSaved = TRUE;
        __try
        {
            entry->data.Entropy = shannonEntropy((PUCHAR)ReadBuffer, Data->IoStatus.Information);
            entry->data.isEntropyCalc = TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            entry->data.isEntropyCalc = FALSE;
            entry->data.Entropy = 0;
        }
        if (fpuStateSaved)
        {
            KeRestoreFloatingPointState(&floatingSave);
            fpuStateSaved = FALSE;
        }
    }
    else
    {
        if (IS_DEBUG_IRP)
            DbgPrint("!!! FsFilter: Failed to save FPU state on Read (Status: 0x%X), skipping entropy calculation\n",
                     fpStatus);
        entry->data.isEntropyCalc = FALSE;
        entry->data.Entropy = 0;
    }
    if (IS_DEBUG_IRP)
        DbgPrint("!!! FsFilter: Addung entry to irps IRP_MJ_READ\n");
    if (!driverData->AddIrpMessage(entry))
    {
        delete entry;
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
FSProcessPostReadSafe(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                      _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(FltObjects);

    NTSTATUS status = STATUS_SUCCESS;
    PIRP_ENTRY entry = (PIRP_ENTRY)CompletionContext;
    if (entry == nullptr) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (FSShouldBypassReadTelemetry(Data))
    {
        delete entry;
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    ASSERT(entry != nullptr);
    status = FltLockUserBuffer(Data);
    if (NT_SUCCESS(status))
    {
        PVOID ReadBuffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Read.MdlAddress,
                                                        NormalPagePriority | MdlMappingNoExecute);
        if (ReadBuffer != NULL)
        {
            entry->data.MemSizeUsed = Data->IoStatus.Information; // successful read data.

            KFLOATING_SAVE floatingSave;
            BOOLEAN fpuStateSaved = FALSE;
            NTSTATUS fpStatus = KeSaveFloatingPointState(&floatingSave);

            if(NT_SUCCESS(fpStatus))
            {
                fpuStateSaved = TRUE;
                __try
                {
                    entry->data.Entropy = shannonEntropy((PUCHAR)ReadBuffer, Data->IoStatus.Information);
                    entry->data.isEntropyCalc = TRUE;
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    // Entropy calculation failed. Reset flags.
                    entry->data.isEntropyCalc = FALSE;
                    entry->data.Entropy = 0;
                    status = STATUS_INTERNAL_ERROR; // Indicate an internal error happened
                }
                if (fpuStateSaved)
                {
                    KeRestoreFloatingPointState(&floatingSave);
                    fpuStateSaved = FALSE;
                }
            }
            else
            {
                // Failed to save FPU state, skip entropy calculation
                entry->data.isEntropyCalc = FALSE;
                entry->data.Entropy = 0;
            }

            if (IS_DEBUG_IRP)
                DbgPrint("!!! FsFilter: Adding entry to irps IRP_MJ_READ (Safe)\n");

            if (NT_SUCCESS(status) && driverData->AddIrpMessage(entry))
            {
                // Successfully added message, don't delete entry here.
                return FLT_POSTOP_FINISHED_PROCESSING;
            }
            // If we reached here, either status was not SUCCESS, or AddIrpMessage failed.
            // In either case, fall through to delete entry.
        } // End of if (ReadBuffer != NULL)

    }
    entry->data.isEntropyCalc = FALSE;
    entry->data.Entropy = 0;
    entry->data.MemSizeUsed = (ULONG)Data->IoStatus.Information;
    if (!driverData->AddIrpMessage(entry))
    {
        delete entry;
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

BOOLEAN
FSShouldIgnorePyasWhitelistPath(_In_ PCUNICODE_STRING Path)
{
    WCHAR normalizedPathBuffer[MAX_FILE_NAME_LENGTH] = {0};
    UNICODE_STRING normalizedPath;
    BOOLEAN matched = FALSE;

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0)
    {
        return FALSE;
    }

    if (KeGetCurrentIrql() == PASSIVE_LEVEL && !g_PyasWhitelistRules.Loaded)
    {
        FSLoadPyasWhitelistRules();
    }

    if (!OwlyNormalizePathForMatch(Path, normalizedPathBuffer, &normalizedPath))
    {
        return FALSE;
    }

    FSEnsurePyasRuleMutex();
    ExAcquireFastMutex(&g_PyasWhitelistRules.Mutex);
    for (ULONG i = 0; i < g_PyasWhitelistRules.Count; ++i)
    {
        PCWSTR rule = g_PyasWhitelistRules.Rules[i];
        if (rule != NULL && rule[0] != L'\0' && wcsstr(normalizedPath.Buffer, rule) != NULL)
        {
            matched = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_PyasWhitelistRules.Mutex);

    return matched;
}

BOOLEAN
FSIsFileNameInScanDirs(CONST PUNICODE_STRING path)
{
    if (FSShouldIgnorePyasWhitelistPath(path))
    {
        return FALSE;
    }

    return driverData->IsContainingDirectory(path);
}

NTSTATUS
FSEntrySetFileName(CONST PFLT_VOLUME Volume, PFLT_FILE_NAME_INFORMATION nameInfo, PUNICODE_STRING uString)
{
    NTSTATUS hr = STATUS_SUCCESS;
    PDEVICE_OBJECT devObject = NULL;
    USHORT volumeDosNameSize;
    USHORT finalNameSize;
    USHORT volumeNameSize = nameInfo->Volume.Length; // in bytes
    USHORT origNameSize = nameInfo->Name.Length;     // in bytes

    // --- START: MODIFICATION ---

    // Use a local variable for the volume's DOS name.
    // Initialize to zero so that Buffer is NULL and safely freed if the call fails.
    UNICODE_STRING volumeData;
    RtlZeroMemory(&volumeData, sizeof(volumeData));

    if (uString == NULL)
    {
        return STATUS_INVALID_ADDRESS;
    }

    hr = FltGetDiskDeviceObject(Volume, &devObject);
    if (NT_SUCCESS(hr) && devObject != NULL && !KeAreAllApcsDisabled())
    {
        hr = IoVolumeDeviceToDosName(devObject, &volumeData);
    }
    else
    {
        hr = STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(hr))
    {
        // Preserve device/provider paths when there is no DOS mount point. This
        // keeps ESP and raw-device activity visible to the user-mode engine.
        hr = RtlUnicodeStringCopy(uString, &nameInfo->Name);
        goto cleanup;
    }

    volumeDosNameSize = volumeData.Length;

    // --- END: MODIFICATION ---

    finalNameSize = origNameSize - volumeNameSize + volumeDosNameSize;

    if (volumeNameSize == origNameSize)
    { // file is the volume, don't need to do anything
        hr = RtlUnicodeStringCopy(uString, &nameInfo->Name);
        goto cleanup;
    }

    // Use the local 'volumeData' instead of the global 'GvolumeData'
    if (NT_SUCCESS(hr = RtlUnicodeStringCopy(uString, &volumeData)))
    {
        RtlCopyMemory(uString->Buffer + (volumeDosNameSize / 2), nameInfo->Name.Buffer + (volumeNameSize / 2),
                      ((finalNameSize - volumeDosNameSize > MAX_FILE_NAME_SIZE - volumeDosNameSize)
                           ? (MAX_FILE_NAME_SIZE - volumeDosNameSize)
                           : (finalNameSize - volumeDosNameSize)));
        uString->Length = (finalNameSize > MAX_FILE_NAME_SIZE) ? MAX_FILE_NAME_SIZE : finalNameSize;
        // DbgPrint("File name: %wZ\n", uString);
    }

cleanup:
    // BUGFIX: IoVolumeDeviceToDosName allocates memory that MUST be freed
    if (volumeData.Buffer != NULL) {
        ExFreePool(volumeData.Buffer);
    }

    if (devObject) {
        ObDereferenceObject(devObject);
    }
    return hr;
}

NTSTATUS
CopyFileIdInfo(_Inout_ PFLT_CALLBACK_DATA Data, PDRIVER_MESSAGE newItem)
{
    FILE_ID_INFORMATION fileInformation;
    NTSTATUS hr = FltQueryInformationFile(Data->Iopb->TargetInstance, Data->Iopb->TargetFileObject, &fileInformation,
                                          sizeof(FILE_ID_INFORMATION), FileIdInformation, NULL);
    RtlCopyMemory(&(newItem->FileID), &fileInformation, sizeof(FILE_ID_INFORMATION));
    return hr;
}

NTSTATUS GetFileNameInfo(_In_ PCFLT_RELATED_OBJECTS FltObjects, PUNICODE_STRING FilePath,
                         PFLT_FILE_NAME_INFORMATION nameInfo)
{
    NTSTATUS hr;
    hr = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(hr))
    {
        return hr;
    }
    hr = FSEntrySetFileName(FltObjects->Volume, nameInfo, FilePath);
    // Caller owns nameInfo lifetime and must release it exactly once.
    return hr;
}

VOID CopyExtension(PWCHAR dest, PFLT_FILE_NAME_INFORMATION nameInfo)
{
    if (IS_DEBUG_IRP)
        DbgPrint("!!! FsFilter: copying the file type extension, extension length: %d, name: %wZ\n",
                 nameInfo->Extension.Length, nameInfo->Extension);
    RtlZeroBytes(dest, (FILE_OBJEC_MAX_EXTENSION_SIZE + 1) * sizeof(WCHAR));
    for (LONG i = 0; i < FILE_OBJEC_MAX_EXTENSION_SIZE; i++)
    {
        if (i == (nameInfo->Extension.Length / 2))
            break;
        dest[i] = nameInfo->Extension.Buffer[i];
    }
}

NTSTATUS GetProcessNameByHandle(_In_ HANDLE ProcessHandle, _Out_ PUNICODE_STRING *Name)
{
    ULONG retLength = 0;
    ULONG pniSize = 512;
    PUNICODE_STRING pni = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    // FIX: Create a local copy of the function pointer to avoid race conditions
    QUERY_INFO_PROCESS localZwQueryInformationProcess = ZwQueryInformationProcess;

    // FIX: Enhanced safety check with local copy
    if (localZwQueryInformationProcess == NULL)
    {
        DbgPrint("!!! FsFilter: CRITICAL - ZwQueryInformationProcess is NULL!\n");
        return STATUS_UNSUCCESSFUL;
    }

    do
    {
        pni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, pniSize, 'RW');
        if (pni != NULL)
        {
            // FIX: Use local copy instead of global variable
            status = localZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, pni, pniSize, &retLength);
            if (!NT_SUCCESS(status))
            {
                ExFreePoolWithTag(pni, 'RW');
                pniSize *= 2;
            }
        }
        else
            status = STATUS_INSUFFICIENT_RESOURCES;
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (NT_SUCCESS(status))
        *Name = pni;

    return status;
}

NTSTATUS GetProcessCommandLineByHandle(_In_ HANDLE ProcessHandle, _Out_ PUNICODE_STRING *CommandLine)
{
    ULONG retLength = 0;
    ULONG pniSize = 1024;
    PUNICODE_STRING pni = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    QUERY_INFO_PROCESS localZwQueryInformationProcess = ZwQueryInformationProcess;
    if (localZwQueryInformationProcess == NULL)
    {
        return STATUS_UNSUCCESSFUL;
    }

    do
    {
        pni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, pniSize, 'RW');
        if (pni == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        // ProcessCommandLineInformation = 60
        status = localZwQueryInformationProcess(ProcessHandle, (PROCESSINFOCLASS)60, pni, pniSize, &retLength);
        if (!NT_SUCCESS(status))
        {
            ExFreePoolWithTag(pni, 'RW');
            pni = NULL;
            if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL)
            {
                pniSize *= 2;
                continue;
            }
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL);

    if (NT_SUCCESS(status) && pni != NULL)
    {
        *CommandLine = pni;
    }

    return status;
}

//
// ** NEW FUNCTION TO DELETE A FILE **
// This helper function deletes a file given its path.
//
NTSTATUS DeleteFileByPath(PUNICODE_STRING FilePath)
{
    OBJECT_ATTRIBUTES objAttributes;
    InitializeObjectAttributes(&objAttributes, FilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    return ZwDeleteFile(&objAttributes);
}

// Quarantine a file by moving it to an isolated folder
NTSTATUS QuarantineFileByPath(PUNICODE_STRING FilePath)
{
    NTSTATUS status;
    HANDLE sourceHandle = NULL;
    HANDLE destHandle = NULL;
    OBJECT_ATTRIBUTES objAttribs;
    IO_STATUS_BLOCK ioStatus;

    // Define quarantine path for HydraDragon
    UNICODE_STRING quarantineDir;
    RtlInitUnicodeString(&quarantineDir, L"\\??\\C:\\ProgramData\\HydraDragonAntivirus\\Quarantine");

    // Create quarantine directory if it doesn't exist
    InitializeObjectAttributes(&objAttribs, &quarantineDir,
                              OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(&destHandle,
                         GENERIC_WRITE | SYNCHRONIZE,
                         &objAttribs,
                         &ioStatus,
                         NULL,
                         FILE_ATTRIBUTE_DIRECTORY,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         FILE_OPEN_IF,
                         FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                         NULL,
                         0);

    // DON'T close destHandle here! We need it for the relative rename.
    // if (destHandle != NULL)
    //    ZwClose(destHandle);

    // Open the source file
    InitializeObjectAttributes(&objAttribs, FilePath,
                              OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenFile(&sourceHandle,
                       DELETE | SYNCHRONIZE,
                       &objAttribs,
                       &ioStatus,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("!!! FsFilter: Failed to open file for quarantine: 0x%X\n", status);
        return status;
    }

    // Extract filename from full path
    USHORT filenameOffset = 0;
    for (USHORT i = FilePath->Length / sizeof(WCHAR); i > 0; i--)
    {
        if (FilePath->Buffer[i - 1] == L'\\')
        {
            filenameOffset = i;
            break;
        }
    }

    // Build destination path: C:\Quarantine\<filename>
    WCHAR destPathBuffer[512];
    UNICODE_STRING destPath;
    destPath.Buffer = destPathBuffer;
    destPath.MaximumLength = sizeof(destPathBuffer);
    destPath.Length = 0;

    RtlAppendUnicodeStringToString(&destPath, &quarantineDir);

    UNICODE_STRING backslash;
    RtlInitUnicodeString(&backslash, L"\\");
    RtlAppendUnicodeStringToString(&destPath, &backslash);

    UNICODE_STRING filename;
    filename.Buffer = &FilePath->Buffer[filenameOffset];
    filename.Length = FilePath->Length - (filenameOffset * sizeof(WCHAR));
    filename.MaximumLength = filename.Length;
    RtlAppendUnicodeStringToString(&destPath, &filename);

    // Prepare rename information
    // We only need the size of the FILE_RENAME_INFORMATION + the relative filename
    ULONG renameInfoSize = sizeof(FILE_RENAME_INFORMATION) + filename.Length;
    PFILE_RENAME_INFORMATION renameInfo = (PFILE_RENAME_INFORMATION)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, renameInfoSize, 'RW');

    if (renameInfo == NULL)
    {
        ZwClose(sourceHandle);
        ZwClose(destHandle); // Clean up
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    renameInfo->ReplaceIfExists = TRUE;
    // Set the root directory to our open handle to the Quarantine folder!
    renameInfo->RootDirectory = destHandle; 
    renameInfo->FileNameLength = filename.Length;
    
    // ONLY copy the filename (e.g., "Code.exe"), not the full path
    RtlCopyMemory(renameInfo->FileName, filename.Buffer, filename.Length);

    // Move the file to quarantine
    status = ZwSetInformationFile(sourceHandle,
                                 &ioStatus,
                                 renameInfo,
                                 renameInfoSize,
                                 FileRenameInformation);

    ExFreePoolWithTag(renameInfo, 'RW');
    ZwClose(sourceHandle);
    ZwClose(destHandle); // Now we can close the directory handle

    if (NT_SUCCESS(status))
    {
        DbgPrint("!!! FsFilter: File quarantined to: %wZ\n", &destPath);

        // Now rename the quarantined file to make it unrunnable
        HANDLE quarantinedFileHandle;
        OBJECT_ATTRIBUTES quarantinedObjAttr;
        UNICODE_STRING newQuarantinedFileName;
        WCHAR newQuarantinedFileNameBuffer[512];

        newQuarantinedFileName.Buffer = newQuarantinedFileNameBuffer;
        newQuarantinedFileName.MaximumLength = sizeof(newQuarantinedFileNameBuffer);
        newQuarantinedFileName.Length = 0;

        RtlAppendUnicodeStringToString(&newQuarantinedFileName, &destPath);
        UNICODE_STRING quarantinedExtension;
        RtlInitUnicodeString(&quarantinedExtension, L".quarantined");
        RtlAppendUnicodeStringToString(&newQuarantinedFileName, &quarantinedExtension);

        InitializeObjectAttributes(&quarantinedObjAttr, &destPath,
                                  OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        NTSTATUS openQuarantinedStatus = ZwOpenFile(&quarantinedFileHandle,
                                                   FILE_ALL_ACCESS, // Need write access to rename
                                                   &quarantinedObjAttr,
                                                   &ioStatus,
                                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                                   FILE_SYNCHRONOUS_IO_NONALERT);

        if (NT_SUCCESS(openQuarantinedStatus))
        {
            ULONG newRenameInfoSize = sizeof(FILE_RENAME_INFORMATION) + newQuarantinedFileName.Length;
            PFILE_RENAME_INFORMATION newRenameInfo = (PFILE_RENAME_INFORMATION)
                ExAllocatePool2(POOL_FLAG_NON_PAGED, newRenameInfoSize, 'RW');

            if (newRenameInfo != NULL)
            {
                newRenameInfo->ReplaceIfExists = TRUE;
                newRenameInfo->RootDirectory = NULL;
                newRenameInfo->FileNameLength = newQuarantinedFileName.Length;
                RtlCopyMemory(newRenameInfo->FileName, newQuarantinedFileName.Buffer, newQuarantinedFileName.Length);

                NTSTATUS renameStatus = ZwSetInformationFile(quarantinedFileHandle,
                                                            &ioStatus,
                                                            newRenameInfo,
                                                            newRenameInfoSize,
                                                            FileRenameInformation);
                if (NT_SUCCESS(renameStatus))
                {
                    DbgPrint("!!! FsFilter: Quarantined file renamed to: %wZ\n", &newQuarantinedFileName);
                }
                else
                {
                    DbgPrint("!!! FsFilter: Failed to rename quarantined file: 0x%X\n", renameStatus);
                }
                ExFreePoolWithTag(newRenameInfo, 'RW');
            }
            else
            {
                DbgPrint("!!! FsFilter: Failed to allocate memory for quarantined file rename info.\n");
            }
            ZwClose(quarantinedFileHandle);
        }
        else
        {
            DbgPrint("!!! FsFilter: Failed to open quarantined file for renaming: 0x%X\n", openQuarantinedStatus);
        }
    }
    else
    {
        DbgPrint("!!! FsFilter: Failed to quarantine file: 0x%X\n", status);
    }

    return status;
}

// new code process recording
static VOID AddRemProcessRoutineCore(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    // FIX: Add early safety check for commHandle
    if (commHandle == NULL || commHandle->CommClosed)
        return;

    // FIX: Additional safety check for ZwQueryInformationProcess before any usage
    if (ZwQueryInformationProcess == NULL)
    {
        DbgPrint("!!! FsFilter: Cannot process notification - ZwQueryInformationProcess is NULL\n");
        return;
    }

    if (Create)
    {
        NTSTATUS hr;
        HANDLE procHandleParent = NULL;
        HANDLE procHandleProcess = NULL;

        CLIENT_ID clientIdParent;
        clientIdParent.UniqueProcess = ParentId;
        clientIdParent.UniqueThread = 0;

        CLIENT_ID clientIdProcess;
        clientIdProcess.UniqueProcess = ProcessId;
        clientIdProcess.UniqueThread = 0;

        OBJECT_ATTRIBUTES objAttribs;

        InitializeObjectAttributes(&objAttribs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

        // Declare all locals up-front so they are in scope for both the normal
        // path and the early-fallback goto path below.
        PUNICODE_STRING procName      = NULL;
        PUNICODE_STRING parentName    = NULL;
        PUNICODE_STRING procCmdLine   = NULL;
        BOOLEAN         mustFreeProcName = TRUE;  // FALSE when procName is a borrowed pointer

        // Use minimal rights; on failure, still record using CreateInfo data
        ULONG openRights = PROCESS_QUERY_LIMITED_INFORMATION;

        hr = ZwOpenProcess(&procHandleParent, openRights, &objAttribs, &clientIdParent);
        if (!NT_SUCCESS(hr)) {
            DbgPrint("!!! FsFilter: Failed to open parent process (non-fatal): %#010x.\n", hr);
            procHandleParent = NULL;  // continue without parent name
        }

        hr = ZwOpenProcess(&procHandleProcess, openRights, &objAttribs, &clientIdProcess);
        if (!NT_SUCCESS(hr)) {
            DbgPrint("!!! FsFilter: Failed to open process (non-fatal): %#010x.\n", hr);
            if (procHandleParent) ZwClose(procHandleParent);

            // Even if the process is already dead (STATUS_INVALID_CID,
            // STATUS_PROCESS_IS_TERMINATING, etc.) we still want to record and
            // forward it for scanning — the executable image is still on disk and
            // may be malware. Use the name the kernel already captured in CreateInfo.
            if (CreateInfo && CreateInfo->ImageFileName) {
                procName = const_cast<PUNICODE_STRING>(CreateInfo->ImageFileName);  // borrowed pointer, don't free
                mustFreeProcName = FALSE;
            } else {
                return;  // no name at all, truly nothing to record
            }
            goto record_process;  // skip the GetProcessNameByHandle calls
        }

        if (procHandleParent != NULL)
        {
            hr = GetProcessNameByHandle(procHandleParent, &parentName);
            if (!NT_SUCCESS(hr))
            {
                // Parent name lookup failed (e.g. UAC-elevated process whose parent is AppInfo/AIS svchost).
                // parentName is only used for debug logging — don't drop the child event just because
                // we can't name the parent. GID inheritance uses ParentId (raw PID), not parentName.
                DbgPrint("!!! FsFilter: Failed to get parent name (non-fatal, continuing): %#010x\n", hr);
                parentName = NULL;
            }
            ZwClose(procHandleParent);
        }

        hr = GetProcessNameByHandle(procHandleProcess, &procName);
        if (!NT_SUCCESS(hr))
        {
            DbgPrint("!!! FsFilter: Failed to get process name: %#010x\n", hr);
            if (parentName != NULL)
                ExFreePoolWithTag(parentName, 'RW');
            ZwClose(procHandleProcess);
            return;
        }

        DbgPrint("!!! FsFilter: New Process, parent: %wZ. Pid: %d\n", parentName, (ULONG)(ULONG_PTR)ParentId);

        // In legacy callback path, command line is not provided by CreateInfo.
        // Best-effort fallback: query ProcessCommandLineInformation directly.
        if (CreateInfo == NULL) {
            (VOID)GetProcessCommandLineByHandle(procHandleProcess, &procCmdLine);
        }

        // procHandleParent was already closed inside the if-block above
        ZwClose(procHandleProcess);

        record_process:
        DbgPrint("!!! FsFilter: New Process, process: %wZ , pid: %d.\n", procName, (ULONG)(ULONG_PTR)ProcessId);

        // ALWAYS record the process and send message to usermode
        ULONGLONG gid = driverData->RecordNewProcess(procName, (ULONG)(ULONG_PTR)ProcessId, (ULONG)(ULONG_PTR)ParentId);

        // Send creation message to usermode
        PIRP_ENTRY newEntry = new IRP_ENTRY();
        if (newEntry != NULL) {
            PDRIVER_MESSAGE newItem = &newEntry->data;
            newItem->PID = (ULONG)(ULONG_PTR)ProcessId;
            newItem->Gid = gid;
            newItem->ParentPid = (ULONG)(ULONG_PTR)ParentId;
            newItem->IRP_OP = IRP_PROCESS_CREATE;

            if (procName != NULL) {
                // Try to convert NT device path (\Device\HarddiskVolumeX\...) to DOS
                // drive-letter path (C:\...) so usermode sees a consistent format.
                PCWSTR srcPath = procName->Buffer;
                USHORT srcLen = procName->Length;
                WCHAR dosPathBuf[MAX_FILE_NAME_LENGTH] = {0};
                if (srcPath != NULL && NtPathToDosPath(srcPath, dosPathBuf, RTL_NUMBER_OF(dosPathBuf)))
                {
                    srcPath = dosPathBuf;
                    srcLen = (USHORT)(wcslen(dosPathBuf) * sizeof(WCHAR));
                }
                if (srcPath != NULL)
                { // ← guard added: only copy when buffer is valid
                    USHORT copyLen =
                        (srcLen < MAX_FILE_NAME_SIZE - sizeof(WCHAR)) ? srcLen : (MAX_FILE_NAME_SIZE - sizeof(WCHAR));
                    RtlCopyMemory(newEntry->Buffer, srcPath, copyLen);
                    newEntry->Buffer[copyLen / sizeof(WCHAR)] = L'\0';
                    newEntry->filePath.Length = copyLen;
                    newEntry->filePath.MaximumLength = MAX_FILE_NAME_SIZE;
                    newEntry->filePath.Buffer = newEntry->Buffer;
                }
            }

            if (CreateInfo &&
                CreateInfo->CommandLine &&
                CreateInfo->CommandLine->Buffer &&
                CreateInfo->CommandLine->Length > 0) {
                USHORT cmdCopyLen = (CreateInfo->CommandLine->Length < MAX_FILE_NAME_SIZE)
                    ? CreateInfo->CommandLine->Length
                    : (MAX_FILE_NAME_SIZE - sizeof(WCHAR));
                RtlCopyMemory(newItem->CommandLine, CreateInfo->CommandLine->Buffer, cmdCopyLen);
                newItem->CommandLine[cmdCopyLen / sizeof(WCHAR)] = L'\0';
            } else if (procCmdLine != NULL &&
                       procCmdLine->Buffer != NULL &&
                       procCmdLine->Length > 0) {
                USHORT cmdCopyLen = (procCmdLine->Length < MAX_FILE_NAME_SIZE)
                    ? procCmdLine->Length
                    : (MAX_FILE_NAME_SIZE - sizeof(WCHAR));
                RtlCopyMemory(newItem->CommandLine, procCmdLine->Buffer, cmdCopyLen);
                newItem->CommandLine[cmdCopyLen / sizeof(WCHAR)] = L'\0';
            }

            if (!driverData->AddIrpMessage(newEntry)) {
                delete newEntry;
            }
        }

        if (parentName != NULL)
            ExFreePoolWithTag(parentName, 'RW');
        if (procCmdLine != NULL)
            ExFreePoolWithTag(procCmdLine, 'RW');
        // Note: procName is managed by RecordNewProcess, don't free it here
    }
    else
    {
        DbgPrint("!!! FsFilter: Terminate Process, Process: %d pid\n", (ULONG)(ULONG_PTR)ProcessId);

        (VOID)UserModeUnhookProcess((ULONG)(ULONG_PTR)ProcessId);
        // Always notifies usermode, Gid=0 signals "untracked process died"
        BOOLEAN found = FALSE;
        ULONGLONG gid = driverData->GetProcessGid((ULONG)(ULONG_PTR)ProcessId, &found);

        // Always send terminate — even if we didn't track this PID, usermode must
        // be able to clear any stale state it may have for this PID.
        PIRP_ENTRY newEntry = new IRP_ENTRY();
        if (newEntry != NULL) {
            PDRIVER_MESSAGE newItem = &newEntry->data;
            newItem->PID  = (ULONG)(ULONG_PTR)ProcessId;
            newItem->Gid  = found ? gid : 0ULL;   // 0 = sentinel "not in our table"
            newItem->IRP_OP = IRP_PROCESS_TERMINATE;
            if (!driverData->AddIrpMessage(newEntry)) {
                delete newEntry;
            }
        }
        driverData->RemoveProcess((ULONG)(ULONG_PTR)ProcessId);
    }
}

_Use_decl_annotations_
VOID AddRemProcessRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    BOOLEAN isCreate = (CreateInfo != NULL);
    HANDLE parentId = isCreate ? CreateInfo->ParentProcessId : 0;
    AddRemProcessRoutineCore(parentId, ProcessId, isCreate, CreateInfo);
}

_Use_decl_annotations_
VOID AddRemProcessRoutineLegacy(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    AddRemProcessRoutineCore(ParentId, ProcessId, Create, NULL);
}

// ====================================================================
// Hook Device Dispatch Routines
// ====================================================================

NTSTATUS FsFilter_HookDeviceCreate_UNUSED(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS FsFilter_HookDeviceClose_UNUSED(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS FsFilter_HookDeviceControl_UNUSED(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesWritten = 0;

    typedef struct _HOOK_EVENT_DATA_WIRE80 {
        ULONG EventType;
        ULONG ProcessId;
        CHAR FunctionName[64];
        ULONG_PTR Arg1;
    } HOOK_EVENT_DATA_WIRE80, *PHOOK_EVENT_DATA_WIRE80;
    
    if (irpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_REPORT_HOOK_EVENT)
    {
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(HOOK_EVENT_DATA_WIRE80))
        {
            PVOID rawBuffer = Irp->AssociatedIrp.SystemBuffer;
            if (rawBuffer) {
                ULONG eventType = 0;
                ULONG processId = 0;
                PCWSTR incomingWideName = NULL;
                ULONG_PTR rawArg1 = 0;
                ULONG_PTR rawArg2 = 0;
                ULONG_PTR rawArg3 = 0;
                ULONG_PTR rawArg4 = 0;
                WCHAR convertedIncomingName[64] = {0};
    
                if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(HOOK_EVENT_DATA))
                {
                    PHOOK_EVENT_DATA eventData = (PHOOK_EVENT_DATA)rawBuffer;
                    eventType = eventData->EventType;
                    processId = eventData->ProcessId;
                    rawArg1 = eventData->Arg1;
                    rawArg2 = eventData->Arg2;
                    rawArg3 = eventData->Arg3;
                    rawArg4 = eventData->Arg4;

                    // Convert ANSI FunctionName to WCHAR
                    if (eventData->FunctionName[0] != '\0')
                    {
                        ANSI_STRING asFunc;
                        UNICODE_STRING usFunc;
                        RtlInitAnsiString(&asFunc, eventData->FunctionName);
                        usFunc.Buffer = convertedIncomingName;
                        usFunc.Length = 0;
                        usFunc.MaximumLength = sizeof(convertedIncomingName);
                        if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&usFunc, &asFunc, FALSE)))
                        {
                            convertedIncomingName[(RTL_NUMBER_OF(convertedIncomingName) - 1)] = L'\0';
                            incomingWideName = convertedIncomingName;
                        }
                    }
                }
                else
                {
                    PHOOK_EVENT_DATA_WIRE80 eventData80 = (PHOOK_EVENT_DATA_WIRE80)rawBuffer;
                    eventType = eventData80->EventType;
                    processId = eventData80->ProcessId;
                    rawArg1 = eventData80->Arg1;
                    rawArg2 = 0;
                    rawArg3 = 0;
                    rawArg4 = 0;
                    if (eventData80->FunctionName[0] != '\0') {
                        ANSI_STRING asFunc;
                        UNICODE_STRING usFunc;
                        RtlInitAnsiString(&asFunc, eventData80->FunctionName);
                        usFunc.Buffer = convertedIncomingName;
                        usFunc.Length = 0;
                        usFunc.MaximumLength = sizeof(convertedIncomingName);
                        if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&usFunc, &asFunc, FALSE))) {
                            convertedIncomingName[(RTL_NUMBER_OF(convertedIncomingName) - 1)] = L'\0';
                            incomingWideName = convertedIncomingName;
                        }
                    }
                }

                PCWSTR functionName = NULL;
                WCHAR resolvedHookName[MAX_FILE_NAME_LENGTH] = {0};

                BOOLEAN incomingHasName = (incomingWideName != NULL && incomingWideName[0] != L'\0');
                BOOLEAN incomingQualified = FALSE;
                if (incomingHasName)
                {
                    incomingQualified = (wcschr(incomingWideName, L'!') != NULL);
                }

                // Prefer fully-qualified module!function labels.
                // If incoming payload is unqualified (e.g. only module stem), resolve by EventId.
                if (incomingQualified) {
                    functionName = incomingWideName;
                } else if (ResolveHookNameByEventId(eventType, resolvedHookName, RTL_NUMBER_OF(resolvedHookName)) &&
                           resolvedHookName[0] != L'\0')
                {
                    functionName = resolvedHookName;
                }
                else if (incomingHasName)
                {
                    functionName = incomingWideName;
                }
                else
                {
                    functionName = L"";
                }

                DbgPrint("FsFilter: API HOOKING EVENT RawType=%lu Name=%ws SourcePid=%lu TargetPid=%lu Arg1=0x%p Arg2=0x%p Arg3=0x%p Arg4=0x%p\n",
                         eventType,
                         functionName ? functionName : L"",
                         processId,
                         processId,
                         (PVOID)rawArg1,
                         (PVOID)rawArg2,
                         (PVOID)rawArg3,
                         (PVOID)rawArg4);
                
                // Preserve raw event type and hook arguments; classification is normalized in ProcessProtection.
                OnKernelApiEvent(IRP_USERMODE_HOOK_EVENT, eventType, processId, processId, functionName, rawArg1, rawArg2, rawArg3, rawArg4);
            }
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }
    else {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }
    
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesWritten;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
