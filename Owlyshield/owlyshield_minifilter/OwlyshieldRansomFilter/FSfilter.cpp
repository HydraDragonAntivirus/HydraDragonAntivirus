/*++

Module Name:

    FSfilter.c

Abstract:

    This is the main module of the FSfilter miniFilter driver.

Environment:

    Kernel mode

--*/

#include "FSfilter.h"
#include "AmsiProtection.h"
#include <ntstrsafe.h>
#include "ProcessProtection.h"
#include "Regedit.h"
#include "RootkitDetector.h"
#include "UserModeHookEngine.h"

#pragma prefast(disable : __WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//  Structure that contains all the global data structures used throughout the driver.

// FIX: Make this volatile to prevent compiler optimizations that could cause issues
volatile QUERY_INFO_PROCESS ZwQueryInformationProcess = NULL;

// Global variable definition
// No global UNICODE_STRING for volumes - use driverData cache instead

EXTERN_C_START

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

DRIVER_INITIALIZE DriverEntry;

EXTERN_C_END

//
// Forward declarations for new callback functions
//

VOID ThreadCreationCallback(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);

VOID ImageLoadCallback(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo);

// FIX: Forward declaration added because it is used before definition
FLT_POSTOP_CALLBACK_STATUS
FSProcessPostReadSafe(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                      _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

VOID DriverUnload(PDRIVER_OBJECT DriverObject);

BOOLEAN
FSShouldIgnorePyasWhitelistPath(_In_ PCUNICODE_STRING Path);

// FIX: Helper to create an OwPn-tagged NonPaged copy of a UNICODE_STRING.
// RecordNewProcess takes ownership of the PUNICODE_STRING it receives and
// later frees it with the process-name pool helper.
// SeLocateProcessImageName allocates from PagedPool with a system tag,
// so passing its result directly causes a pool-tag mismatch on free
// (silent heap corruption -> eventual bugcheck 0x13a).
// This function copies the string into a single NonPaged, OwPn-tagged
// allocation and returns an owning pointer.  Caller must free the
// original SeLocateProcessImageName buffer after this succeeds.
static PUNICODE_STRING FSCopyUnicodeStringForRecordNewProcess(_In_ PUNICODE_STRING Source)
{
    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0)
        return NULL;

    USHORT allocLen = Source->Length + sizeof(WCHAR);
    PUNICODE_STRING copy =
        (PUNICODE_STRING)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING) + allocLen, OWLY_POOL_TAG_PROCESS_NAME);
    if (copy == NULL)
        return NULL;

    copy->Buffer = (PWCH)((PUCHAR)copy + sizeof(UNICODE_STRING));
    copy->Length = Source->Length;
    copy->MaximumLength = allocLen;
    RtlCopyMemory(copy->Buffer, Source->Buffer, Source->Length);
    copy->Buffer[copy->Length / sizeof(WCHAR)] = L'\0';
    return copy;
}

static VOID FSCopyProcessPathForMessage(_In_opt_ PUNICODE_STRING Source,
                                        _Out_writes_(MAX_FILE_NAME_LENGTH) PWCHAR Destination,
                                        _Out_ PUSHORT DestinationLength)
{
    if (Destination == NULL || DestinationLength == NULL)
        return;

    RtlZeroMemory(Destination, MAX_FILE_NAME_SIZE);
    *DestinationLength = 0;

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0)
        return;

    PCWSTR srcPath = Source->Buffer;
    USHORT srcLen = Source->Length;
    WCHAR dosPathBuf[MAX_FILE_NAME_LENGTH] = {0};

    if (NtPathToDosPath(srcPath, dosPathBuf, RTL_NUMBER_OF(dosPathBuf)))
    {
        srcPath = dosPathBuf;
        srcLen = (USHORT)(wcslen(dosPathBuf) * sizeof(WCHAR));
    }

    USHORT copyLen = (srcLen < (MAX_FILE_NAME_SIZE - sizeof(WCHAR))) ? srcLen : (MAX_FILE_NAME_SIZE - sizeof(WCHAR));

    if (copyLen > 0)
        RtlCopyMemory(Destination, srcPath, copyLen);

    Destination[copyLen / sizeof(WCHAR)] = L'\0';
    *DestinationLength = copyLen;
}

static BOOLEAN FSShouldBypassReadTelemetry(_In_ PFLT_CALLBACK_DATA Data)
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
        if (processName != NULL && (_stricmp((const char *)processName, "MemCompression") == 0 ||
                                    _stricmp((const char *)processName, "System") == 0))
        {
            ObDereferenceObject(requestorProcess);
            return TRUE;
        }

        ObDereferenceObject(requestorProcess);
    }

    return FALSE;
}

// CDO Dispatch Routines
// HookDevice* dispatch functions are now in Communication.cpp.
// Use InitHookNotifyDevice() / CleanupHookNotifyDevice() instead.

// g_HookDeviceObject removed: hook device owned by Communication.cpp
static PDRIVER_OBJECT g_DriverObject = NULL;         // set in DriverEntry
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
typedef struct _HOOK_PROCESS_WORK_ITEM
{
    PIO_WORKITEM WorkItem; // <-- handle, not embedded struct
    ULONG ProcessId;
} HOOK_PROCESS_WORK_ITEM, *PHOOK_PROCESS_WORK_ITEM;

static VOID HookProcessWorkItemRoutine(_In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Parameter)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PHOOK_PROCESS_WORK_ITEM ctx = (PHOOK_PROCESS_WORK_ITEM)Parameter;
    if (ctx == NULL)
        return;

    (VOID) UserModeHookProcess(ctx->ProcessId);

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

        KeMemoryBarrier();              // Ensure all FAST_MUTEX bytes are visible globally
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

static VOID FSFreePyasRuleSetStorage(_Inout_ PPYAS_WHITELIST_RULE_SET RuleSet)
{
    if (RuleSet == NULL)
    {
        return;
    }

    if (RuleSet->Rules != NULL)
    {
        for (ULONG i = 0; i < RuleSet->Count; ++i)
        {
            if (RuleSet->Rules[i] != NULL)
            {
                ExFreePoolWithTag(RuleSet->Rules[i], PYAS_RULE_POOL_TAG);
            }
        }
        ExFreePoolWithTag(RuleSet->Rules, PYAS_RULE_POOL_TAG);
        RuleSet->Rules = NULL;
    }

    RuleSet->Count = 0;
    RuleSet->Capacity = 0;
}

static VOID FSFreePyasWhitelistRulesUnlocked(VOID)
{
    FSFreePyasRuleSetStorage(&g_PyasWhitelistRules);
}

static NTSTATUS FSEnsurePyasRuleCapacityForSet(_Inout_ PPYAS_WHITELIST_RULE_SET RuleSet, _In_ ULONG RequiredCount)
{
    PWSTR *newArray;
    SIZE_T allocSize;
    ULONG newCapacity;

    if (RuleSet == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (RuleSet->Capacity >= RequiredCount)
    {
        return STATUS_SUCCESS;
    }

    newCapacity = (RuleSet->Capacity == 0) ? 8 : RuleSet->Capacity * 2;
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
    if (RuleSet->Rules != NULL && RuleSet->Count > 0)
    {
        RtlCopyMemory(newArray, RuleSet->Rules, sizeof(PWSTR) * RuleSet->Count);
        ExFreePoolWithTag(RuleSet->Rules, PYAS_RULE_POOL_TAG);
    }

    RuleSet->Rules = newArray;
    RuleSet->Capacity = newCapacity;
    return STATUS_SUCCESS;
}

static NTSTATUS FSAddPyasWhitelistRuleNormalizedToSet(_Inout_ PPYAS_WHITELIST_RULE_SET RuleSet,
                                                      _In_reads_(RuleChars) PCWSTR RuleText, _In_ SIZE_T RuleChars)
{
    WCHAR normalizedLine[PYAS_RULE_MAX_LINE_CHARS];
    SIZE_T lineLen = 0;
    NTSTATUS status;

    if (RuleSet == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (!OwlyNormalizeRuleLineForMatch(RuleText, RuleChars, normalizedLine, RTL_NUMBER_OF(normalizedLine), FALSE,
                                       &lineLen) ||
        lineLen == 0)
    {
        return STATUS_SUCCESS;
    }

    for (ULONG i = 0; i < RuleSet->Count; ++i)
    {
        if (OwlyWideEqualsInsensitiveBounded(RuleSet->Rules[i], PYAS_RULE_MAX_LINE_CHARS,
                                             normalizedLine, RTL_NUMBER_OF(normalizedLine)))
        {
            return STATUS_SUCCESS;
        }
    }

    status = FSEnsurePyasRuleCapacityForSet(RuleSet, RuleSet->Count + 1);
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
        RuleSet->Rules[RuleSet->Count++] = newRule;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS FSAppendPyasRulesFromBufferToSet(_Inout_ PPYAS_WHITELIST_RULE_SET RuleSet,
                                                 _In_reads_bytes_(BytesRead) PUCHAR Buffer, _In_ ULONG BytesRead)
{
    if (RuleSet == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

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
                    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(RuleSet, &utf16Buffer[start], i - start);
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
                    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(RuleSet, lineBuffer, lineLen);
                }
                start = i + 1;
            }
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS InitializeOwlyshieldRules(VOID)
{
    FSEnsurePyasRuleMutex();

    ExAcquireFastMutex(&g_PyasWhitelistRules.Mutex);

    // Dynamic hook exclude rules (normalized/contains match, case-insensitive)
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\smss.exe", 27);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\csrss.exe", 28);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\wininit.exe", 30);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\winlogon.exe", 31);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\lsass.exe", 28);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\services.exe", 31);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\svchost.exe", 30);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\fontdrvhost.exe", 34);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\sihost.exe", 29);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\dwm.exe", 26);

    // HydraDragonAntivirus-specific examples
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Program Files\\HydraDragonAntivirus", 38);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\tasks\\hydradragonantivirus", 45);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\edrpm64.dll", 29);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\edrpm32.dll", 29);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\edrmm.dll", 27);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\drivers\\sanctum.sys", 39);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\drivers\\edrdrv.sys", 38);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\drivers\\OwlyshieldRansomFilter.sys", 55);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\drivers\\RedDbgDrv.sys", 41);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Windows\\System32\\drivers\\hyperhv.sys", 39);
    (VOID) FSAddPyasWhitelistRuleNormalizedToSet(&g_PyasWhitelistRules, L"C:\\Program Files\\HydraDragonAntivirus\\hydradragon\\sanctum", 56);

    g_PyasWhitelistRules.Loaded = TRUE;

    ExReleaseFastMutex(&g_PyasWhitelistRules.Mutex);
    return STATUS_SUCCESS;
}

NTSTATUS FSSetPyasWhitelistRulesFromBuffer(_In_reads_bytes_(BytesRead) PUCHAR Buffer, _In_ ULONG BytesRead)
{
    PYAS_WHITELIST_RULE_SET stagedRules = {0};
    NTSTATUS status;

    if (Buffer == NULL || BytesRead == 0 || BytesRead > PYAS_RULE_MAX_FILE_SIZE)
    {
        return STATUS_INVALID_PARAMETER;
    }

    FSEnsurePyasRuleMutex();

    status = FSAppendPyasRulesFromBufferToSet(&stagedRules, Buffer, BytesRead);
    if (!NT_SUCCESS(status))
    {
        FSFreePyasRuleSetStorage(&stagedRules);
        return status;
    }

    ExAcquireFastMutex(&g_PyasWhitelistRules.Mutex);
    FSFreePyasWhitelistRulesUnlocked();

    g_PyasWhitelistRules.Rules = stagedRules.Rules;
    g_PyasWhitelistRules.Count = stagedRules.Count;
    g_PyasWhitelistRules.Capacity = stagedRules.Capacity;
    g_PyasWhitelistRules.Loaded = TRUE;

    stagedRules.Rules = NULL;
    stagedRules.Count = 0;
    stagedRules.Capacity = 0;

    ExReleaseFastMutex(&g_PyasWhitelistRules.Mutex);
    FSFreePyasRuleSetStorage(&stagedRules);

    return STATUS_SUCCESS;
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

extern "C" int __crt_init();
extern "C" void __crt_deinit();

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
    g_DriverObject = DriverObject;

    __crt_init();

    //
    // --- FIX: Initialize required function pointers FIRST and verify. ---
    //
    if (ZwQueryInformationProcess == NULL)
    {
        UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");

        ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

        if (ZwQueryInformationProcess == NULL)
        {
#if IS_DEBUG_IRP
            DbgPrint("Cannot resolve ZwQueryInformationProcess. Driver will not load.\n");
#endif
            return STATUS_UNSUCCESSFUL;
        }

        // FIX: Add a small delay and re-verify to ensure it's properly set
        KeStallExecutionProcessor(100); // 100 microseconds

        if (ZwQueryInformationProcess == NULL)
        {
#if IS_DEBUG_IRP
            DbgPrint("ZwQueryInformationProcess became NULL after initialization. Driver will not load.\n");
#endif
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
#if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: Cannot resolve ZwQuerySystemInformation. Driver will not load.\n");
#endif
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
        NTSTATUS cdoStatus =
            IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_WorkItemDeviceObject);
        if (!NT_SUCCESS(cdoStatus))
        {
#if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: IoCreateDevice for work-item CDO failed 0x%X (non-fatal)\n", cdoStatus);
#endif
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
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: InitHookNotifyDevice failed 0x%X\n", status);
#endif
        // Non-fatal: minifilter still works; only shellcode IOCTL events are lost.
        status = STATUS_SUCCESS;
    }

    //
    // FIX: Register the process notification callback AFTER all dependencies are initialized
    // and double-check ZwQueryInformationProcess is still valid.
    //
    if (ZwQueryInformationProcess == NULL)
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: CRITICAL - ZwQueryInformationProcess is NULL before callback registration!\n");
#endif
        CommClose();
        FltUnregisterFilter(driverData->getFilter());
        delete driverData;
        delete commHandle;
        return STATUS_UNSUCCESSFUL;
    }

    status = PsSetCreateProcessNotifyRoutineEx(AddRemProcessRoutineEx, FALSE);
    if (!NT_SUCCESS(status))
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: PsSetCreateProcessNotifyRoutineEx failed: %#010x, falling back to legacy callback.\n",
                 status);
#endif
        status = PsSetCreateProcessNotifyRoutine(AddRemProcessRoutineLegacy, FALSE);
        if (!NT_SUCCESS(status))
        {
#if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: Failed to register any process notify routine: %#010x\n", status);
#endif
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

#if IS_DEBUG_IRP
    DbgPrint("loaded scanner successfully");
#endif

    // Initialize Registry Protection
    RegeditDriverEntry();

    AmsiInitialize();

    // Initialize Process Protection (ObRegisterCallbacks for termination detection)
    status = InitProcessProtection();
    if (!NT_SUCCESS(status))
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: InitProcessProtection failed: 0x%X (non-fatal, continuing)\n", status);
#endif
        // Don't fail driver load - this is an enhancement, not critical
    }

    // Set the quarantine path
    UNICODE_STRING quarantinePathString;
    RtlInitUnicodeString(&quarantinePathString, QuarantinePath);
    driverData->SetQuarantinePath(&quarantinePathString);

#if DBG
    DriverObject->DriverUnload = DriverUnload;
#else
    DriverObject->DriverUnload = NULL;
#endif

    // ====================================================================
    // Initialize monitoring systems
    // - Hypervisor/VMM monitoring backend
    // - Thread creation callbacks
    // - Image load callbacks
    // ====================================================================

#if IS_DEBUG_IRP
    DbgPrint("!!! FSfilter: Initializing advanced monitoring systems...\n");
#endif

    // 1. Initialize user-mode hook engine for dynamic API hook events.
    status = UserModeHookEngineInitialize();
    if (!NT_SUCCESS(status))
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Failed to initialize user-mode hook engine: 0x%X (non-fatal)\n", status);
#endif
    }

    // 2. Initialize communication with standalone VMM hypervisors (Intel/AMD)
    status = InitVmmCommunication();
    if (!NT_SUCCESS(status))
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Standalone VMM communication initialization skipped or failed: 0x%X\n", status);
#endif
    }

#if IS_DEBUG_IRP
    DbgPrint("!!! FSfilter: Enumerating existing processes for initial process baseline\n");
#endif
    EnumerateExistingProcesses();

    // 3. Register thread creation callback
    //    Detects remote thread injection (NtCreateThreadEx from different process)
    status = PsSetCreateThreadNotifyRoutine(ThreadCreationCallback);
    if (!NT_SUCCESS(status))
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Failed to register thread creation callback: 0x%X\n", status);
#endif
    }
    else
    {
        g_ThreadNotifyRegistered = TRUE;
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Thread creation monitoring enabled\n");
#endif
    }

    // 4. Register image load callback
    //    Detects DLL injection and driver loading
    status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);
    if (!NT_SUCCESS(status))
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Failed to register image load callback: 0x%X\n", status);
#endif
    }
    else
    {
        g_ImageNotifyRegistered = TRUE;
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Image load monitoring enabled (DLL/driver detection)\n");
#endif
    }

    // Initialize hardcoded rules for boot protection
    (VOID)InitializeOwlyshieldRules();

#if IS_DEBUG_IRP
    DbgPrint("!!! FSfilter: ========================================\n");
#endif
#if IS_DEBUG_IRP
    DbgPrint("!!! FSfilter: MONITORING COVERAGE:\n");
#endif
#if IS_DEBUG_IRP
    DbgPrint("!!! FSfilter: - Process creation/termination (PsSetCreateProcessNotifyRoutine)\n");
#endif
#if IS_DEBUG_IRP
    DbgPrint("!!! FSfilter: - Process/thread handle operations (ObRegisterCallbacks)\n");
#endif
#if IS_DEBUG_IRP
    DbgPrint("!!! FSfilter: - Thread creation (PsSetCreateThreadNotifyRoutine)\n");
#endif
#if IS_DEBUG_IRP
    DbgPrint("!!! FSfilter: - DLL/driver loading (PsSetLoadImageNotifyRoutine)\n");
#endif
#if IS_DEBUG_IRP
    DbgPrint("!!! FSfilter: - File operations (Minifilter callbacks)\n");
#endif
#if IS_DEBUG_IRP
    DbgPrint("!!! FSfilter: - Registry operations (CmRegisterCallback)\n");
#endif
#if IS_DEBUG_IRP
    DbgPrint("!!! FSfilter: - Memory operations (VMM/hypervisor + dynamic API hooks)\n");
#endif
#if IS_DEBUG_IRP
    DbgPrint("!!! FSfilter: ========================================\n");
#endif

    // ====================================================================
    // End of monitoring initialization
    // ====================================================================

    // Initialize Rootkit Detector
    RootkitDetectorInitialize();
    if (g_WorkItemDeviceObject != NULL)
    {
        RootkitDetectorSetDeviceObject(g_WorkItemDeviceObject);
    }
#if IS_DEBUG_IRP
    DbgPrint("!!! FSfilter: Rootkit detection engine initialized\n");
#endif

    return STATUS_SUCCESS;
}

//
// NEW: Thread creation callback
// Detects remote thread injection
//

VOID ThreadCreationCallback(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ThreadId);

    if (!Create)
    {
        return; // Only monitor thread creation, not termination
    }

    if (driverData == NULL || driverData->isFilterClosed())
    {
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
    if (currentPid != ProcessId)
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Remote thread creation detected!\n");
#endif
#if IS_DEBUG_IRP
        DbgPrint("!!!   Source PID: %lu -> Target PID: %lu, Thread ID: %lu\n", (ULONG)(ULONG_PTR)currentPid,
                 (ULONG)(ULONG_PTR)ProcessId, (ULONG)(ULONG_PTR)ThreadId);
#endif

        // Check if either process is monitored
        BOOLEAN sourceFound = FALSE;
        BOOLEAN targetFound = FALSE;
        ULONGLONG sourceGid = driverData->GetProcessGid((ULONG)(ULONG_PTR)currentPid, &sourceFound);
        ULONGLONG targetGid = driverData->GetProcessGid((ULONG)(ULONG_PTR)ProcessId, &targetFound);

        if (sourceFound || targetFound)
        {
            NTSTATUS onThreadStatus = OnThreadCreation((ULONG)(ULONG_PTR)currentPid, (ULONG)(ULONG_PTR)ProcessId, NULL);
            if (NT_SUCCESS(onThreadStatus))
            {
                return;
            }

            // Log to usermode via dedicated remote-thread callback opcode
            PIRP_ENTRY newEntry = new IRP_ENTRY();
            if (newEntry != NULL)
            {
                PDRIVER_MESSAGE newItem = &newEntry->data;
                newItem->IRP_OP = IRP_KERNEL_REMOTE_THREAD; // 13

                // Attribute to the attacker (source process)
                if (sourceFound)
                {
                    newItem->PID = (ULONG)(ULONG_PTR)currentPid;
                    newItem->Gid = sourceGid;
                }
                else
                {
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
                (VOID)
                    RtlStringCchCopyW(newItem->KernelEventInfo.ObjectName,
                                      RTL_NUMBER_OF(newItem->KernelEventInfo.ObjectName), L"IRP_KERNEL_REMOTE_THREAD");

                if (!driverData->AddIrpMessage(newEntry))
                {
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
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Kernel driver loaded: %wZ\n", FullImageName);
#endif
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
        (VOID) driverData->GetProcessGid((ULONG)(ULONG_PTR)ProcessId, &found);
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
                    if (ctx->WorkItem == NULL)
                    {
                        ExFreePoolWithTag(ctx, 'wHuM');
                    }
                    else
                    {
                        ctx->ProcessId = (ULONG)(ULONG_PTR)ProcessId;
                        IoQueueWorkItem(ctx->WorkItem, HookProcessWorkItemRoutine, DelayedWorkQueue, ctx);
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
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: EnumerateExistingProcesses: ZwQuerySystemInformation not resolved\n");
#endif
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
#if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: EnumerateExistingProcesses: allocation failed\n");
#endif
            return;
        }

        status = g_fnZwQuerySystemInformation(SystemProcessInformationLocal, buffer, bufferSize, &returnLength);
        if (status != STATUS_INFO_LENGTH_MISMATCH)
            break;

        // Buffer too small - free and grow
        ExFreePoolWithTag(buffer, 'EPrW');
        buffer = NULL;
        bufferSize = returnLength + 4096;
    }

    if (!NT_SUCCESS(status) || buffer == NULL)
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: EnumerateExistingProcesses: ZwQuerySystemInformation failed 0x%X\n", status);
#endif
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
            PUNICODE_STRING procName =
                (PUNICODE_STRING)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING) + allocLen, OWLY_POOL_TAG_PROCESS_NAME);

            if (procName != NULL)
            {
                procName->Buffer = (PWCH)((PUCHAR)procName + sizeof(UNICODE_STRING));
                procName->Length = entry->ImageName.Length;
                procName->MaximumLength = allocLen;
                RtlCopyMemory(procName->Buffer, entry->ImageName.Buffer, entry->ImageName.Length);
                procName->Buffer[entry->ImageName.Length / sizeof(WCHAR)] = L'\0';

                WCHAR processPathForMessage[MAX_FILE_NAME_LENGTH] = {0};
                USHORT processPathForMessageLength = 0;
                FSCopyProcessPathForMessage(procName, processPathForMessage, &processPathForMessageLength);

                // No loader lock here; call directly at PASSIVE_LEVEL
                ULONGLONG gid = driverData->RecordNewProcess(procName, pidNum, parentPid);
                (VOID) UserModeHookProcess(pidNum); // direct call, safe here

                PIRP_ENTRY newEntry = new IRP_ENTRY();
                if (newEntry != NULL)
                {
                    newEntry->data.PID = pidNum;
                    newEntry->data.Gid = gid;
                    newEntry->data.ParentPid = parentPid;
                    newEntry->data.IRP_OP = IRP_PROCESS_CREATE;

                    if (processPathForMessageLength > 0)
                    {
                        RtlCopyMemory(newEntry->Buffer, processPathForMessage, processPathForMessageLength);
                        newEntry->Buffer[processPathForMessageLength / sizeof(WCHAR)] = L'\0';
                    }
                    newEntry->filePath.Length = processPathForMessageLength;
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

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    // Call the minifilter unload logic (flags = 0)
    (VOID) FSUnloadDriver(0);
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

#if IS_DEBUG_IRP
    DbgPrint("FSfilter: Unloading driver\n");
#endif

    __crt_deinit();

    // Stop new activity first, then detach callbacks to avoid concurrent work
    // while teardown is in progress.
    if (driverData)
    {
        driverData->setFilterStop();
    }

    if (g_ImageNotifyRegistered)
    {
        NTSTATUS rmImageStatus = PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: PsRemoveLoadImageNotifyRoutine => 0x%X\n", rmImageStatus);
#else
        (void)rmImageStatus;
#endif
        g_ImageNotifyRegistered = FALSE;
    }

    if (g_ThreadNotifyRegistered)
    {
        NTSTATUS rmThreadStatus = PsRemoveCreateThreadNotifyRoutine(ThreadCreationCallback);
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: PsRemoveCreateThreadNotifyRoutine => 0x%X\n", rmThreadStatus);
#else
        (void)rmThreadStatus;
#endif
        g_ThreadNotifyRegistered = FALSE;
    }

    if (g_ProcessNotifyRegistered)
    {
        NTSTATUS rmProcStatus;
        if (g_UseLegacyProcessNotify)
        {
            rmProcStatus = PsSetCreateProcessNotifyRoutine(AddRemProcessRoutineLegacy, TRUE);
        }
        else
        {
            rmProcStatus = PsSetCreateProcessNotifyRoutineEx(AddRemProcessRoutineEx, TRUE);
        }
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Process notify unregister => 0x%X\n", rmProcStatus);
#endif
        g_ProcessNotifyRegistered = FALSE;
    }

    // Process Protection Cleanup (ObUnRegisterCallbacks)
    UninitProcessProtection();

    CleanupVmmCommunication();

    UserModeHookEngineCleanup();
    // Cleanup memory-resident rules
    FSEnsurePyasRuleMutex();
    ExAcquireFastMutex(&g_PyasWhitelistRules.Mutex);
    FSFreePyasWhitelistRulesUnlocked();
    g_PyasWhitelistRules.Loaded = FALSE;
    ExReleaseFastMutex(&g_PyasWhitelistRules.Mutex);


    // Registry Cleanup
    RegeditUnloadDriver();

    // Rootkit detector owns a shared work item and caches the dedicated CDO
    // pointer. Tear it down before freeing driverData or deleting the CDO.
    RootkitDetectorCleanup();

    AmsiCleanup();

    // Close Communication
    if (commHandle)
    {
        if (!IsCommClosed())
        {
            CommClose();
        }

        // Do not call FltUnregisterFilter() here: we are already running in
        // FilterUnload callback context, and Filter Manager owns unregister.
        commHandle->Filter = NULL;
        delete commHandle;
        commHandle = NULL;
    }

    // Cleanup DriverData
    if (driverData)
    {
        delete driverData;
        driverData = NULL;
    }

    // Delete the dedicated work-item CDO before hook device teardown
    if (g_WorkItemDeviceObject != NULL)
    {
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

#if IS_DEBUG_IRP
    DbgPrint("FSfilter: Entered FSInstanceSetup\n");
#endif

    NTSTATUS hr = STATUS_SUCCESS;
    PDEVICE_OBJECT devObject = NULL;
    UNICODE_STRING volumeData;
    RtlZeroMemory(&volumeData, sizeof(volumeData));

    hr = FltGetDiskDeviceObject(FltObjects->Volume, &devObject);
    if (!NT_SUCCESS(hr))
    {
        // Not a disk device - skip caching (e.g., named pipes, network shares)
        return STATUS_SUCCESS;
    }

    if (devObject != NULL)
    {
        hr = IoVolumeDeviceToDosName(devObject, &volumeData);
        ObDereferenceObject(devObject);
        if (NT_SUCCESS(hr))
        {
            // Pre-populate the cache for this volume
            (VOID) driverData->AddVolumeDosName(FltObjects->Volume, &volumeData);
            ExFreePool(volumeData.Buffer);
        }
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

#if IS_DEBUG_IRP
    DbgPrint("FSfilter: Entered FSInstanceQueryTeardown\n");
#endif

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

#if IS_DEBUG_IRP
    DbgPrint("FSfilter: Entered FSInstanceTeardownStart\n");
#endif
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
#if IS_DEBUG_IRP
    DbgPrint("FSfilter: Entered FSInstanceTeardownComplete\n");
#endif
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
        #if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: Allowing pre op for trusted process, no post op\n");
        #endif

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
    NTSTATUS hr = FLT_PREOP_SUCCESS_NO_CALLBACK;
    BOOLEAN isNamedPipe = (FltObjects->Volume != NULL && Data->Iopb->TargetFileObject != NULL &&
                           Data->Iopb->TargetFileObject->DeviceObject != NULL &&
                           Data->Iopb->TargetFileObject->DeviceObject->DeviceType == FILE_DEVICE_NAMED_PIPE);

    // --- NAMED PIPE DETECTION ---
    if (isNamedPipe)
    {
        PIRP_ENTRY pipeEntry = new IRP_ENTRY();
        if (pipeEntry != NULL)
        {
            PDRIVER_MESSAGE pipeMsg = &pipeEntry->data;
            pipeMsg->PID = FltGetRequestorProcessId(Data);
            BOOLEAN pipeGidFound = FALSE;
            pipeMsg->Gid = driverData->GetProcessGid(pipeMsg->PID, &pipeGidFound);

            // Get pipe name
            PFLT_FILE_NAME_INFORMATION nameInfo;
            if (NT_SUCCESS(FltGetFileNameInformation(
                    Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &nameInfo)))
            {
                USHORT copyLen = (nameInfo->Name.Length < (MAX_FILE_NAME_SIZE - sizeof(WCHAR)))
                                     ? nameInfo->Name.Length
                                     : (MAX_FILE_NAME_SIZE - sizeof(WCHAR));
                RtlCopyMemory(pipeEntry->Buffer, nameInfo->Name.Buffer, copyLen);
                pipeEntry->Buffer[copyLen / sizeof(WCHAR)] = L'\0';
                FltReleaseFileNameInformation(nameInfo);
            }

            if (Data->Iopb->MajorFunction == IRP_MJ_CREATE)
            {
                pipeMsg->IRP_OP = IRP_NAMED_PIPE_CREATE;
                // Store path in ObjectName for behavior engine matching
                RtlCopyMemory(pipeMsg->KernelEventInfo.ObjectName, pipeEntry->Buffer,
                              sizeof(pipeMsg->KernelEventInfo.ObjectName));
            }
            else if (Data->Iopb->MajorFunction == IRP_MJ_WRITE)
            {
                pipeMsg->IRP_OP = IRP_NAMED_PIPE_WRITE;

                // Capture Payload
                PVOID writeBuffer = NULL;
                if (Data->Iopb->Parameters.Write.MdlAddress == NULL)
                {
                    writeBuffer = Data->Iopb->Parameters.Write.WriteBuffer;
                }
                else
                {
                    writeBuffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Write.MdlAddress,
                                                               NormalPagePriority | MdlMappingNoExecute);
                }

                if (writeBuffer != NULL)
                {
                    ULONG captureLen =
                        (Data->Iopb->Parameters.Write.Length < 512) ? Data->Iopb->Parameters.Write.Length : 512;
                    // Store binary payload in ObjectName buffer (which is 1024 bytes raw)
                    RtlCopyMemory(pipeMsg->KernelEventInfo.ObjectName, writeBuffer, captureLen);
                    pipeMsg->KernelEventInfo.RawArgument1 = captureLen; // Store actual captured length
                }
            }
            else
            {
                delete pipeEntry;
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }

            if (!driverData->AddIrpMessage(pipeEntry))
            {
                delete pipeEntry;
            }
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

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
    if (driverData->IsPathInQuarantineDir(FilePath))
    {
        // If the requesting process is NOT the trusted Owlyshield process
        if (FltGetRequestorProcessId(Data) != driverData->getPID())
        {
#if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: Blocking access to quarantine folder for untrusted process (PID: %u)\n",
                     FltGetRequestorProcessId(Data));
#endif
            FltReleaseFileNameInformation(nameInfo);
            delete newEntry;
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE; // Block the operation
        }
        else
        {
#if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: Allowing access to quarantine folder for trusted Owlyshield process (PID: %u)\n",
                     FltGetRequestorProcessId(Data));
#endif
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
    if (driverData->IsPathBlocked(FilePath))
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: BLOCKING access to path: %wZ (Kernel-Mode Block)\n", FilePath);
#endif
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
        if (NT_SUCCESS(hr))
        {
            PUNICODE_STRING procPath = NULL;
            hr = SeLocateProcessImageName(process, &procPath);
            if (NT_SUCCESS(hr) && procPath != NULL)
            {
                // FIX Bug#1+#2: SeLocateProcessImageName allocates from PagedPool
                // with a system tag. RecordNewProcess takes ownership and later
                // frees through the process-name pool helper. Passing the original pointer
                // causes (a) pool-tag mismatch on free and (b) the old code also
                // called ExFreePool(procPath) here which was a DOUBLE-FREE.
                // Solution: copy into an OwPn-tagged NonPaged allocation, free the
                // original, and pass the copy. Do NOT free the copy — RecordNewProcess owns it.
                PUNICODE_STRING procPathCopy = FSCopyUnicodeStringForRecordNewProcess(procPath);
                // Free the original SeLocateProcessImageName buffer immediately.
                ExFreePool(procPath);
                procPath = NULL;

                if (procPathCopy != NULL)
                {
                    WCHAR discoveryPathBuffer[MAX_FILE_NAME_LENGTH] = {0};
                    USHORT discoveryPathLength = 0;
                    FSCopyProcessPathForMessage(procPathCopy, discoveryPathBuffer, &discoveryPathLength);

                    gid = driverData->RecordNewProcess(procPathCopy, newItem->PID, 0);
                    isGidFound = (gid != 0);
#if IS_DEBUG_IRP
                    DbgPrint("!!! FSfilter: DISCOVERED untracked process in PreOp. PID: %u, GID: %llu\n", newItem->PID,
                             gid);
#endif

                    if (isGidFound)
                    {
                        // Inform usermode about this late process discovery so the PID/GID map stays in sync.
                        PIRP_ENTRY discoveryEntry = new IRP_ENTRY();
                        if (discoveryEntry != NULL)
                        {
                            PDRIVER_MESSAGE discoveryMsg = &discoveryEntry->data;
                            discoveryMsg->PID = newItem->PID;
                            discoveryMsg->Gid = gid;
                            discoveryMsg->IRP_OP = IRP_PROCESS_CREATE;

                            if (discoveryPathLength > 0)
                            {
                                RtlCopyMemory(discoveryEntry->Buffer, discoveryPathBuffer, discoveryPathLength);
                                discoveryEntry->Buffer[discoveryPathLength / sizeof(WCHAR)] = L'\0';
                            }
                            discoveryEntry->filePath.Length = discoveryPathLength;
                            discoveryEntry->filePath.MaximumLength = MAX_FILE_NAME_SIZE;
                            discoveryEntry->filePath.Buffer = discoveryEntry->Buffer;

                            if (!driverData->AddIrpMessage(discoveryEntry))
                            {
                                delete discoveryEntry;
                            }
                        }
                    }
                    // NOTE: procPathCopy is now owned by RecordNewProcess. Do NOT free it.
                }
            }
            else if (procPath != NULL)
            {
                ExFreePool(procPath);
                procPath = NULL;
            }
            ObDereferenceObject(process);
        }

        if (!isGidFound)
        {
            #if IS_DEBUG_IRP
                DbgPrint("!!! FSfilter: Item does not have a gid, skipping after discovery attempt\n");
            #endif
            FltReleaseFileNameInformation(nameInfo);
            delete newEntry;
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }

    #if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Registring new irp for Gid: %d with pid: %d\n", (ULONG)gid, newItem->PID);
    #endif
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
            #if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: File in scan area \n");
        #endif
        newItem->FileLocationInfo = FILE_PROTECTED;
    }

    if (Data->Iopb->MajorFunction == IRP_MJ_READ || Data->Iopb->MajorFunction == IRP_MJ_WRITE)
    {
        CopyExtension(newItem->Extension, nameInfo);
    }

    #if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Logging IRP op: %s \n", FltGetIrpName(Data->Iopb->MajorFunction));
    #endif

    // Release nameInfo only if not IRP_MJ_SET_INFORMATION (which might need it later)
    if (Data->Iopb->MajorFunction != IRP_MJ_SET_INFORMATION)
        FltReleaseFileNameInformation(nameInfo);

    switch (Data->Iopb->MajorFunction)
    {
    case IRP_MJ_READ: {
        newItem->IRP_OP = IRP_READ;
        if (Data->Iopb->Parameters.Read.Length == 0) // no data to read
        {
            // Fix: Clean up memory before returning
            delete newEntry;
        #if IS_DEBUG_IRP
            DbgPrint("FSfilter: IRP READ NOCALLBACK LENGTH IS ZERO! \n");
        #endif
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        if (FSShouldBypassReadTelemetry(Data))
        {
            delete newEntry;
        #if IS_DEBUG_IRP
                DbgPrint("!!! FSfilter: Skipping post-read telemetry for paging/kernel MM read path\n");
        #endif
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
            #if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: Preop IRP_MJ_READ, return with postop \n");
        #endif
        // save context for post, we calculate the entropy of read, we pass the irp to application on post op
        *CompletionContext = newEntry;
            #if IS_DEBUG_IRP
            DbgPrint("FSfilter: IRP READ WITH CALLBACK! ****************** \n");
        #endif
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
                            #if IS_DEBUG_IRP
                    DbgPrint("!!! FSfilter: Failed to calc entropy (Exception caught, IRP failing)\n");
                #endif

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
            #if IS_DEBUG_IRP
                DbgPrint("!!! FSfilter: Failed to save FPU state (Status: 0x%X), skipping entropy calculation\n",
                         fpStatus);
            #endif
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
        }    // end rename
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

    #if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Adding entry to irps %s\n", FltGetIrpName(Data->Iopb->MajorFunction));
    #endif

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
#if IS_DEBUG_IRP
    // 
#if IS_DEBUG_IRP
DbgPrint("!!! FSfilter: Enter post op for irp: %s, pid of process: %u\n",
    // FltGetIrpName(Data->Iopb->MajorFunction), FltGetRequestorProcessId(Data));
#endif
#endif


    if (!NT_SUCCESS(Data->IoStatus.Status) || (STATUS_REPARSE == Data->IoStatus.Status))
    {
#if IS_DEBUG_IRP
        // 
#if IS_DEBUG_IRP
DbgPrint("!!! FSfilter: finished post operation, already failed \n");
#endif

#endif
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
        if (CompletionContext == nullptr)
        {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        if (FSShouldBypassReadTelemetry(Data))
        {
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
#if IS_DEBUG_IRP
        if (!KeIsExecutingDpc()) // prevent recursion in DPC or debug trap
            
#if IS_DEBUG_IRP
DbgPrint("FSfilter: IRP READ WITH CALLBACK! ****************** \n");
#endif

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
#if IS_DEBUG_IRP
        // 
#if IS_DEBUG_IRP
DbgPrint("!!! FSfilter: filter closed or comm closed, skip irp\n");
#endif

#endif
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
        if (NT_SUCCESS(hr))
        {
            PUNICODE_STRING procPath = NULL;
            hr = SeLocateProcessImageName(process, &procPath);
            if (NT_SUCCESS(hr) && procPath != NULL)
            {
                // FIX Bug#2: Same tag mismatch as PreOp discovery.
                // Copy into OwPn-tagged NonPaged allocation for RecordNewProcess.
                PUNICODE_STRING procPathCopy = FSCopyUnicodeStringForRecordNewProcess(procPath);
                ExFreePool(procPath);
                procPath = NULL;

                if (procPathCopy != NULL)
                {
                    gid = driverData->RecordNewProcess(procPathCopy, newItem->PID, 0);
                    isGidFound = (gid != 0);
#if IS_DEBUG_IRP
                    DbgPrint("!!! FSfilter: DISCOVERED untracked process in PostCreate. PID: %u, GID: %llu\n",
                             newItem->PID, gid);
#endif
                    // NOTE: procPathCopy is now owned by RecordNewProcess. Do NOT free.
                }
            }
            else if (procPath != NULL)
            {
                ExFreePool(procPath);
                procPath = NULL;
            }
            ObDereferenceObject(process);
        }

        if (!isGidFound)
        {
#if IS_DEBUG_IRP
            // 
#if IS_DEBUG_IRP
DbgPrint("!!! FSfilter: Item does not have a gid, skipping\n");
#endif

#endif
            FltReleaseFileNameInformation(nameInfo);
            delete newEntry;
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
    }
    newItem->Gid = gid;
#if IS_DEBUG_IRP
        DbgPrint(
            "!!! FSfilter: Registring new irp for Gid: %llu with pid: %d\n", gid,
            newItem->PID); // TODO: incase it doesnt exist we can add it with our method that checks for system process

    // get file id
    hr = CopyFileIdInfo(Data, newItem);
#endif
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
        #if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: Skipping uninterented file, not in scan area \n");
        #endif
        delete newEntry;
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    */

    if (isDir && (Data->IoStatus.Information) == FILE_OPENED)
    {
        #if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: Dir listing opened on existing directory\n");
        #endif
        newItem->FileChange = FILE_OPEN_DIRECTORY;
    }
    else if (isDir)
    {
        #if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: Dir but not listing, not importent \n");
        #endif
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
    #if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Added MJ_CREATE message\n");
    #endif
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
        #if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: Post op read, comm or filter closed\n");
        #endif
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
        // For reads that aren't already safe, we check the size before doing expensive safe completion
        if (Data->IoStatus.Information < 512)
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
    if (!ReadBuffer || Data->IoStatus.Information < 512)
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
        #if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: Failed to save FPU state on Read (Status: 0x%X), skipping entropy calculation\n",
                     fpStatus);
        #endif
        entry->data.isEntropyCalc = FALSE;
        entry->data.Entropy = 0;
    }
    #if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Addung entry to irps IRP_MJ_READ\n");
    #endif
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
    if (entry == nullptr)
    {
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
        if (ReadBuffer != NULL && Data->IoStatus.Information >= 512)
        {
            entry->data.MemSizeUsed = Data->IoStatus.Information; // successful read data.

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

            #if IS_DEBUG_IRP
                DbgPrint("!!! FSfilter: Adding entry to irps IRP_MJ_READ (Safe)\n");
            #endif

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

    if (!OwlyNormalizePathForMatch(Path, normalizedPathBuffer, &normalizedPath))
    {
        return FALSE;
    }

    // Never issue ZwCreateFile/ZwReadFile from the minifilter callback path.
    // The cache is populated at startup and refreshed explicitly through
    // MESSAGE_RELOAD_EXCLUDE_RULES from user mode.
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

    UNICODE_STRING volumeData;
    RtlZeroMemory(&volumeData, sizeof(volumeData));

    if (uString == NULL)
    {
        return STATUS_INVALID_ADDRESS;
    }

    // --- CACHE CHECK ---
    hr = driverData->GetVolumeDosName(Volume, &volumeData);
    if (!NT_SUCCESS(hr))
    {
        // Not in cache, try to resolve it once.
        // NOTE: IoVolumeDeviceToDosName can re-enter the filter.
        // The cache breaks infinite recursion as the second entry for the same volume will hit GetVolumeDosName.
        hr = FltGetDiskDeviceObject(Volume, &devObject);
        if (NT_SUCCESS(hr) && devObject != NULL && !KeAreAllApcsDisabled())
        {
            hr = IoVolumeDeviceToDosName(devObject, &volumeData);
            if (NT_SUCCESS(hr))
            {
                // Store in cache for future use
                (VOID) driverData->AddVolumeDosName(Volume, &volumeData);
            }
        }
        else
        {
            hr = STATUS_UNSUCCESSFUL;
        }
    }

    if (!NT_SUCCESS(hr))
    {
        // Preserve device/provider paths when there is no DOS mount point or resolution fails.
        hr = RtlUnicodeStringCopy(uString, &nameInfo->Name);
        goto cleanup;
    }

    volumeDosNameSize = volumeData.Length;

    finalNameSize = origNameSize - volumeNameSize + volumeDosNameSize;

    if (volumeNameSize == origNameSize)
    { // file is the volume
        hr = RtlUnicodeStringCopy(uString, &volumeData);
        goto cleanup;
    }

    if (NT_SUCCESS(hr = RtlUnicodeStringCopy(uString, &volumeData)))
    {
        RtlCopyMemory(uString->Buffer + (volumeDosNameSize / 2), nameInfo->Name.Buffer + (volumeNameSize / 2),
                      ((finalNameSize - volumeDosNameSize > MAX_FILE_NAME_SIZE - volumeDosNameSize)
                           ? (MAX_FILE_NAME_SIZE - volumeDosNameSize)
                           : (finalNameSize - volumeDosNameSize)));
        uString->Length = (finalNameSize > MAX_FILE_NAME_SIZE) ? MAX_FILE_NAME_SIZE : finalNameSize;
    }

cleanup:
    // We always free volumeData here because GetVolumeDosName returns a copy
    // and IoVolumeDeviceToDosName allocates a new buffer.
    if (volumeData.Buffer != NULL)
    {
        ExFreePool(volumeData.Buffer);
    }

    if (devObject)
    {
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
    #if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: copying the file type extension, extension length: %d, name: %wZ\n",
                 nameInfo->Extension.Length, nameInfo->Extension);
    #endif
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
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: CRITICAL - ZwQueryInformationProcess is NULL!\n");
#endif
        return STATUS_UNSUCCESSFUL;
    }

    do
    {
        pni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, pniSize, OWLY_POOL_TAG_PROCESS_NAME);
        if (pni != NULL)
        {
            // FIX: Use local copy instead of global variable
            status = localZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, pni, pniSize, &retLength);
            if (!NT_SUCCESS(status))
            {
                ExFreePoolWithTag(pni, OWLY_POOL_TAG_PROCESS_NAME);
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
        pni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, pniSize, OWLY_POOL_TAG_PROCESS_NAME);
        if (pni == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        // ProcessCommandLineInformation = 60
        status = localZwQueryInformationProcess(ProcessHandle, (PROCESSINFOCLASS)60, pni, pniSize, &retLength);
        if (!NT_SUCCESS(status))
        {
            ExFreePoolWithTag(pni, OWLY_POOL_TAG_PROCESS_NAME);
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
    RtlInitUnicodeString(&quarantineDir, QuarantinePath);

    // Create quarantine directory if it doesn't exist
    InitializeObjectAttributes(&objAttribs, &quarantineDir, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(&destHandle, GENERIC_WRITE | SYNCHRONIZE, &objAttribs, &ioStatus, NULL,
                          FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                          FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    // DON'T close destHandle here! We need it for the relative rename.
    // if (destHandle != NULL)
    //    ZwClose(destHandle);

    // Open the source file
    InitializeObjectAttributes(&objAttribs, FilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenFile(&sourceHandle, DELETE | SYNCHRONIZE, &objAttribs, &ioStatus,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(status))
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Failed to open file for quarantine: 0x%X\n", status);
#endif
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
    PFILE_RENAME_INFORMATION renameInfo =
        (PFILE_RENAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, renameInfoSize, OWLY_POOL_TAG_FILE_TEMP);

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
    status = ZwSetInformationFile(sourceHandle, &ioStatus, renameInfo, renameInfoSize, FileRenameInformation);

    ExFreePoolWithTag(renameInfo, OWLY_POOL_TAG_FILE_TEMP);
    ZwClose(sourceHandle);
    ZwClose(destHandle); // Now we can close the directory handle

    if (NT_SUCCESS(status))
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: File quarantined to: %wZ\n", &destPath);
#endif

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

        InitializeObjectAttributes(&quarantinedObjAttr, &destPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
                                   NULL);

        NTSTATUS openQuarantinedStatus =
            ZwOpenFile(&quarantinedFileHandle,
                       FILE_ALL_ACCESS, // Need write access to rename
                       &quarantinedObjAttr, &ioStatus, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       FILE_SYNCHRONOUS_IO_NONALERT);

        if (NT_SUCCESS(openQuarantinedStatus))
        {
            ULONG newRenameInfoSize = sizeof(FILE_RENAME_INFORMATION) + newQuarantinedFileName.Length;
            PFILE_RENAME_INFORMATION newRenameInfo =
                (PFILE_RENAME_INFORMATION)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, newRenameInfoSize, OWLY_POOL_TAG_FILE_TEMP);

            if (newRenameInfo != NULL)
            {
                newRenameInfo->ReplaceIfExists = TRUE;
                newRenameInfo->RootDirectory = NULL;
                newRenameInfo->FileNameLength = newQuarantinedFileName.Length;
                RtlCopyMemory(newRenameInfo->FileName, newQuarantinedFileName.Buffer, newQuarantinedFileName.Length);

                NTSTATUS renameStatus = ZwSetInformationFile(quarantinedFileHandle, &ioStatus, newRenameInfo,
                                                             newRenameInfoSize, FileRenameInformation);
                if (NT_SUCCESS(renameStatus))
                {
#if IS_DEBUG_IRP
                    DbgPrint("!!! FSfilter: Quarantined file renamed to: %wZ\n", &newQuarantinedFileName);
#endif
                }
                else
                {
#if IS_DEBUG_IRP
                    DbgPrint("!!! FSfilter: Failed to rename quarantined file: 0x%X\n", renameStatus);
#endif
                }
                ExFreePoolWithTag(newRenameInfo, OWLY_POOL_TAG_FILE_TEMP);
            }
            else
            {
#if IS_DEBUG_IRP
                DbgPrint("!!! FSfilter: Failed to allocate memory for quarantined file rename info.\n");
#endif
            }
            ZwClose(quarantinedFileHandle);
        }
        else
        {
#if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: Failed to open quarantined file for renaming: 0x%X\n", openQuarantinedStatus);
#endif
        }
    }
    else
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Failed to quarantine file: 0x%X\n", status);
#endif
    }

    return status;
}

// new code process recording
static VOID AddRemProcessRoutineCore(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create,
                                     PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    // FIX: Add early safety check for commHandle
    if (commHandle == NULL || commHandle->CommClosed)
        return;

    // FIX: Additional safety check for ZwQueryInformationProcess before any usage
    if (ZwQueryInformationProcess == NULL)
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Cannot process notification - ZwQueryInformationProcess is NULL\n");
#endif
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
        PUNICODE_STRING procName = NULL;
        PUNICODE_STRING parentName = NULL;
        PUNICODE_STRING procCmdLine = NULL;
        BOOLEAN mustFreeProcName = TRUE; // FALSE when procName is a borrowed pointer

        // Use minimal rights; on failure, still record using CreateInfo data
        ULONG openRights = PROCESS_QUERY_LIMITED_INFORMATION;

        hr = ZwOpenProcess(&procHandleParent, openRights, &objAttribs, &clientIdParent);
        if (!NT_SUCCESS(hr))
        {
#if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: Failed to open parent process (non-fatal): %#010x.\n", hr);
#endif
            procHandleParent = NULL; // continue without parent name
        }

        hr = ZwOpenProcess(&procHandleProcess, openRights, &objAttribs, &clientIdProcess);
        if (!NT_SUCCESS(hr))
        {
#if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: Failed to open process (non-fatal): %#010x.\n", hr);
#endif
            if (procHandleParent)
                ZwClose(procHandleParent);

            // Even if the process is already dead (STATUS_INVALID_CID,
            // STATUS_PROCESS_IS_TERMINATING, etc.) we still want to record and
            // forward it for scanning — the executable image is still on disk and
            // may be malware. Use the name the kernel already captured in CreateInfo.
            if (CreateInfo && CreateInfo->ImageFileName)
            {
                procName = const_cast<PUNICODE_STRING>(CreateInfo->ImageFileName); // borrowed pointer, don't free
                mustFreeProcName = FALSE;
            }
            else
            {
                return; // no name at all, truly nothing to record
            }
            goto record_process; // skip the GetProcessNameByHandle calls
        }

        if (procHandleParent != NULL)
        {
            hr = GetProcessNameByHandle(procHandleParent, &parentName);
            if (!NT_SUCCESS(hr))
            {
                // Parent name lookup failed (e.g. UAC-elevated process whose parent is AppInfo/AIS svchost).
                // parentName is only used for debug logging — don't drop the child event just because
                // we can't name the parent. GID inheritance uses ParentId (raw PID), not parentName.
#if IS_DEBUG_IRP
                DbgPrint("!!! FSfilter: Failed to get parent name (non-fatal, continuing): %#010x\n", hr);
#endif
                parentName = NULL;
            }
            ZwClose(procHandleParent);
        }

        hr = GetProcessNameByHandle(procHandleProcess, &procName);
        if (!NT_SUCCESS(hr))
        {
#if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: Failed to get process name: %#010x\n", hr);
#endif
            if (parentName != NULL)
                ExFreePoolWithTag(parentName, OWLY_POOL_TAG_PROCESS_NAME);
            ZwClose(procHandleProcess);
            return;
        }

        #if IS_DEBUG_IRP
            DbgPrint("!!! FSfilter: New Process, parent: %wZ. Pid: %d\n", parentName, (ULONG)(ULONG_PTR)ParentId);
        #endif

        // In legacy callback path, command line is not provided by CreateInfo.
        // Best-effort fallback: query ProcessCommandLineInformation directly.
        if (CreateInfo == NULL)
        {
            (VOID) GetProcessCommandLineByHandle(procHandleProcess, &procCmdLine);
        }

        // procHandleParent was already closed inside the if-block above
        ZwClose(procHandleProcess);

    record_process:
    #if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: New Process, process: %wZ , pid: %d.\n", procName, (ULONG)(ULONG_PTR)ProcessId);
#endif

        // FIX Bug#4: When mustFreeProcName==FALSE, procName is a borrowed pointer
        // to CreateInfo->ImageFileName which becomes invalid after this callback
        // returns. RecordNewProcess takes permanent ownership and later frees with
        // the process-name pool helper. We must ALWAYS pass a properly-tagged, owned copy.
        PUNICODE_STRING procNameForRecord = procName;
        if (!mustFreeProcName && procName != NULL)
        {
            procNameForRecord = FSCopyUnicodeStringForRecordNewProcess(procName);
            if (procNameForRecord == NULL)
            {
                // Allocation failed, cannot record this process.
                if (parentName != NULL)
                    ExFreePoolWithTag(parentName, OWLY_POOL_TAG_PROCESS_NAME);
                if (procCmdLine != NULL)
                    ExFreePoolWithTag(procCmdLine, OWLY_POOL_TAG_PROCESS_NAME);
                return;
            }
        }

        WCHAR processPathForMessage[MAX_FILE_NAME_LENGTH] = {0};
        USHORT processPathForMessageLength = 0;
        FSCopyProcessPathForMessage(procNameForRecord, processPathForMessage, &processPathForMessageLength);

        // ALWAYS record the process and send message to usermode
        ULONGLONG gid =
            driverData->RecordNewProcess(procNameForRecord, (ULONG)(ULONG_PTR)ProcessId, (ULONG)(ULONG_PTR)ParentId);

        // Send creation message to usermode
        PIRP_ENTRY newEntry = new IRP_ENTRY();
        if (newEntry != NULL)
        {
            PDRIVER_MESSAGE newItem = &newEntry->data;
            newItem->PID = (ULONG)(ULONG_PTR)ProcessId;
            newItem->Gid = gid;
            newItem->ParentPid = (ULONG)(ULONG_PTR)ParentId;
            newItem->IRP_OP = IRP_PROCESS_CREATE;

            if (processPathForMessageLength > 0)
            {
                RtlCopyMemory(newEntry->Buffer, processPathForMessage, processPathForMessageLength);
                newEntry->Buffer[processPathForMessageLength / sizeof(WCHAR)] = L'\0';
            }
            newEntry->filePath.Length = processPathForMessageLength;
            newEntry->filePath.MaximumLength = MAX_FILE_NAME_SIZE;
            newEntry->filePath.Buffer = newEntry->Buffer;

            if (CreateInfo && CreateInfo->CommandLine && CreateInfo->CommandLine->Buffer &&
                CreateInfo->CommandLine->Length > 0)
            {
                USHORT cmdCopyLen = (CreateInfo->CommandLine->Length < MAX_FILE_NAME_SIZE)
                                        ? CreateInfo->CommandLine->Length
                                        : (MAX_FILE_NAME_SIZE - sizeof(WCHAR));
                RtlCopyMemory(newItem->CommandLine, CreateInfo->CommandLine->Buffer, cmdCopyLen);
                newItem->CommandLine[cmdCopyLen / sizeof(WCHAR)] = L'\0';

                // Scan for AMSI bypasses in the command line
                AmsiScanCommandLine((ULONG)(ULONG_PTR)ProcessId, CreateInfo ? CreateInfo->CommandLine : procCmdLine);
            }
            else if (procCmdLine != NULL && procCmdLine->Buffer != NULL && procCmdLine->Length > 0)
            {
                USHORT cmdCopyLen = (procCmdLine->Length < MAX_FILE_NAME_SIZE) ? procCmdLine->Length
                                                                               : (MAX_FILE_NAME_SIZE - sizeof(WCHAR));
                RtlCopyMemory(newItem->CommandLine, procCmdLine->Buffer, cmdCopyLen);
                newItem->CommandLine[cmdCopyLen / sizeof(WCHAR)] = L'\0';

                // Scan for AMSI bypasses in the command line
                AmsiScanCommandLine((ULONG)(ULONG_PTR)ProcessId, procCmdLine);
            }

            if (!driverData->AddIrpMessage(newEntry))
            {
                delete newEntry;
            }
        }

        if (parentName != NULL)
            ExFreePoolWithTag(parentName, OWLY_POOL_TAG_PROCESS_NAME);
        if (procCmdLine != NULL)
            ExFreePoolWithTag(procCmdLine, OWLY_POOL_TAG_PROCESS_NAME);
        // Note: procName is managed by RecordNewProcess, don't free it here
    }
    else
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Terminate Process, Process: %d pid\n", (ULONG)(ULONG_PTR)ProcessId);
#endif

        (VOID) UserModeUnhookProcess((ULONG)(ULONG_PTR)ProcessId);
        // Always notifies usermode, Gid=0 signals "untracked process died"
        BOOLEAN found = FALSE;
        ULONGLONG gid = driverData->GetProcessGid((ULONG)(ULONG_PTR)ProcessId, &found);

        // Always send terminate — even if we didn't track this PID, usermode must
        // be able to clear any stale state it may have for this PID.
        PIRP_ENTRY newEntry = new IRP_ENTRY();
        if (newEntry != NULL)
        {
            PDRIVER_MESSAGE newItem = &newEntry->data;
            newItem->PID = (ULONG)(ULONG_PTR)ProcessId;
            newItem->Gid = found ? gid : 0ULL; // 0 = sentinel "not in our table"
            newItem->IRP_OP = IRP_PROCESS_TERMINATE;
            if (!driverData->AddIrpMessage(newEntry))
            {
                delete newEntry;
            }
        }
        driverData->RemoveProcess((ULONG)(ULONG_PTR)ProcessId);
    }
}

_Use_decl_annotations_ VOID AddRemProcessRoutineEx(PEPROCESS Process, HANDLE ProcessId,
                                                   PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    BOOLEAN isCreate = (CreateInfo != NULL);
    HANDLE parentId = isCreate ? CreateInfo->ParentProcessId : 0;
    AddRemProcessRoutineCore(parentId, ProcessId, isCreate, CreateInfo);
}

_Use_decl_annotations_ VOID AddRemProcessRoutineLegacy(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    AddRemProcessRoutineCore(ParentId, ProcessId, Create, NULL);
}

// ====================================================================
// Hook Device Dispatch Routines
// ====================================================================

NTSTATUS FSfilter_HookDeviceCreate_UNUSED(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS FSfilter_HookDeviceClose_UNUSED(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS FSfilter_HookDeviceControl_UNUSED(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesWritten = 0;

    typedef struct _HOOK_EVENT_DATA_WIRE80
    {
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
            if (rawBuffer)
            {
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
                    if (eventData80->FunctionName[0] != '\0')
                    {
                        ANSI_STRING asFunc;
                        UNICODE_STRING usFunc;
                        RtlInitAnsiString(&asFunc, eventData80->FunctionName);
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
                if (incomingQualified)
                {
                    functionName = incomingWideName;
                }
                else if (ResolveHookNameByEventId(eventType, resolvedHookName, RTL_NUMBER_OF(resolvedHookName)) &&
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

#if IS_DEBUG_IRP
                DbgPrint("FSfilter: API HOOKING EVENT RawType=%lu Name=%ws SourcePid=%lu TargetPid=%lu Arg1=0x%p "
                         "Arg2=0x%p Arg3=0x%p Arg4=0x%p\n",
                         eventType, functionName ? functionName : L"", processId, processId, (PVOID)rawArg1,
                         (PVOID)rawArg2, (PVOID)rawArg3, (PVOID)rawArg4);
#endif

                // Preserve raw event type and hook arguments; classification is normalized in ProcessProtection.
                OnKernelApiEvent(IRP_USERMODE_HOOK_EVENT, eventType, processId, processId, functionName, rawArg1,
                                 rawArg2, rawArg3, rawArg4);
            }
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }
    else
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesWritten;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
