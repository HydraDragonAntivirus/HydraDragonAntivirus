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
#include "Communication.h"
#include "DriverData.h"
#include "FsFilter.h"
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
#ifndef PROCESS_ALL_ACCESS
#define PROCESS_ALL_ACCESS 0x001FFFFF
#endif

// PsGetProcessImageFileName is an undocumented ntoskrnl export not present in
// all WDK headers.  Resolve it dynamically to avoid VCR001 "function definition
// not found" from the static analyser.
typedef UCHAR *(NTAPI *PPS_GET_PROCESS_IMAGE_FILE_NAME)(PEPROCESS Process);
static PPS_GET_PROCESS_IMAGE_FILE_NAME fnPsGetProcessImageFileName = NULL;

static VOID EnsurePsGetProcessImageFileName(VOID)
{
    if (fnPsGetProcessImageFileName == NULL)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"PsGetProcessImageFileName");
        fnPsGetProcessImageFileName = (PPS_GET_PROCESS_IMAGE_FILE_NAME)MmGetSystemRoutineAddress(&routineName);
    }
}

// Forward declaration for helper function
static BOOLEAN IsExecutableProtection(ULONG Protect);
static VOID PopulateKernelEventCommon(_Inout_ PDRIVER_MESSAGE Item, _In_ ULONG EventType, _In_ ULONG SourcePid,
                                      _In_ ULONG TargetPid);
static VOID SetKernelEventObjectName(_Inout_ PDRIVER_MESSAGE Item, _In_opt_z_ PCWSTR EventName);
static PCWSTR KernelEventDefaultLabel(_In_ ULONG EventType);
static VOID AppendProcessPathSuffix(_Inout_updates_z_(OutCch) PWCHAR OutBuffer, _In_ SIZE_T OutCch,
                                    _In_ ULONG ProcessId);
static BOOLEAN CopyProcessPathByPidBestEffort(_In_ ULONG ProcessId, _Out_writes_z_(OutCch) PWCHAR OutBuffer,
                                              _In_ SIZE_T OutCch, _In_ BOOLEAN AllowSlowLookup);
static BOOLEAN ShouldSkipProcessProtectionPid(_In_ ULONG ProcessId, _In_ BOOLEAN AllowSlowLookup);
static BOOLEAN ShouldSkipProcessProtectionPair(_In_ ULONG SourcePid, _In_ ULONG TargetPid,
                                               _In_ BOOLEAN AllowSlowLookup);

#define PROCESS_PROTECTION_RULE_POOL_TAG 'pKhO'
#define PROCESS_PROTECTION_RULE_MAX_FILE_SIZE (64 * 1024)
#define PROCESS_PROTECTION_RULE_MAX_LINE_CHARS 512

typedef struct _PROCESS_PROTECTION_EXCLUDE_RULE_SET
{
    PWSTR *Rules;
    ULONG Count;
    ULONG Capacity;
    FAST_MUTEX Mutex;
    volatile LONG MutexInitState;
    BOOLEAN Loaded;
} PROCESS_PROTECTION_EXCLUDE_RULE_SET, *PPROCESS_PROTECTION_EXCLUDE_RULE_SET;

static PROCESS_PROTECTION_EXCLUDE_RULE_SET g_ProcessProtectionExcludeRules = {0};
static volatile LONG g_ProcessProtectionExcludeLoadState = 0;

static VOID EnsureProcessProtectionRuleMutex(VOID)
{
    LONG state = InterlockedCompareExchange(&g_ProcessProtectionExcludeRules.MutexInitState, 0, 0);
    if (state == 2)
    {
        KeMemoryBarrier();
        return;
    }

    if (state == 0 && InterlockedCompareExchange(&g_ProcessProtectionExcludeRules.MutexInitState, 1, 0) == 0)
    {
        ExInitializeFastMutex(&g_ProcessProtectionExcludeRules.Mutex);
        KeMemoryBarrier();
        InterlockedExchange(&g_ProcessProtectionExcludeRules.MutexInitState, 2);
        return;
    }

    while (InterlockedCompareExchange(&g_ProcessProtectionExcludeRules.MutexInitState, 0, 0) != 2)
    {
        YieldProcessor();
    }

    KeMemoryBarrier();
}

static VOID FreeProcessProtectionExcludeRulesUnlocked(VOID)
{
    if (g_ProcessProtectionExcludeRules.Rules != NULL)
    {
        for (ULONG i = 0; i < g_ProcessProtectionExcludeRules.Count; ++i)
        {
            PWSTR current = g_ProcessProtectionExcludeRules.Rules[i];
            if (current != NULL)
            {
                ExFreePoolWithTag(current, PROCESS_PROTECTION_RULE_POOL_TAG);
            }
        }
        ExFreePoolWithTag(g_ProcessProtectionExcludeRules.Rules, PROCESS_PROTECTION_RULE_POOL_TAG);
    }

    g_ProcessProtectionExcludeRules.Rules = NULL;
    g_ProcessProtectionExcludeRules.Count = 0;
    g_ProcessProtectionExcludeRules.Capacity = 0;
}

static NTSTATUS EnsureProcessProtectionRuleCapacityUnlocked(_In_ ULONG RequiredCount)
{
    PWSTR *newArray;
    SIZE_T allocSize;
    ULONG newCapacity;

    if (g_ProcessProtectionExcludeRules.Capacity >= RequiredCount)
    {
        return STATUS_SUCCESS;
    }

    newCapacity = (g_ProcessProtectionExcludeRules.Capacity == 0) ? 8 : g_ProcessProtectionExcludeRules.Capacity * 2;
    if (newCapacity < RequiredCount)
    {
        newCapacity = RequiredCount;
    }

    allocSize = sizeof(PWSTR) * newCapacity;
    newArray = (PWSTR *)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, PROCESS_PROTECTION_RULE_POOL_TAG);
    if (newArray == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(newArray, allocSize);
    if (g_ProcessProtectionExcludeRules.Rules != NULL && g_ProcessProtectionExcludeRules.Count > 0)
    {
        RtlCopyMemory(newArray, g_ProcessProtectionExcludeRules.Rules,
                      sizeof(PWSTR) * g_ProcessProtectionExcludeRules.Count);
        ExFreePoolWithTag(g_ProcessProtectionExcludeRules.Rules, PROCESS_PROTECTION_RULE_POOL_TAG);
    }

    g_ProcessProtectionExcludeRules.Rules = newArray;
    g_ProcessProtectionExcludeRules.Capacity = newCapacity;
    return STATUS_SUCCESS;
}

static NTSTATUS AddProcessProtectionExcludeRuleNormalizedUnlocked(_In_reads_(RuleChars) PCWSTR RuleText,
                                                                  _In_ SIZE_T RuleChars)
{
    WCHAR normalizedLine[PROCESS_PROTECTION_RULE_MAX_LINE_CHARS];
    SIZE_T lineLen = 0;
    NTSTATUS status;

    if (!OwlyNormalizeRuleLineForMatch(RuleText, RuleChars, normalizedLine, RTL_NUMBER_OF(normalizedLine), FALSE,
                                       &lineLen) ||
        lineLen == 0)
    {
        return STATUS_SUCCESS;
    }

    for (ULONG i = 0; i < g_ProcessProtectionExcludeRules.Count; ++i)
    {
        if (_wcsicmp(g_ProcessProtectionExcludeRules.Rules[i], normalizedLine) == 0)
        {
            return STATUS_SUCCESS;
        }
    }

    status = EnsureProcessProtectionRuleCapacityUnlocked(g_ProcessProtectionExcludeRules.Count + 1);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    SIZE_T allocSize = (lineLen + 1) * sizeof(WCHAR);
    PWSTR newRule = (PWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, PROCESS_PROTECTION_RULE_POOL_TAG);
    if (newRule == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(newRule, allocSize);
    RtlCopyMemory(newRule, normalizedLine, lineLen * sizeof(WCHAR));
    newRule[lineLen] = L'\0';
    g_ProcessProtectionExcludeRules.Rules[g_ProcessProtectionExcludeRules.Count++] = newRule;
    return STATUS_SUCCESS;
}

static NTSTATUS AppendProcessProtectionExcludeRulesFromBufferUnlocked(_In_reads_bytes_(BytesRead) PUCHAR Buffer,
                                                                      _In_ ULONG BytesRead)
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
                    (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(&utf16Buffer[start], i - start);
                }
                start = i + 1;
            }
        }
        return STATUS_SUCCESS;
    }

    ULONG start = 0;
    for (ULONG i = 0; i <= BytesRead; ++i)
    {
        BOOLEAN isDelimiter = (i == BytesRead) || Buffer[i] == '\n' || Buffer[i] == '\r';
        if (isDelimiter)
        {
            if (i > start)
            {
                WCHAR lineBuffer[PROCESS_PROTECTION_RULE_MAX_LINE_CHARS];
                SIZE_T lineLen = 0;
                for (ULONG j = start; j < i && lineLen + 1 < RTL_NUMBER_OF(lineBuffer); ++j)
                {
                    lineBuffer[lineLen++] = (WCHAR)Buffer[j];
                }
                lineBuffer[lineLen] = L'\0';
                (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(lineBuffer, lineLen);
            }
            start = i + 1;
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS LoadProcessProtectionExcludeRulesFromFileUnlocked(_In_ PCUNICODE_STRING FilePath)
{
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK ioStatus;
    FILE_STANDARD_INFORMATION fileInfo;
    HANDLE fileHandle = NULL;
    NTSTATUS status;
    PUCHAR buffer = NULL;
    ULONG bufferSize;

    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    InitializeObjectAttributes(&oa, (PUNICODE_STRING)FilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    RtlZeroMemory(&ioStatus, sizeof(ioStatus));
    status = ZwCreateFile(&fileHandle, GENERIC_READ, &oa, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                          FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    RtlZeroMemory(&fileInfo, sizeof(fileInfo));
    status = ZwQueryInformationFile(fileHandle, &ioStatus, &fileInfo, sizeof(fileInfo), FileStandardInformation);
    if (!NT_SUCCESS(status))
    {
        ZwClose(fileHandle);
        return status;
    }

    if (fileInfo.EndOfFile.QuadPart <= 0 || fileInfo.EndOfFile.QuadPart > PROCESS_PROTECTION_RULE_MAX_FILE_SIZE)
    {
        ZwClose(fileHandle);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    bufferSize = (ULONG)fileInfo.EndOfFile.QuadPart;
    buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, PROCESS_PROTECTION_RULE_POOL_TAG);
    if (buffer == NULL)
    {
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(buffer, bufferSize);
    RtlZeroMemory(&ioStatus, sizeof(ioStatus));
    status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatus, buffer, bufferSize, NULL, NULL);
    if (NT_SUCCESS(status))
    {
        (VOID) AppendProcessProtectionExcludeRulesFromBufferUnlocked(buffer, (ULONG)ioStatus.Information);
    }

    ExFreePoolWithTag(buffer, PROCESS_PROTECTION_RULE_POOL_TAG);
    ZwClose(fileHandle);
    return status;
}

static VOID EnsureProcessProtectionExcludeRulesLoaded(VOID)
{
    if (InterlockedCompareExchange(&g_ProcessProtectionExcludeLoadState, 0, 0) == 2)
    {
        return;
    }

    LONG prevState = InterlockedCompareExchange(&g_ProcessProtectionExcludeLoadState, 1, 0);
    if (prevState == 2)
    {
        return;
    }

    if (prevState == 1)
    {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000LL;
        while (InterlockedCompareExchange(&g_ProcessProtectionExcludeLoadState, 0, 0) == 1)
        {
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
        return;
    }

    EnsureProcessProtectionRuleMutex();

    ExAcquireFastMutex(&g_ProcessProtectionExcludeRules.Mutex);
    FreeProcessProtectionExcludeRulesUnlocked();
    ExReleaseFastMutex(&g_ProcessProtectionExcludeRules.Mutex);

    BOOLEAN loadSucceeded = FALSE;
    static const PCWSTR ruleFiles[] = {OWLY_PROCESS_PROTECTION_RULE_FILE_KERNEL};
    for (ULONG i = 0; i < RTL_NUMBER_OF(ruleFiles); ++i)
    {
        UNICODE_STRING ruleFile;
        NTSTATUS loadStatus;
        RtlInitUnicodeString(&ruleFile, ruleFiles[i]);
        loadStatus = LoadProcessProtectionExcludeRulesFromFileUnlocked(&ruleFile);
        if (NT_SUCCESS(loadStatus))
        {
            loadSucceeded = TRUE;
        }
    }

    ExAcquireFastMutex(&g_ProcessProtectionExcludeRules.Mutex);
    g_ProcessProtectionExcludeRules.Loaded = loadSucceeded;
    ExReleaseFastMutex(&g_ProcessProtectionExcludeRules.Mutex);

    InterlockedExchange(&g_ProcessProtectionExcludeLoadState, loadSucceeded ? 2 : 0);
}

static BOOLEAN IsNormalizedPathExcludedByProcessProtectionRules(_In_ PCUNICODE_STRING NormalizedPath)
{
    BOOLEAN matched = FALSE;

    if (NormalizedPath == NULL || NormalizedPath->Buffer == NULL || NormalizedPath->Length < sizeof(WCHAR))
    {
        return FALSE;
    }

    // Paths and rules are normalized into a root-relative form such as
    // "\users\victim\..." so the match is stable across both DOS paths
    // and "\Device\HarddiskVolumeX\..." names.
    if (NormalizedPath->Buffer[0] != L'\\')
    {
        return FALSE;
    }

    EnsureProcessProtectionExcludeRulesLoaded();
    EnsureProcessProtectionRuleMutex();
    ExAcquireFastMutex(&g_ProcessProtectionExcludeRules.Mutex);
    for (ULONG i = 0; i < g_ProcessProtectionExcludeRules.Count; ++i)
    {
        PCWSTR rule = g_ProcessProtectionExcludeRules.Rules[i];
        if (rule == NULL || rule[0] == L'\0')
        {
            continue;
        }

        // Use prefix matching: the process path must START WITH the rule.
        // Previously wcsstr did a substring match, which could match a rule
        // appearing anywhere inside a path, causing unrelated processes to
        // be incorrectly excluded from process protection detection.
        SIZE_T ruleLen = wcslen(rule);
        SIZE_T pathChars = NormalizedPath->Length / sizeof(WCHAR);
        if (pathChars >= ruleLen && _wcsnicmp(NormalizedPath->Buffer, rule, ruleLen) == 0)
        {
            matched = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_ProcessProtectionExcludeRules.Mutex);

    return matched;
}

VOID FormatProcessDescriptorByPid(_In_ ULONG ProcessId, _Out_writes_z_(OutCch) PWCHAR OutBuffer, _In_ SIZE_T OutCch)
{
    if (OutBuffer == NULL || OutCch == 0)
    {
        return;
    }

    OutBuffer[0] = L'\0';
    if (!NT_SUCCESS(RtlStringCchPrintfW(OutBuffer, OutCch, L"%lu", ProcessId)))
    {
        return;
    }

    AppendProcessPathSuffix(OutBuffer, OutCch, ProcessId);
}

static BOOLEAN CopyProcessPathByPidBestEffort(_In_ ULONG ProcessId, _Out_writes_z_(OutCch) PWCHAR OutBuffer,
                                              _In_ SIZE_T OutCch, _In_ BOOLEAN AllowSlowLookup)
{
    if (OutBuffer == NULL || OutCch == 0)
    {
        return FALSE;
    }

    OutBuffer[0] = L'\0';

    if (ProcessId == 0)
    {
        return FALSE;
    }

    if (driverData != NULL && driverData->CopyProcessPathByPid(ProcessId, OutBuffer, OutCch))
    {
        return TRUE;
    }

    if (!AllowSlowLookup || KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FALSE;
    }

    PEPROCESS process = NULL;
    PUNICODE_STRING processImagePath = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    status = SeLocateProcessImageName(process, &processImagePath);
    ObDereferenceObject(process);
    if (!NT_SUCCESS(status) || processImagePath == NULL || processImagePath->Buffer == NULL ||
        processImagePath->Length == 0)
    {
        if (processImagePath != NULL)
        {
            ExFreePool(processImagePath);
        }
        return FALSE;
    }

    SIZE_T charsToCopy = processImagePath->Length / sizeof(WCHAR);
    if (charsToCopy >= OutCch)
    {
        charsToCopy = OutCch - 1;
    }

    if (charsToCopy > 0)
    {
        RtlCopyMemory(OutBuffer, processImagePath->Buffer, charsToCopy * sizeof(WCHAR));
    }
    OutBuffer[charsToCopy] = L'\0';
    ExFreePool(processImagePath);
    return TRUE;
}

static VOID AppendProcessPathSuffix(_Inout_updates_z_(OutCch) PWCHAR OutBuffer, _In_ SIZE_T OutCch,
                                    _In_ ULONG ProcessId)
{
    WCHAR pathBuffer[MAX_FILE_NAME_LENGTH] = {0};

    if (OutBuffer == NULL || OutCch == 0)
    {
        return;
    }

    if (!CopyProcessPathByPidBestEffort(ProcessId, pathBuffer, RTL_NUMBER_OF(pathBuffer), TRUE))
    {
        (VOID) RtlStringCchCatW(OutBuffer, OutCch, L":<path_unavailable>");
        return;
    }

    (VOID) RtlStringCchCatW(OutBuffer, OutCch, L":");
    (VOID) RtlStringCchCatW(OutBuffer, OutCch, pathBuffer);
}

static BOOLEAN ShouldSkipProcessProtectionPid(_In_ ULONG ProcessId, _In_ BOOLEAN AllowSlowLookup)
{
    WCHAR processPath[MAX_FILE_NAME_LENGTH] = {0};
    WCHAR normalizedBuffer[MAX_FILE_NAME_LENGTH] = {0};
    UNICODE_STRING processPathString;
    UNICODE_STRING normalizedPath;

    if (ProcessId == 0)
    {
        return FALSE;
    }

    if (!CopyProcessPathByPidBestEffort(ProcessId, processPath, RTL_NUMBER_OF(processPath), AllowSlowLookup))
    {
        return FALSE;
    }

    RtlInitUnicodeString(&processPathString, processPath);
    if (!OwlyNormalizePathForMatch(&processPathString, normalizedBuffer, &normalizedPath))
    {
        return FALSE;
    }

    return IsNormalizedPathExcludedByProcessProtectionRules(&normalizedPath);
}

static BOOLEAN ShouldSkipProcessProtectionPair(_In_ ULONG SourcePid, _In_ ULONG TargetPid, _In_ BOOLEAN AllowSlowLookup)
{
    UNREFERENCED_PARAMETER(TargetPid);

    // Only skip if the SOURCE process (the actor performing the operation)
    // is excluded. If the source is a trusted/excluded process, its actions
    // are considered benign and don't need to be reported.
    //
    // We intentionally do NOT skip when the TARGET is excluded. If an
    // unknown process tries to terminate or inject into a trusted target
    // (e.g. HydraDragonAntivirus), that IS suspicious and MUST be detected.
    // The old logic dropped those events, letting attackers target our own
    // processes silently.
    if (ShouldSkipProcessProtectionPid(SourcePid, AllowSlowLookup))
    {
        return TRUE;
    }

    return FALSE;
}

static VOID PopulateKernelEventCommon(_Inout_ PDRIVER_MESSAGE Item, _In_ ULONG EventType, _In_ ULONG SourcePid,
                                      _In_ ULONG TargetPid)
{
    LARGE_INTEGER timestamp;

    if (Item == NULL)
    {
        return;
    }

    KeQuerySystemTime(&timestamp);
    Item->KernelEventInfo.EventType = EventType;
    Item->KernelEventInfo.Timestamp = (ULONGLONG)timestamp.QuadPart;
    Item->KernelEventInfo.SourceProcessId = SourcePid;
    Item->KernelEventInfo.TargetProcessId = TargetPid;
    Item->KernelEventInfo.OperationStatus = STATUS_SUCCESS;
}

static VOID SetKernelEventObjectName(_Inout_ PDRIVER_MESSAGE Item, _In_opt_z_ PCWSTR EventName)
{
    if (Item == NULL)
    {
        return;
    }

    RtlZeroMemory(Item->KernelEventInfo.ObjectName, sizeof(Item->KernelEventInfo.ObjectName));
    if (EventName != NULL && EventName[0] != L'\0')
    {
        (VOID) RtlStringCchCopyW(Item->KernelEventInfo.ObjectName, RTL_NUMBER_OF(Item->KernelEventInfo.ObjectName),
                                 EventName);
    }
}

static PCWSTR KernelEventDefaultLabel(_In_ ULONG EventType)
{
    switch (EventType)
    {
    case IRP_KERNEL_REMOTE_THREAD:
        return L"IRP_KERNEL_REMOTE_THREAD";
    case IRP_KERNEL_CREATE_THREAD:
        return L"IRP_KERNEL_CREATE_THREAD";
    case IRP_KERNEL_WRITE_MEMORY:
        return L"IRP_KERNEL_WRITE_MEMORY";
    case IRP_KERNEL_PROTECT_MEMORY:
        return L"IRP_KERNEL_PROTECT_MEMORY";
    case IRP_KERNEL_QUEUE_APC:
        return L"IRP_KERNEL_QUEUE_APC";
    case IRP_KERNEL_CREATE_SECTION:
        return L"IRP_KERNEL_CREATE_SECTION";
    case IRP_KERNEL_MAP_SECTION:
        return L"IRP_KERNEL_MAP_SECTION";
    default:
        return L"";
    }
}

//
// --- Globals for ObRegisterCallbacks ---
//

static PVOID g_ObRegistrationHandle = NULL;
static POB_CALLBACK_REGISTRATION g_ObReg = NULL;
static POB_OPERATION_REGISTRATION g_OpReg = NULL;

//
// --- Forward Declarations ---
//

OB_PREOP_CALLBACK_STATUS ProcessHandlePreCallback(_In_ PVOID RegistrationContext,
                                                  _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation);

NTSTATUS QueueTerminationAttemptToUserMode(PEPROCESS AttackerProcess, PEPROCESS TargetProcess);

BOOLEAN IsSystemProcessPP(PEPROCESS Process);

//
// --- Initialization and Cleanup ---
//

NTSTATUS InitProcessProtection()
{
    NTSTATUS status = STATUS_SUCCESS;

    // Safety: ensure called at PASSIVE_LEVEL
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        DbgPrint("!!! ProcessProtection: InitProcessProtection called at wrong IRQL %u\n", (ULONG)KeGetCurrentIrql());
        return STATUS_INVALID_LEVEL;
    }

    // Allocate operation registration (only for process handles)
    g_OpReg =
        (POB_OPERATION_REGISTRATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(OB_OPERATION_REGISTRATION), 'ppOr');
    if (!g_OpReg)
    {
        DbgPrint("!!! ProcessProtection: Failed to allocate operation registration\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_OpReg, sizeof(OB_OPERATION_REGISTRATION));

    g_ObReg = (POB_CALLBACK_REGISTRATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(OB_CALLBACK_REGISTRATION), 'ppCr');
    if (!g_ObReg)
    {
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
    g_ObReg->Version = OB_FLT_REGISTRATION_VERSION;
    g_ObReg->OperationRegistrationCount = 1;
    g_ObReg->OperationRegistration = g_OpReg;
    g_ObReg->RegistrationContext = NULL;
    // Use a different altitude than PYAS to avoid conflicts
    RtlInitUnicodeString(&g_ObReg->Altitude, L"321100");

    // Register callbacks
    status = ObRegisterCallbacks(g_ObReg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("!!! ProcessProtection: ObRegisterCallbacks failed: 0x%X\n", status);
        ExFreePoolWithTag(g_OpReg, 'ppOr');
        ExFreePoolWithTag(g_ObReg, 'ppCr');
        g_OpReg = NULL;
        g_ObReg = NULL;
        return status;
    }

    EnsureProcessProtectionExcludeRulesLoaded();
    DbgPrint("!!! ProcessProtection: ObRegisterCallbacks succeeded\n");
    return STATUS_SUCCESS;
}

VOID UninitProcessProtection()
{
    // Unregister the object callback
    if (g_ObRegistrationHandle)
    {
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObRegistrationHandle = NULL;
        DbgPrint("!!! ProcessProtection: ObUnRegisterCallbacks completed\n");
    }

    // Free the allocated registration memory
    if (g_OpReg)
    {
        ExFreePoolWithTag(g_OpReg, 'ppOr');
        g_OpReg = NULL;
    }
    if (g_ObReg)
    {
        ExFreePoolWithTag(g_ObReg, 'ppCr');
        g_ObReg = NULL;
    }

    EnsureProcessProtectionRuleMutex();
    ExAcquireFastMutex(&g_ProcessProtectionExcludeRules.Mutex);
    FreeProcessProtectionExcludeRulesUnlocked();
    g_ProcessProtectionExcludeRules.Loaded = FALSE;
    ExReleaseFastMutex(&g_ProcessProtectionExcludeRules.Mutex);
    InterlockedExchange(&g_ProcessProtectionExcludeLoadState, 0);

    DbgPrint("!!! ProcessProtection: Unloaded\n");
}

//
// --- Callback Implementation ---
//

OB_PREOP_CALLBACK_STATUS ProcessHandlePreCallback(_In_ PVOID RegistrationContext,
                                                  _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation)
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
    ULONG callerPid = (ULONG)(ULONG_PTR)PsGetProcessId(currentProc);
    ULONG targetPid = (ULONG)(ULONG_PTR)PsGetProcessId(targetProc);

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

    if (ShouldSkipProcessProtectionPair(callerPid, targetPid, FALSE))
        return OB_PREOP_SUCCESS;

    // 5. Capture requested access mask (read-only, never modify).
    ACCESS_MASK desiredAccess = 0;
    if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
    {
        desiredAccess = pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    }
    else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
    {
        desiredAccess = pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    }

    // 6. NOTIFY-ONLY: report all cross-process handle operations.
    //
    // Previously only PROCESS_TERMINATE was reported, silently dropping
    // PROCESS_VM_WRITE / DUP_HANDLE / CREATE_THREAD -- the exact masks
    // used by process injection. We now report every cross-process open.
    // DesiredAccess is NEVER modified -- this is pure telemetry.
    if (desiredAccess & PROCESS_TERMINATE)
    {
        QueueTerminationAttemptToUserMode(currentProc, targetProc);
    }
    else
    {
        OnProcessHandleOperation((HANDLE)(ULONG_PTR)callerPid, (HANDLE)(ULONG_PTR)targetPid, desiredAccess,
                                 (UCHAR)pOperationInformation->Operation);
    }

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
    if (pid == (HANDLE)4 || pid == (HANDLE)0)
    {
        return TRUE;
    }

    // Check for critical subsystem processes using the process name
    // PsGetProcessImageFileName is safe (doesn't open handles)
    EnsurePsGetProcessImageFileName();
    UCHAR *processName = fnPsGetProcessImageFileName ? fnPsGetProcessImageFileName(Process) : NULL;

    if (processName)
    {
        if (_stricmp((char *)processName, "csrss.exe") == 0 || _stricmp((char *)processName, "lsass.exe") == 0 ||
            _stricmp((char *)processName, "services.exe") == 0 || _stricmp((char *)processName, "wininit.exe") == 0 ||
            _stricmp((char *)processName, "smss.exe") == 0 || _stricmp((char *)processName, "System") == 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}

NTSTATUS QueueTerminationAttemptToUserMode(PEPROCESS AttackerProcess, PEPROCESS TargetProcess)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    HANDLE attackerPid = PsGetProcessId(AttackerProcess);
    HANDLE targetPid = PsGetProcessId(TargetProcess);

    if (ShouldSkipProcessProtectionPair((ULONG)(ULONG_PTR)attackerPid, (ULONG)(ULONG_PTR)targetPid, FALSE))
    {
        return STATUS_SUCCESS;
    }

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
    if (newEntry == NULL)
    {
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

    // NOTE: SeLocateProcessImageName is NOT called here.
    // It acquires the process image-section/token lock inside an ObCallback,
    // which deadlocks when the target process is initializing or tearing down.
    // User-mode can look up the path from the PID.
    newEntry->Buffer[0] = L'\0';
    newEntry->filePath.Length = 0;
    newEntry->filePath.MaximumLength = MAX_FILE_NAME_SIZE;
    newEntry->filePath.Buffer = newEntry->Buffer;

    DbgPrint("!!! ProcessProtection: Termination attempt detected - Attacker PID %d (GID %llu) -> Target PID %d (GID "
             "%llu)\n",
             (ULONG)(ULONG_PTR)attackerPid, attackerGid, (ULONG)(ULONG_PTR)targetPid, targetGid);

    // Add to IRP queue
    if (!driverData->AddIrpMessage(newEntry))
    {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}
//
// --- New Event Detection Functions for Comprehensive Process Monitoring ---
//

NTSTATUS OnProcessCreate(_In_ HANDLE ProcessId, _In_ HANDLE ParentProcessId)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
    ULONG parentPid = (ULONG)(ULONG_PTR)ParentProcessId;

    if (ShouldSkipProcessProtectionPid(pid, TRUE))
        return STATUS_SUCCESS;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;
    newItem->PID = pid;
    newItem->ParentPid = parentPid;
    newItem->IRP_OP = IRP_PROCESS_CREATE;

    BOOLEAN found = FALSE;
    newItem->Gid = driverData->GetProcessGid(pid, &found);

    DbgPrint("!!! ProcessProtection: Process created - PID %lu (Parent: %lu, GID: %llu)\n", pid, parentPid,
             newItem->Gid);

    if (!driverData->AddIrpMessage(newEntry))
    {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS OnProcessExit(_In_ HANDLE ProcessId)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;

    if (ShouldSkipProcessProtectionPid(pid, TRUE))
        return STATUS_SUCCESS;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;
    newItem->PID = pid;
    newItem->IRP_OP = IRP_PROCESS_EXIT;

    BOOLEAN found = FALSE;
    newItem->Gid = driverData->GetProcessGid(pid, &found);

    DbgPrint("!!! ProcessProtection: Process exited - PID %lu (GID: %llu)\n", pid, newItem->Gid);

    if (!driverData->AddIrpMessage(newEntry))
    {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS OnProcessHandleOperation(_In_ HANDLE CallerProcessId, _In_ HANDLE TargetProcessId,
                                  _In_ ACCESS_MASK DesiredAccess, _In_ UCHAR OperationType)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    ULONG callerPid = (ULONG)(ULONG_PTR)CallerProcessId;
    ULONG targetPid = (ULONG)(ULONG_PTR)TargetProcessId;

    if (ShouldSkipProcessProtectionPair(callerPid, targetPid, FALSE))
        return STATUS_SUCCESS;

    // Get GIDs if processes are tracked
    BOOLEAN callerFound = FALSE;
    BOOLEAN targetFound = FALSE;
    ULONGLONG callerGid = driverData->GetProcessGid(callerPid, &callerFound);
    ULONGLONG targetGid = driverData->GetProcessGid(targetPid, &targetFound);

    // Skip if neither process is tracked
    if (!callerFound && !targetFound)
        return STATUS_SUCCESS;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL)
    {
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

    if (!driverData->AddIrpMessage(newEntry))
    {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS OnProcessTerminationAttempt(_In_ HANDLE AttackerPid, _In_ HANDLE TargetPid)
{
    // FIX: AttackerPid/TargetPid are PID integers, NOT PEPROCESS pointers.
    // The old cast (PEPROCESS)AttackerPid caused instant bugcheck when
    // QueueTerminationAttemptToUserMode dereferenced the "pointer".
    // Resolve EPROCESS from PID with reference counting.
    PEPROCESS attackerProc = NULL;
    PEPROCESS targetProc = NULL;
    NTSTATUS st;

    st = PsLookupProcessByProcessId(AttackerPid, &attackerProc);
    if (!NT_SUCCESS(st))
        return st;

    st = PsLookupProcessByProcessId(TargetPid, &targetProc);
    if (!NT_SUCCESS(st))
    {
        ObDereferenceObject(attackerProc);
        return st;
    }

    st = QueueTerminationAttemptToUserMode(attackerProc, targetProc);

    ObDereferenceObject(targetProc);
    ObDereferenceObject(attackerProc);
    return st;
}

//
// --- Kernel API Hook Integration Functions ---
//

NTSTATUS OnKernelApiEvent(_In_ ULONG EventType, _In_ ULONG SourcePid, _In_ ULONG TargetPid,
                          _In_opt_ PCWSTR FunctionName, _In_opt_ ULONG_PTR EventArg1, _In_opt_ ULONG_PTR EventArg2,
                          _In_opt_ ULONG_PTR EventArg3, _In_opt_ ULONG_PTR EventArg4)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    if (ShouldSkipProcessProtectionPair(SourcePid, TargetPid, TRUE))
        return STATUS_SUCCESS;

    WCHAR sourceProcessDescriptor[MAX_FILE_NAME_LENGTH + 32] = {0};
    WCHAR targetProcessDescriptor[MAX_FILE_NAME_LENGTH + 32] = {0};
    BOOLEAN sourceFound = FALSE;
    BOOLEAN targetFound = FALSE;
    ULONGLONG sourceGid = driverData->GetProcessGid(SourcePid, &sourceFound);
    ULONGLONG targetGid = driverData->GetProcessGid(TargetPid, &targetFound);

    // Keep the owning message PID stable even when a hook event cannot resolve
    // a remote target PID. KernelEventInfo preserves the exact source/target.
    const ULONG ownerPid = (TargetPid != 0) ? TargetPid : SourcePid;
    const ULONGLONG ownerGid = targetFound ? targetGid : sourceGid;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;
    newItem->PID = ownerPid;
    newItem->Gid = ownerGid;
    newItem->AttackerPID = SourcePid;
    newItem->AttackerGid = sourceGid;
    newItem->IRP_OP = IRP_HYPERVISOR_EVENT;

    // Preserve full HIM/API-hook metadata while emitting one generic opcode.
    PopulateKernelEventCommon(newItem, EventType, SourcePid, TargetPid);
    newItem->KernelEventInfo.RawArgument1 = EventArg1;
    newItem->KernelEventInfo.RawArgument2 = EventArg2;
    newItem->KernelEventInfo.RawArgument3 = EventArg3;
    newItem->KernelEventInfo.RawArgument4 = EventArg4;
    newItem->KernelEventInfo.MemoryAddress = (PVOID)EventArg2;
    newItem->KernelEventInfo.ThreadHandle = (HANDLE)EventArg1;
    newItem->KernelEventInfo.AccessMask = (ACCESS_MASK)EventArg1;

    PCWSTR effectiveName =
        (FunctionName != NULL && FunctionName[0] != L'\0') ? FunctionName : KernelEventDefaultLabel(EventType);
    SetKernelEventObjectName(newItem, effectiveName);

    FormatProcessDescriptorByPid(SourcePid, sourceProcessDescriptor, RTL_NUMBER_OF(sourceProcessDescriptor));
    FormatProcessDescriptorByPid(TargetPid, targetProcessDescriptor, RTL_NUMBER_OF(targetProcessDescriptor));

    DbgPrint("!!! ProcessProtection: API HOOKING EVENT forwarded - RawType: %lu, GenericOp: %u, Name: %ls, "
             "src_pid_path=%ws, target_pid_path=%ws, Arg1: 0x%p, Arg2: 0x%p, Arg3: 0x%p, Arg4: 0x%p\n",
             EventType, IRP_HYPERVISOR_EVENT, effectiveName, sourceProcessDescriptor, targetProcessDescriptor,
             (PVOID)EventArg1, (PVOID)EventArg2, (PVOID)EventArg3, (PVOID)EventArg4);

    if (!driverData->AddIrpMessage(newEntry))
    {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS OnMemoryWrite(_In_ ULONG SourcePid, _In_ ULONG TargetPid, _In_ PVOID TargetAddress, _In_ SIZE_T Size,
                       _In_ BOOLEAN IsExecutableMemory)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    if (ShouldSkipProcessProtectionPair(SourcePid, TargetPid, TRUE))
        return STATUS_SUCCESS;

    BOOLEAN sourceFound = FALSE;
    BOOLEAN targetFound = FALSE;
    ULONGLONG sourceGid = driverData->GetProcessGid(SourcePid, &sourceFound);
    ULONGLONG targetGid = driverData->GetProcessGid(TargetPid, &targetFound);

    if (!sourceFound && !targetFound)
        return STATUS_SUCCESS;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;
    newItem->PID = TargetPid;
    newItem->Gid = targetGid;
    newItem->AttackerPID = SourcePid;
    newItem->AttackerGid = sourceGid;
    newItem->IRP_OP = IRP_KERNEL_WRITE_MEMORY;

    PopulateKernelEventCommon(newItem, IRP_KERNEL_WRITE_MEMORY, SourcePid, TargetPid);
    newItem->KernelEventInfo.MemoryAddress = TargetAddress;
    newItem->KernelEventInfo.MemorySize = Size;
    newItem->KernelEventInfo.IsExecutableMemory = IsExecutableMemory;
    newItem->KernelEventInfo.RawArgument1 = (ULONG_PTR)TargetAddress;
    newItem->KernelEventInfo.RawArgument2 = (ULONG_PTR)Size;
    newItem->KernelEventInfo.AccessMask = PROCESS_VM_WRITE;
    SetKernelEventObjectName(newItem, L"IRP_KERNEL_WRITE_MEMORY");

    DbgPrint("!!! ProcessProtection: Memory write detected - Source PID %lu -> Target PID %lu (Address: %p, Size: %zu, "
             "Executable: %u)\n",
             SourcePid, TargetPid, TargetAddress, Size, IsExecutableMemory);

    if (!driverData->AddIrpMessage(newEntry))
    {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS OnMemoryProtectionChange(_In_ ULONG SourcePid, _In_ ULONG TargetPid, _In_ PVOID BaseAddress,
                                  _In_ SIZE_T RegionSize, _In_ ULONG NewProtection, _In_ ULONG OldProtection)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    if (ShouldSkipProcessProtectionPair(SourcePid, TargetPid, TRUE))
        return STATUS_SUCCESS;

    BOOLEAN sourceFound = FALSE;
    BOOLEAN targetFound = FALSE;
    ULONGLONG sourceGid = driverData->GetProcessGid(SourcePid, &sourceFound);
    ULONGLONG targetGid = driverData->GetProcessGid(TargetPid, &targetFound);

    if (!sourceFound && !targetFound)
        return STATUS_SUCCESS;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;
    newItem->PID = TargetPid;
    newItem->Gid = targetGid;
    newItem->AttackerPID = SourcePid;
    newItem->AttackerGid = sourceGid;
    newItem->IRP_OP = IRP_KERNEL_PROTECT_MEMORY;

    PopulateKernelEventCommon(newItem, IRP_KERNEL_PROTECT_MEMORY, SourcePid, TargetPid);
    newItem->KernelEventInfo.MemoryAddress = BaseAddress;
    newItem->KernelEventInfo.MemorySize = RegionSize;
    newItem->KernelEventInfo.MemoryProtection = NewProtection;
    newItem->KernelEventInfo.IsExecutableMemory = IsExecutableProtection(NewProtection);
    newItem->KernelEventInfo.RawArgument1 = (ULONG_PTR)BaseAddress;
    newItem->KernelEventInfo.RawArgument2 =
        (((ULONG_PTR)NewProtection) << 32) | ((ULONG_PTR)OldProtection & 0xffffffffull);
    newItem->KernelEventInfo.AccessMask = PROCESS_VM_OPERATION;
    SetKernelEventObjectName(newItem, L"IRP_KERNEL_PROTECT_MEMORY");

    DbgPrint("!!! ProcessProtection: Memory protection change - Source PID %lu -> Target PID %lu (Old: 0x%X, New: "
             "0x%X, Executable: %u)\n",
             SourcePid, TargetPid, OldProtection, NewProtection, IsExecutableProtection(NewProtection));

    if (!driverData->AddIrpMessage(newEntry))
    {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS OnThreadCreation(_In_ ULONG SourcePid, _In_ ULONG TargetPid, _In_ PVOID StartRoutine)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    if (ShouldSkipProcessProtectionPair(SourcePid, TargetPid, TRUE))
        return STATUS_SUCCESS;

    BOOLEAN sourceFound = FALSE;
    BOOLEAN targetFound = FALSE;
    ULONGLONG sourceGid = driverData->GetProcessGid(SourcePid, &sourceFound);
    ULONGLONG targetGid = driverData->GetProcessGid(TargetPid, &targetFound);

    if (!sourceFound && !targetFound)
        return STATUS_SUCCESS;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;
    newItem->PID = TargetPid;
    newItem->Gid = targetGid;
    newItem->AttackerPID = SourcePid;
    newItem->AttackerGid = sourceGid;
    newItem->IRP_OP = IRP_KERNEL_REMOTE_THREAD;

    PopulateKernelEventCommon(newItem, IRP_KERNEL_REMOTE_THREAD, SourcePid, TargetPid);
    newItem->KernelEventInfo.ThreadStartRoutine = StartRoutine;
    newItem->KernelEventInfo.RawArgument1 = (ULONG_PTR)StartRoutine;
    newItem->KernelEventInfo.AccessMask = PROCESS_CREATE_THREAD;
    SetKernelEventObjectName(newItem, L"IRP_KERNEL_REMOTE_THREAD");

    DbgPrint("!!! ProcessProtection: Remote thread creation - Source PID %lu -> Target PID %lu (Start: %p)\n",
             SourcePid, TargetPid, StartRoutine);

    if (!driverData->AddIrpMessage(newEntry))
    {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS OnApcQueueing(_In_ ULONG SourcePid, _In_ ULONG TargetPid, _In_ HANDLE ThreadHandle, _In_ PVOID ApcRoutine)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    if (ShouldSkipProcessProtectionPair(SourcePid, TargetPid, TRUE))
        return STATUS_SUCCESS;

    BOOLEAN sourceFound = FALSE;
    BOOLEAN targetFound = FALSE;
    ULONGLONG sourceGid = driverData->GetProcessGid(SourcePid, &sourceFound);
    ULONGLONG targetGid = driverData->GetProcessGid(TargetPid, &targetFound);

    if (!sourceFound && !targetFound)
        return STATUS_SUCCESS;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;
    newItem->PID = TargetPid;
    newItem->Gid = targetGid;
    newItem->AttackerPID = SourcePid;
    newItem->AttackerGid = sourceGid;
    newItem->IRP_OP = IRP_KERNEL_QUEUE_APC;

    PopulateKernelEventCommon(newItem, IRP_KERNEL_QUEUE_APC, SourcePid, TargetPid);
    newItem->KernelEventInfo.ThreadHandle = ThreadHandle;
    newItem->KernelEventInfo.ThreadStartRoutine = ApcRoutine;
    newItem->KernelEventInfo.RawArgument1 = (ULONG_PTR)ThreadHandle;
    newItem->KernelEventInfo.RawArgument2 = (ULONG_PTR)ApcRoutine;
    SetKernelEventObjectName(newItem, L"IRP_KERNEL_QUEUE_APC");

    DbgPrint("!!! ProcessProtection: APC queued - Source PID %lu -> Target PID %lu (Thread: %p, APC: %p)\n", SourcePid,
             TargetPid, ThreadHandle, ApcRoutine);

    if (!driverData->AddIrpMessage(newEntry))
    {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS OnSectionOperation(_In_ ULONG SourcePid, _In_ ULONG TargetPid, _In_opt_ PCWSTR SectionName,
                            _In_ UCHAR OperationType)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    if (ShouldSkipProcessProtectionPair(SourcePid, TargetPid, TRUE))
        return STATUS_SUCCESS;

    BOOLEAN sourceFound = FALSE;
    BOOLEAN targetFound = FALSE;
    ULONGLONG sourceGid = driverData->GetProcessGid(SourcePid, &sourceFound);
    ULONGLONG targetGid = driverData->GetProcessGid(TargetPid, &targetFound);

    if (!sourceFound && !targetFound)
        return STATUS_SUCCESS;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PDRIVER_MESSAGE newItem = &newEntry->data;
    newItem->PID = TargetPid;
    newItem->Gid = targetGid;
    newItem->AttackerPID = SourcePid;
    newItem->AttackerGid = sourceGid;

    UCHAR irpOp = (OperationType == 1) ? (UCHAR)IRP_KERNEL_CREATE_SECTION : (UCHAR)IRP_KERNEL_MAP_SECTION;
    newItem->IRP_OP = irpOp;

    PopulateKernelEventCommon(newItem, irpOp, SourcePid, TargetPid);
    newItem->KernelEventInfo.RawArgument1 = (ULONG_PTR)OperationType;
    SetKernelEventObjectName(newItem, (OperationType == 1) ? L"IRP_KERNEL_CREATE_SECTION" : L"IRP_KERNEL_MAP_SECTION");

    if (SectionName != NULL)
    {
        (VOID) RtlStringCchCopyW(newEntry->Buffer, RTL_NUMBER_OF(newEntry->Buffer), SectionName);
        newEntry->filePath.Buffer = newEntry->Buffer;
        newEntry->filePath.Length = (USHORT)(wcslen(newEntry->Buffer) * sizeof(WCHAR));
        newEntry->filePath.MaximumLength = MAX_FILE_NAME_SIZE;
    }

    DbgPrint("!!! ProcessProtection: Section operation - Source PID %lu -> Target PID %lu (Type: %u, Name: %ws)\n",
             SourcePid, TargetPid, OperationType, SectionName ? SectionName : L"<unnamed>");

    if (!driverData->AddIrpMessage(newEntry))
    {
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
    return (Protect & PAGE_EXECUTE) || (Protect & PAGE_EXECUTE_READ) || (Protect & PAGE_EXECUTE_READWRITE) ||
           (Protect & PAGE_EXECUTE_WRITECOPY);
}
