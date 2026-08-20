/*++

Module Name:

    ProcessProtection.cpp

Abstract:

    Comprehensive process protection implementation using ObRegisterCallbacks and
    kernel-level API hooks. Detects all process-related events:
    - Process termination attempts
    - Process handle operations
    - Kernel API injection attempts

Environment:

    Kernel mode

--*/

#include "ProcessProtection.h"
#include "Communication.h"
#include "DriverData.h"
#include "common.h"
#include "osutils.h"   // cmd::getTickCount64, cmd::g_pCommonData (via common.h chain)
#include "fltport.h"
#include <ntstrsafe.h>

// All cmd:: symbols used in the LBVS blocks below are fully-qualified.
// getTickCount64 and g_pCommonData live in namespace cmd (osutils.h / common.h).

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
static PCWSTR KernelEventDefaultLabel(_In_ ULONG EventType);
static VOID AppendProcessPathSuffix(_Inout_updates_z_(OutCch) PWCHAR OutBuffer, _In_ SIZE_T OutCch,
                                    _In_ ULONG ProcessId);
static BOOLEAN CopyProcessPathByPidBestEffort(_In_ ULONG ProcessId, _Out_writes_z_(OutCch) PWCHAR OutBuffer,
                                              _In_ SIZE_T OutCch, _In_ BOOLEAN AllowSlowLookup);
static BOOLEAN ShouldSkipProcessProtectionPid(_In_ ULONG ProcessId, _In_ BOOLEAN AllowSlowLookup);
static BOOLEAN ShouldSkipProcessProtectionPair(_In_ ULONG SourcePid, _In_ ULONG TargetPid,
                                               _In_ BOOLEAN AllowSlowLookup);
static BOOLEAN IsSystemProcessPP(PEPROCESS Process);

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
    newArray = (PWSTR *)ExAllocatePoolWithTag(NonPagedPool, allocSize, PROCESS_PROTECTION_RULE_POOL_TAG);
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
        if (OwlyWideEqualsInsensitiveBounded(g_ProcessProtectionExcludeRules.Rules[i],
                                             PROCESS_PROTECTION_RULE_MAX_LINE_CHARS,
                                             normalizedLine, RTL_NUMBER_OF(normalizedLine)))
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
    PWSTR newRule = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, allocSize, PROCESS_PROTECTION_RULE_POOL_TAG);
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



static VOID EnsureProcessProtectionExcludeRulesLoaded(VOID)
{
    return;
}



VOID ReloadProcessProtectionExcludeRules(VOID)
{
    EnsureProcessProtectionRuleMutex();
    ExAcquireFastMutex(&g_ProcessProtectionExcludeRules.Mutex);
    FreeProcessProtectionExcludeRulesUnlocked();
    g_ProcessProtectionExcludeRules.Loaded = FALSE;
    ExReleaseFastMutex(&g_ProcessProtectionExcludeRules.Mutex);
    InterlockedExchange(&g_ProcessProtectionExcludeLoadState, 0);
    EnsureProcessProtectionExcludeRulesLoaded();
}

static NTSTATUS InitializeProcessProtectionRules(VOID)
{
    EnsureProcessProtectionRuleMutex();

    ExAcquireFastMutex(&g_ProcessProtectionExcludeRules.Mutex);

    // Dynamic hook exclude rules (normalized/contains match, case-insensitive)
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\smss.exe", 27);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\csrss.exe", 28);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\wininit.exe", 30);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\winlogon.exe", 31);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\lsass.exe", 28);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\services.exe", 31);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\svchost.exe", 30);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\fontdrvhost.exe", 34);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\sihost.exe", 29);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\dwm.exe", 26);

    // HydraDragonAntivirus-specific examples
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Program Files\\HydraDragonAntivirus", 38);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\ProgramData\\edrsvc", 22);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\tasks\\hydradragonantivirus", 45);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\edrpm64.dll", 29);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\edrpm32.dll", 29);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\edrmm.dll", 27);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\drivers\\sanctum.sys", 39);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\drivers\\edrdrv.sys", 38);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\drivers\\OwlyshieldRansomFilter.sys", 55);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\drivers\\RedDbgDrv.sys", 41);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\drivers\\hyperhv.sys", 39);
    // (VOID) AddProcessProtectionExcludeRuleNormalizedUnlocked(L"C:\\Program Files\\HydraDragonAntivirus\\hydradragon\\sanctum", 56);

    g_ProcessProtectionExcludeRules.Loaded = TRUE;

    ExReleaseFastMutex(&g_ProcessProtectionExcludeRules.Mutex);
    InterlockedExchange(&g_ProcessProtectionExcludeLoadState, 2);
    return STATUS_SUCCESS;
}

NTSTATUS SetProcessProtectionExcludeRulesFromBuffer(
    _In_reads_bytes_(BytesRead) PUCHAR Buffer,
    _In_ ULONG BytesRead)
{
    NTSTATUS status;

    if (Buffer == NULL || BytesRead == 0 || BytesRead > PROCESS_PROTECTION_RULE_MAX_FILE_SIZE)
    {
        return STATUS_INVALID_PARAMETER;
    }

    EnsureProcessProtectionRuleMutex();

    ExAcquireFastMutex(&g_ProcessProtectionExcludeRules.Mutex);
    FreeProcessProtectionExcludeRulesUnlocked();

    status = AppendProcessProtectionExcludeRulesFromBufferUnlocked(Buffer, BytesRead);
    g_ProcessProtectionExcludeRules.Loaded = NT_SUCCESS(status);

    ExReleaseFastMutex(&g_ProcessProtectionExcludeRules.Mutex);
    InterlockedExchange(&g_ProcessProtectionExcludeLoadState, NT_SUCCESS(status) ? 2 : 0);

    return status;
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
        // Fast path: CopyProcessPathByPid may return an NT device path.
        // Attempt conversion to DOS path at PASSIVE_LEVEL.
        if (KeGetCurrentIrql() == PASSIVE_LEVEL)
        {
            WCHAR dosPathBuf[MAX_FILE_NAME_LENGTH] = {0};
            if (NtPathToDosPath(OutBuffer, dosPathBuf, RTL_NUMBER_OF(dosPathBuf)))
            {
                (VOID)RtlStringCchCopyW(OutBuffer, OutCch, dosPathBuf);
            }
        }
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

    // Slow path: SeLocateProcessImageName returns an NT device path. Convert to DOS.
    {
        WCHAR dosPathBuf[MAX_FILE_NAME_LENGTH] = {0};
        if (NtPathToDosPath(OutBuffer, dosPathBuf, RTL_NUMBER_OF(dosPathBuf)))
        {
            (VOID)RtlStringCchCopyW(OutBuffer, OutCch, dosPathBuf);
        }
    }

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

    // Direct check for the registered service PID to avoid expensive path lookups
    if (driverData != NULL && ProcessId == driverData->getPID())
    {
        return TRUE;
    }

    // Hardened check for system processes that might not be in our path cache
    PEPROCESS proc = NULL;
    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &proc)))
    {
        if (IsSystemProcessPP(proc))
        {
            ObDereferenceObject(proc);
            return TRUE;
        }
        ObDereferenceObject(proc);
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

static PCWSTR KernelEventDefaultLabel(_In_ ULONG EventType)
{
    switch (EventType)
    {
    case IRP_USERMODE_HOOK_EVENT:
        return L"IRP_USERMODE_HOOK_EVENT";
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

static BOOLEAN WideContainsInsensitive(_In_opt_z_ PCWSTR Haystack, _In_z_ PCWSTR Needle)
{
    if (Haystack == NULL || Needle == NULL || Needle[0] == L'\0')
    {
        return FALSE;
    }

    const SIZE_T needleLen = wcslen(Needle);
    const SIZE_T haystackLen = wcslen(Haystack);
    if (needleLen == 0 || haystackLen < needleLen)
    {
        return FALSE;
    }

    for (SIZE_T i = 0; i <= haystackLen - needleLen; ++i)
    {
        BOOLEAN matched = TRUE;
        for (SIZE_T j = 0; j < needleLen; ++j)
        {
            if (RtlUpcaseUnicodeChar(Haystack[i + j]) != RtlUpcaseUnicodeChar(Needle[j]))
            {
                matched = FALSE;
                break;
            }
        }
        if (matched)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static UCHAR ResolveHookIrpOpcode(_In_ ULONG RequestedIrpOp, _In_ ULONG EventType, _In_opt_z_ PCWSTR FunctionName)
{
    if (RequestedIrpOp != IRP_USERMODE_HOOK_EVENT)
    {
        return (UCHAR)RequestedIrpOp;
    }

    if (EventType >= IRP_KERNEL_REMOTE_THREAD && EventType <= IRP_KERNEL_MAP_SECTION)
    {
        return (UCHAR)EventType;
    }

    if (FunctionName == NULL || FunctionName[0] == L'\0')
    {
        return (UCHAR)RequestedIrpOp;
    }

    if (WideContainsInsensitive(FunctionName, L"WriteVirtualMemory") ||
        WideContainsInsensitive(FunctionName, L"WriteProcessMemory"))
    {
        return (UCHAR)IRP_KERNEL_WRITE_MEMORY;
    }
    if (WideContainsInsensitive(FunctionName, L"ProtectVirtualMemory") ||
        WideContainsInsensitive(FunctionName, L"VirtualProtect"))
    {
        return (UCHAR)IRP_KERNEL_PROTECT_MEMORY;
    }
    if (WideContainsInsensitive(FunctionName, L"CreateRemoteThread") ||
        WideContainsInsensitive(FunctionName, L"CreateThreadEx") ||
        WideContainsInsensitive(FunctionName, L"CreateThread"))
    {
        return (UCHAR)IRP_KERNEL_CREATE_THREAD;
    }
    if (WideContainsInsensitive(FunctionName, L"QueueApcThread") ||
        WideContainsInsensitive(FunctionName, L"QueueUserAPC"))
    {
        return (UCHAR)IRP_KERNEL_QUEUE_APC;
    }
    if (WideContainsInsensitive(FunctionName, L"CreateSection"))
    {
        return (UCHAR)IRP_KERNEL_CREATE_SECTION;
    }
    if (WideContainsInsensitive(FunctionName, L"MapViewOfSection"))
    {
        return (UCHAR)IRP_KERNEL_MAP_SECTION;
    }

    return (UCHAR)RequestedIrpOp;
}

//
// --- Globals for ObRegisterCallbacks ---
//

static PVOID g_ObRegistrationHandle = NULL;
static POB_CALLBACK_REGISTRATION g_ObReg = NULL;
static POB_OPERATION_REGISTRATION g_OpReg = NULL;

#define REMOTE_THREAD_CANDIDATE_SLOTS 64
#define REMOTE_THREAD_CANDIDATE_WINDOW_100NS (1ull * 10ull * 1000ull * 1000ull)

typedef struct _REMOTE_THREAD_CANDIDATE
{
    ULONG SourcePid;
    ULONG TargetPid;
    ULONGLONG LastSeenTime100ns;
} REMOTE_THREAD_CANDIDATE, *PREMOTE_THREAD_CANDIDATE;

static REMOTE_THREAD_CANDIDATE g_RemoteThreadCandidates[REMOTE_THREAD_CANDIDATE_SLOTS] = {0};
static KSPIN_LOCK g_RemoteThreadCandidateLock;
static BOOLEAN g_RemoteThreadCandidateLockInitialized = FALSE;

//
// --- Forward Declarations ---
//

OB_PREOP_CALLBACK_STATUS ProcessHandlePreCallback(_In_ PVOID RegistrationContext,
                                                  _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation);

BOOLEAN IsSystemProcessPP(PEPROCESS Process);
VOID NoteRemoteThreadCandidate(_In_ ULONG SourcePid, _In_ ULONG TargetPid);
BOOLEAN ResolveRemoteThreadCandidate(_In_ ULONG TargetPid, _Out_ PULONG SourcePid);

//
// --- Initialization and Cleanup ---
//

NTSTATUS InitProcessProtection()
{
    NTSTATUS status = STATUS_SUCCESS;

    // Safety: ensure called at PASSIVE_LEVEL
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
#if IS_DEBUG_IRP
        _LOGINFO_RAW("!!! ProcessProtection: InitProcessProtection called at wrong IRQL %u\n", (ULONG)KeGetCurrentIrql());
#endif
        return STATUS_INVALID_LEVEL;
    }

    // Allocate operation registration (only for process handles)
    g_OpReg =
        (POB_OPERATION_REGISTRATION)ExAllocatePoolWithTag(NonPagedPool, sizeof(OB_OPERATION_REGISTRATION), 'ppOr');
    if (!g_OpReg)
    {
#if IS_DEBUG_IRP
        _LOGINFO_RAW("!!! ProcessProtection: Failed to allocate operation registration\n");
#endif
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_OpReg, sizeof(OB_OPERATION_REGISTRATION));

    g_ObReg = (POB_CALLBACK_REGISTRATION)ExAllocatePoolWithTag(NonPagedPool, sizeof(OB_CALLBACK_REGISTRATION), 'ppCr');
    if (!g_ObReg)
    {
        ExFreePoolWithTag(g_OpReg, 'ppOr');
        g_OpReg = NULL;
#if IS_DEBUG_IRP
        _LOGINFO_RAW("!!! ProcessProtection: Failed to allocate callback registration\n");
#endif
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
#if IS_DEBUG_IRP
        _LOGINFO_RAW("!!! ProcessProtection: ObRegisterCallbacks failed: 0x%X\n", status);
#endif
        ExFreePoolWithTag(g_OpReg, 'ppOr');
        ExFreePoolWithTag(g_ObReg, 'ppCr');
        g_OpReg = NULL;
        g_ObReg = NULL;
        return status;
    }

    KeInitializeSpinLock(&g_RemoteThreadCandidateLock);
    RtlZeroMemory(g_RemoteThreadCandidates, sizeof(g_RemoteThreadCandidates));
    g_RemoteThreadCandidateLockInitialized = TRUE;

    EnsureProcessProtectionExcludeRulesLoaded();
    (VOID)InitializeProcessProtectionRules();
#if IS_DEBUG_IRP
    _LOGINFO_RAW("!!! ProcessProtection: ObRegisterCallbacks succeeded\n");
#endif
    return STATUS_SUCCESS;
}

VOID UninitProcessProtection()
{
    // Unregister the object callback
    if (g_ObRegistrationHandle)
    {
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObRegistrationHandle = NULL;
#if IS_DEBUG_IRP
        _LOGINFO_RAW("!!! ProcessProtection: ObUnRegisterCallbacks completed\n");
#endif
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

    if (g_RemoteThreadCandidateLockInitialized)
    {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_RemoteThreadCandidateLock, &oldIrql);
        RtlZeroMemory(g_RemoteThreadCandidates, sizeof(g_RemoteThreadCandidates));
        KeReleaseSpinLock(&g_RemoteThreadCandidateLock, oldIrql);
        g_RemoteThreadCandidateLockInitialized = FALSE;
    }

    EnsureProcessProtectionRuleMutex();
    ExAcquireFastMutex(&g_ProcessProtectionExcludeRules.Mutex);
    FreeProcessProtectionExcludeRulesUnlocked();
    g_ProcessProtectionExcludeRules.Loaded = FALSE;
    ExReleaseFastMutex(&g_ProcessProtectionExcludeRules.Mutex);
    InterlockedExchange(&g_ProcessProtectionExcludeLoadState, 0);

#if IS_DEBUG_IRP
    _LOGINFO_RAW("!!! ProcessProtection: Unloaded\n");
#endif
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

    // OB pre/post operation callbacks can be invoked at IRQL up to
    // DISPATCH_LEVEL. The event pipeline (paged pool allocation, fast mutex)
    // is not safe there, so skip everything above PASSIVE_LEVEL.
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
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

    // 4b. Skip the service process explicitly
    if (driverData != NULL && callerPid == driverData->getPID())
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
        cmd::QueueTerminationAttemptToUserMode(currentProc, targetProc);
    }
    else
    {
        cmd::OnProcessHandleOperation((HANDLE)(ULONG_PTR)callerPid, (HANDLE)(ULONG_PTR)targetPid, desiredAccess,
                                     (UCHAR)pOperationInformation->Operation);
    }

    if ((desiredAccess & PROCESS_CREATE_THREAD) != 0 && callerPid != targetPid)
    {
        NoteRemoteThreadCandidate(callerPid, targetPid);
    }

    // Always allow the operation to proceed - we're just observing
    return OB_PREOP_SUCCESS;
}

VOID NoteRemoteThreadCandidate(_In_ ULONG SourcePid, _In_ ULONG TargetPid)
{
    KIRQL oldIrql;
    ULONGLONG now;
    ULONG replaceIndex = 0;
    ULONGLONG oldestSeen = ~0ull;
    ULONG i;

    if (!g_RemoteThreadCandidateLockInitialized || SourcePid == 0 || TargetPid == 0 || SourcePid == TargetPid)
    {
        return;
    }

    now = KeQueryInterruptTime();

    KeAcquireSpinLock(&g_RemoteThreadCandidateLock, &oldIrql);

    for (i = 0; i < RTL_NUMBER_OF(g_RemoteThreadCandidates); ++i)
    {
        PREMOTE_THREAD_CANDIDATE slot = &g_RemoteThreadCandidates[i];

        if (slot->TargetPid == TargetPid && slot->SourcePid == SourcePid)
        {
            slot->LastSeenTime100ns = now;
            KeReleaseSpinLock(&g_RemoteThreadCandidateLock, oldIrql);
            return;
        }

        if (slot->TargetPid == 0 || (now - slot->LastSeenTime100ns) > REMOTE_THREAD_CANDIDATE_WINDOW_100NS)
        {
            replaceIndex = i;
            oldestSeen = 0;
            break;
        }

        if (slot->LastSeenTime100ns < oldestSeen)
        {
            oldestSeen = slot->LastSeenTime100ns;
            replaceIndex = i;
        }
    }

    g_RemoteThreadCandidates[replaceIndex].SourcePid = SourcePid;
    g_RemoteThreadCandidates[replaceIndex].TargetPid = TargetPid;
    g_RemoteThreadCandidates[replaceIndex].LastSeenTime100ns = now;

    KeReleaseSpinLock(&g_RemoteThreadCandidateLock, oldIrql);
}

BOOLEAN ResolveRemoteThreadCandidate(_In_ ULONG TargetPid, _Out_ PULONG SourcePid)
{
    KIRQL oldIrql;
    ULONGLONG now;
    ULONGLONG newestSeen = 0;
    ULONG resolvedSource = 0;
    ULONG i;

    if (SourcePid == NULL)
    {
        return FALSE;
    }

    *SourcePid = 0;
    if (!g_RemoteThreadCandidateLockInitialized || TargetPid == 0)
    {
        return FALSE;
    }

    now = KeQueryInterruptTime();

    KeAcquireSpinLock(&g_RemoteThreadCandidateLock, &oldIrql);

    for (i = 0; i < RTL_NUMBER_OF(g_RemoteThreadCandidates); ++i)
    {
        PREMOTE_THREAD_CANDIDATE slot = &g_RemoteThreadCandidates[i];

        if (slot->TargetPid == 0)
        {
            continue;
        }

        if ((now - slot->LastSeenTime100ns) > REMOTE_THREAD_CANDIDATE_WINDOW_100NS)
        {
            RtlZeroMemory(slot, sizeof(*slot));
            continue;
        }

        if (slot->TargetPid == TargetPid && slot->LastSeenTime100ns >= newestSeen)
        {
            newestSeen = slot->LastSeenTime100ns;
            resolvedSource = slot->SourcePid;
        }
    }

    KeReleaseSpinLock(&g_RemoteThreadCandidateLock, oldIrql);

    if (resolvedSource == 0 || resolvedSource == TargetPid)
    {
        return FALSE;
    }

    *SourcePid = resolvedSource;
    return TRUE;
}

//
// --- Helper Functions ---
//

static BOOLEAN IsSystemProcessPP(PEPROCESS Process)
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

namespace cmd {

NTSTATUS QueueTerminationAttemptToUserMode(PEPROCESS AttackerProcess, PEPROCESS TargetProcess)
{
    ULONG attackerPid = (ULONG)(ULONG_PTR)PsGetProcessId(AttackerProcess);
    ULONG targetPid   = (ULONG)(ULONG_PTR)PsGetProcessId(TargetProcess);

    if (::ShouldSkipProcessProtectionPair(attackerPid, targetPid, FALSE))
        return STATUS_SUCCESS;

    LOGINFO2("QueueTerminationAttempt LBVS: AttackerPid=%lu -> TargetPid=%lu\r\n", attackerPid, targetPid);

    // Send via LBVS as ProcessOpen with PROCESS_TERMINATE access mask.
    // OpenEDR SysmonEvent::ProcessOpen (0x000D) carries process handle ops;
    // PROCESS_TERMINATE (0x0001) in AccessMask signals the termination intent.
    NonPagedLbvsSerializer<edrdrv::EventField> serializer;
    if (!serializer.write(edrdrv::EventField::RawEventId,
            uint16_t(edrdrv::SysmonEvent::ProcessOpen)))               return STATUS_NO_MEMORY;
    if (!serializer.write(edrdrv::EventField::TickTime,
            (uint64_t)getTickCount64()))                               return STATUS_NO_MEMORY;
    if (!serializer.write(edrdrv::EventField::ProcessPid,
            (uint32_t)attackerPid))                                    return STATUS_NO_MEMORY;
    if (!serializer.write(edrdrv::EventField::TargetProcessPid,
            (uint32_t)targetPid))                                      return STATUS_NO_MEMORY;
    if (!serializer.write(edrdrv::EventField::AccessMask,
            (uint32_t)PROCESS_TERMINATE))                              return STATUS_NO_MEMORY;

    return fltport::sendRawEvent(serializer);
}

//
// --- Process Handle Open: LBVS path (OpenEDR ProcessOpen / SysmonEvent 0x000D) ---
//

NTSTATUS OnProcessHandleOperation(_In_ HANDLE CallerProcessId, _In_ HANDLE TargetProcessId,
                                  _In_ ACCESS_MASK DesiredAccess, _In_ UCHAR OperationType)
{
    UNREFERENCED_PARAMETER(OperationType);

    ULONG callerPid = (ULONG)(ULONG_PTR)CallerProcessId;
    ULONG targetPid = (ULONG)(ULONG_PTR)TargetProcessId;

    if (::ShouldSkipProcessProtectionPair(callerPid, targetPid, FALSE))
        return STATUS_SUCCESS;

    LOGINFO2("OnProcessHandleOperation LBVS: CallerPid=%lu, TargetPid=%lu, Access=0x%X\r\n",
        callerPid, targetPid, DesiredAccess);

    // Send via OpenEDR LBVS fltport — mirrors SysmonEvent::ProcessOpen (0x000D)
    NonPagedLbvsSerializer<edrdrv::EventField> serializer;
    if (!serializer.write(edrdrv::EventField::RawEventId,
            uint16_t(edrdrv::SysmonEvent::ProcessOpen)))               return STATUS_NO_MEMORY;
    if (!serializer.write(edrdrv::EventField::TickTime,
            (uint64_t)getTickCount64()))                               return STATUS_NO_MEMORY;
    if (!serializer.write(edrdrv::EventField::ProcessPid,
            (uint32_t)callerPid))                                      return STATUS_NO_MEMORY;
    if (!serializer.write(edrdrv::EventField::TargetProcessPid,
            (uint32_t)targetPid))                                      return STATUS_NO_MEMORY;
    if (!serializer.write(edrdrv::EventField::AccessMask,
            (uint32_t)DesiredAccess))                                  return STATUS_NO_MEMORY;

    return fltport::sendRawEvent(serializer);
}

//
// --- Kernel API Hook Integration Functions ---
//

NTSTATUS OnKernelApiEvent(_In_ ULONG IrpOp, _In_ ULONG EventType, _In_ ULONG SourcePid, _In_ ULONG TargetPid,
                          _In_opt_ PCWSTR FunctionName, _In_opt_ ULONG_PTR EventArg1, _In_opt_ ULONG_PTR EventArg2,
                          _In_opt_ ULONG_PTR EventArg3, _In_opt_ ULONG_PTR EventArg4)
{
    if (::ShouldSkipProcessProtectionPair(SourcePid, TargetPid, TRUE))
        return STATUS_SUCCESS;

    // Resolve effective name and IRP opcode for this event type
    PCWSTR effectiveName =
        (FunctionName != NULL && FunctionName[0] != L'\0') ? FunctionName : ::KernelEventDefaultLabel(EventType);
    UCHAR effectiveIrpOp = ::ResolveHookIrpOpcode(IrpOp, EventType, effectiveName);
    if ((effectiveName == NULL || effectiveName[0] == L'\0') && effectiveIrpOp != (UCHAR)IrpOp)
        effectiveName = ::KernelEventDefaultLabel(effectiveIrpOp);

    LOGINFO2("OnKernelApiEvent LBVS: EventType=%lu, IrpOp=%u, EffIrpOp=%u, SourcePid=%lu, TargetPid=%lu\r\n",
        EventType, IrpOp, (ULONG)effectiveIrpOp, SourcePid, TargetPid);

    // Serialize via OpenEDR LBVS fltport — this is what Rust usermode reads.
    // SysmonEvent::DeviceIoControl (0x000E) is the carrier event for kernel API hook events.
    //
    // Every write() below is unconditionally logged on failure - this used to
    // fail completely silently (bare `return STATUS_NO_MEMORY`), which made it
    // impossible to tell "event never built" apart from "event built but never
    // sent" apart from "event sent but never received". Definitive diagnostic
    // for the last mile of the pipeline: kernel drain confirmed working, but
    // no owlyHook message ever reaches userland.
    NonPagedLbvsSerializer<edrdrv::EventField> serializer;
    if (!serializer.write(edrdrv::EventField::RawEventId,
            uint16_t(edrdrv::SysmonEvent::DeviceIoControl)))
    {
        DbgPrint("!!! OnKernelApiEvent: serializer.write(RawEventId) FAILED\n");
        return STATUS_NO_MEMORY;
    }
    if (!serializer.write(edrdrv::EventField::TickTime,
            (uint64_t)getTickCount64()))
    {
        DbgPrint("!!! OnKernelApiEvent: serializer.write(TickTime) FAILED\n");
        return STATUS_NO_MEMORY;
    }
    if (!serializer.write(edrdrv::EventField::ProcessPid,
            (uint32_t)SourcePid))
    {
        DbgPrint("!!! OnKernelApiEvent: serializer.write(ProcessPid) FAILED\n");
        return STATUS_NO_MEMORY;
    }
    if (!serializer.write(edrdrv::EventField::OwlyHookEventType,
            (uint32_t)EventType))
    {
        DbgPrint("!!! OnKernelApiEvent: serializer.write(OwlyHookEventType) FAILED\n");
        return STATUS_NO_MEMORY;
    }
    if (!serializer.write(edrdrv::EventField::OwlyHookSourcePid,
            (uint32_t)SourcePid))
    {
        DbgPrint("!!! OnKernelApiEvent: serializer.write(OwlyHookSourcePid) FAILED\n");
        return STATUS_NO_MEMORY;
    }
    if (!serializer.write(edrdrv::EventField::OwlyHookTargetPid,
            (uint32_t)TargetPid))
    {
        DbgPrint("!!! OnKernelApiEvent: serializer.write(OwlyHookTargetPid) FAILED\n");
        return STATUS_NO_MEMORY;
    }
    if (!serializer.write(edrdrv::EventField::OwlyHookArg1,
            (uint64_t)EventArg1))
    {
        DbgPrint("!!! OnKernelApiEvent: serializer.write(OwlyHookArg1) FAILED\n");
        return STATUS_NO_MEMORY;
    }
    if (!serializer.write(edrdrv::EventField::OwlyHookArg2,
            (uint64_t)EventArg2))
    {
        DbgPrint("!!! OnKernelApiEvent: serializer.write(OwlyHookArg2) FAILED\n");
        return STATUS_NO_MEMORY;
    }
    if (!serializer.write(edrdrv::EventField::OwlyHookArg3,
            (uint64_t)EventArg3))
    {
        DbgPrint("!!! OnKernelApiEvent: serializer.write(OwlyHookArg3) FAILED\n");
        return STATUS_NO_MEMORY;
    }
    if (!serializer.write(edrdrv::EventField::OwlyHookArg4,
            (uint64_t)EventArg4))
    {
        DbgPrint("!!! OnKernelApiEvent: serializer.write(OwlyHookArg4) FAILED\n");
        return STATUS_NO_MEMORY;
    }
    if (effectiveName != NULL && effectiveName[0] != L'\0')
    {
        UNICODE_STRING usName;
        RtlInitUnicodeString(&usName, effectiveName);
        if (!cmd::write(serializer, edrdrv::EventField::OwlyHookFunctionName,
                &usName))
        {
            DbgPrint("!!! OnKernelApiEvent: cmd::write(OwlyHookFunctionName) FAILED\n");
            return STATUS_NO_MEMORY;
        }
    }

    NTSTATUS sendStatus = fltport::sendRawEvent(serializer);
    if (!NT_SUCCESS(sendStatus))
    {
        DbgPrint("!!! OnKernelApiEvent: fltport::sendRawEvent FAILED 0x%X (SourcePid=%lu TargetPid=%lu EventType=%lu)\n",
                 sendStatus, SourcePid, TargetPid, EventType);
    }
    return sendStatus;
}

} // namespace cmd
