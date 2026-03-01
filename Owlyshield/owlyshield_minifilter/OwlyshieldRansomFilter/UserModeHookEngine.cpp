/*++

Module Name:

    UserModeHookEngine.cpp

Abstract:

    Implementation of user-mode ntdll.dll hooking engine.
    FIXED: Uses dynamic resolution for PsGetProcessPeb and ZwProtectVirtualMemory.

Environment:

    Kernel mode

--*/

#include "UserModeHookEngine.h"
#include <ntimage.h>
#include <ntstrsafe.h>

// -------------------------------------------------------------------------
// DYNAMIC IMPORT DEFINITIONS
// -------------------------------------------------------------------------

// Function Pointer Types
typedef NTSTATUS(NTAPI *PZW_PROTECT_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                    _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtect,
                                                    _Out_ PULONG OldProtect);

typedef PPEB(NTAPI *PPS_GET_PROCESS_PEB)(_In_ PEPROCESS Process);

typedef NTSTATUS(NTAPI *PZW_ALLOCATE_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                     _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize,
                                                     _In_ ULONG AllocationType, _In_ ULONG Protect);
typedef NTSTATUS(NTAPI *PZW_DUPLICATE_OBJECT)(_In_ HANDLE SourceProcessHandle, _In_ HANDLE SourceHandle,
                                               _In_opt_ HANDLE TargetProcessHandle, _Out_opt_ PHANDLE TargetHandle,
                                               _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes,
                                               _In_ ULONG Options);
typedef NTSTATUS(NTAPI *PZW_FREE_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                 _Inout_ PSIZE_T RegionSize, _In_ ULONG FreeType);
typedef BOOLEAN(NTAPI *PPS_IS_PROTECTED_PROCESS)(_In_ PEPROCESS Process);
typedef BOOLEAN(NTAPI *PPS_IS_PROTECTED_PROCESS_LIGHT)(_In_ PEPROCESS Process);

//
// Global Function Pointers
//
PZW_PROTECT_VIRTUAL_MEMORY fnZwProtectVirtualMemory = NULL;
PZW_ALLOCATE_VIRTUAL_MEMORY fnZwAllocateVirtualMemory = NULL;
PZW_DUPLICATE_OBJECT fnZwDuplicateObject = NULL;
PZW_FREE_VIRTUAL_MEMORY fnZwFreeVirtualMemory = NULL;
PPS_GET_PROCESS_PEB fnPsGetProcessPeb = NULL;
PPS_IS_PROTECTED_PROCESS fnPsIsProtectedProcess = NULL;
PPS_IS_PROTECTED_PROCESS_LIGHT fnPsIsProtectedProcessLight = NULL;

PUSERMODE_HOOK_ENGINE g_UserHookEngine = NULL;
extern PDEVICE_OBJECT g_HookDeviceObject;

// Dynamic Configuration
HOOK_CONFIG_DATA g_GlobalCustomHooks[MAX_CUSTOM_HOOKS];
ULONG g_CustomHookCount = 0;
FAST_MUTEX g_ConfigMutex;

#define HOOK_RULE_POOL_TAG 'rKhO'
#define HOOK_RULE_MAX_FILE_SIZE (64 * 1024)
#define HOOK_RULE_MAX_LINE_CHARS 512

typedef struct _HOOK_EXCLUDE_RULE_SET
{
    PWSTR *Rules;
    ULONG Count;
    ULONG Capacity;
    FAST_MUTEX Mutex;
    BOOLEAN MutexInitialized;
    BOOLEAN Loaded;
} HOOK_EXCLUDE_RULE_SET, *PHOOK_EXCLUDE_RULE_SET;

static HOOK_EXCLUDE_RULE_SET g_HookExcludeRules = {0};

static VOID EnsureHookExcludeRuleMutex(VOID)
{
    //
    // FIX 6: Original code had a race: two threads could both read
    // MutexInitialized==FALSE and both call ExInitializeFastMutex,
    // corrupting the mutex. Use InterlockedCompareExchange to guarantee
    // exactly one initializer wins.
    //
    if (InterlockedCompareExchange((volatile LONG *)&g_HookExcludeRules.MutexInitialized, 0, 0) == FALSE)
    {
        // Speculatively initialize a local copy, then race to publish it.
        FAST_MUTEX tempMutex;
        ExInitializeFastMutex(&tempMutex);

        // Only the first thread to flip MutexInitialized from FALSE to TRUE
        // copies the initialized mutex into the global. Losers harmlessly
        // discard their local copy - the winner's mutex is already valid.
        if (InterlockedCompareExchange((volatile LONG *)&g_HookExcludeRules.MutexInitialized,
                                       TRUE, FALSE) == FALSE)
        {
            RtlCopyMemory(&g_HookExcludeRules.Mutex, &tempMutex, sizeof(FAST_MUTEX));
        }
        // Losers spin-wait until the winner's write is visible.
        while (InterlockedCompareExchange((volatile LONG *)&g_HookExcludeRules.MutexInitialized,
                                          0, 0) == FALSE)
        {
            YieldProcessor();
        }
    }
}

static VOID FreeHookExcludeRulesUnlocked(VOID)
{
    if (g_HookExcludeRules.Rules != NULL)
    {
        for (ULONG i = 0; i < g_HookExcludeRules.Count; ++i)
        {
            PWSTR current = g_HookExcludeRules.Rules[i];
            if (current != NULL)
            {
                ExFreePoolWithTag(current, HOOK_RULE_POOL_TAG);
            }
        }
        ExFreePoolWithTag(g_HookExcludeRules.Rules, HOOK_RULE_POOL_TAG);
    }

    g_HookExcludeRules.Rules = NULL;
    g_HookExcludeRules.Count = 0;
    g_HookExcludeRules.Capacity = 0;
}

static NTSTATUS EnsureHookExcludeRuleCapacityUnlocked(_In_ ULONG RequiredCount)
{
    PWSTR *newArray;
    SIZE_T allocSize;
    ULONG newCapacity;

    if (g_HookExcludeRules.Capacity >= RequiredCount)
    {
        return STATUS_SUCCESS;
    }

    newCapacity = (g_HookExcludeRules.Capacity == 0) ? 8 : g_HookExcludeRules.Capacity * 2;
    if (newCapacity < RequiredCount)
    {
        newCapacity = RequiredCount;
    }

    allocSize = sizeof(PWSTR) * newCapacity;
    newArray = (PWSTR *)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, HOOK_RULE_POOL_TAG);
    if (newArray == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(newArray, allocSize);
    if (g_HookExcludeRules.Rules != NULL && g_HookExcludeRules.Count > 0)
    {
        RtlCopyMemory(newArray, g_HookExcludeRules.Rules, sizeof(PWSTR) * g_HookExcludeRules.Count);
        ExFreePoolWithTag(g_HookExcludeRules.Rules, HOOK_RULE_POOL_TAG);
    }

    g_HookExcludeRules.Rules = newArray;
    g_HookExcludeRules.Capacity = newCapacity;
    return STATUS_SUCCESS;
}

static SIZE_T FindPatternOffset(_In_reads_bytes_(BufferLength) const UCHAR *Buffer,
                                _In_ SIZE_T BufferLength,
                                _In_reads_bytes_(PatternLength) const UCHAR *Pattern,
                                _In_ SIZE_T PatternLength)
{
    if (Buffer == NULL || Pattern == NULL || PatternLength == 0 || BufferLength < PatternLength)
    {
        return (SIZE_T)-1;
    }

    for (SIZE_T i = 0; i <= BufferLength - PatternLength; ++i)
    {
        if (RtlCompareMemory(Buffer + i, Pattern, PatternLength) == PatternLength)
        {
            return i;
        }
    }

    return (SIZE_T)-1;
}

static BOOLEAN NormalizeKernelPathLower(_In_ PCUNICODE_STRING InputPath,
                                        _Out_writes_(MAX_FILE_NAME_LENGTH) PWCHAR OutputBuffer,
                                        _Out_ PUNICODE_STRING NormalizedPath)
{
    return OwlyNormalizePathForMatch(InputPath, OutputBuffer, NormalizedPath);
}

static NTSTATUS AddHookExcludeRuleNormalizedUnlocked(_In_reads_(RuleChars) PCWSTR RuleText, _In_ SIZE_T RuleChars)
{
    WCHAR normalizedLine[HOOK_RULE_MAX_LINE_CHARS];
    SIZE_T lineLen = 0;
    SIZE_T start = 0;
    SIZE_T end = RuleChars;
    SIZE_T commentPos = (SIZE_T)-1;
    NTSTATUS status;

    if (RuleText == NULL || RuleChars == 0)
    {
        return STATUS_SUCCESS;
    }

    while (start < end && (RuleText[start] == L' ' || RuleText[start] == L'\t'))
    {
        start++;
    }

    for (SIZE_T i = start; i < end; ++i)
    {
        if (RuleText[i] == L'#')
        {
            commentPos = i;
            break;
        }
        if ((i + 1) < end && RuleText[i] == L'/' && RuleText[i + 1] == L'/')
        {
            commentPos = i;
            break;
        }
    }
    if (commentPos != (SIZE_T)-1)
    {
        end = commentPos;
    }

    while (end > start &&
           (RuleText[end - 1] == L' ' || RuleText[end - 1] == L'\t' || RuleText[end - 1] == L'\r' || RuleText[end - 1] == L'"'))
    {
        end--;
    }
    if (end <= start)
    {
        return STATUS_SUCCESS;
    }

    for (SIZE_T i = start; i < end && lineLen + 1 < RTL_NUMBER_OF(normalizedLine); ++i)
    {
        WCHAR ch = RuleText[i];
        if (ch == L'/')
        {
            ch = L'\\';
        }
        normalizedLine[lineLen++] = RtlDowncaseUnicodeChar(ch);
    }
    normalizedLine[lineLen] = L'\0';

    if (lineLen >= 4 &&
        normalizedLine[0] == L'\\' &&
        normalizedLine[1] == L'?' &&
        normalizedLine[2] == L'?' &&
        normalizedLine[3] == L'\\')
    {
        RtlMoveMemory(normalizedLine, normalizedLine + 4, (lineLen - 4 + 1) * sizeof(WCHAR));
        lineLen -= 4;
    }
    if (lineLen >= 4 &&
        normalizedLine[0] == L'\\' &&
        normalizedLine[1] == L'\\' &&
        normalizedLine[2] == L'?' &&
        normalizedLine[3] == L'\\')
    {
        RtlMoveMemory(normalizedLine, normalizedLine + 4, (lineLen - 4 + 1) * sizeof(WCHAR));
        lineLen -= 4;
    }

    if (lineLen == 0 || normalizedLine[0] == L'#')
    {
        return STATUS_SUCCESS;
    }
    if (lineLen >= 2 && normalizedLine[0] == L'/' && normalizedLine[1] == L'/')
    {
        return STATUS_SUCCESS;
    }

    for (ULONG i = 0; i < g_HookExcludeRules.Count; ++i)
    {
        if (_wcsicmp(g_HookExcludeRules.Rules[i], normalizedLine) == 0)
        {
            return STATUS_SUCCESS;
        }
    }

    status = EnsureHookExcludeRuleCapacityUnlocked(g_HookExcludeRules.Count + 1);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    {
        SIZE_T allocSize = (lineLen + 1) * sizeof(WCHAR);
        PWSTR newRule = (PWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, HOOK_RULE_POOL_TAG);
        if (newRule == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(newRule, allocSize);
        RtlCopyMemory(newRule, normalizedLine, lineLen * sizeof(WCHAR));
        newRule[lineLen] = L'\0';
        g_HookExcludeRules.Rules[g_HookExcludeRules.Count++] = newRule;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS AppendHookExcludeRulesFromBufferUnlocked(_In_reads_bytes_(BytesRead) PUCHAR Buffer, _In_ ULONG BytesRead)
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
                    (VOID)AddHookExcludeRuleNormalizedUnlocked(&utf16Buffer[start], i - start);
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
                    WCHAR lineBuffer[HOOK_RULE_MAX_LINE_CHARS];
                    SIZE_T lineLen = 0;
                    for (ULONG j = start; j < i && lineLen + 1 < RTL_NUMBER_OF(lineBuffer); ++j)
                    {
                        lineBuffer[lineLen++] = (WCHAR)Buffer[j];
                    }
                    lineBuffer[lineLen] = L'\0';
                    (VOID)AddHookExcludeRuleNormalizedUnlocked(lineBuffer, lineLen);
                }
                start = i + 1;
            }
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS LoadHookExcludeRulesFromFileUnlocked(_In_ PCUNICODE_STRING FilePath)
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

    if (fileInfo.EndOfFile.QuadPart <= 0 || fileInfo.EndOfFile.QuadPart > HOOK_RULE_MAX_FILE_SIZE)
    {
        ZwClose(fileHandle);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    bufferSize = (ULONG)fileInfo.EndOfFile.QuadPart;
    buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, HOOK_RULE_POOL_TAG);
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
        (VOID)AppendHookExcludeRulesFromBufferUnlocked(buffer, (ULONG)ioStatus.Information);
    }

    ExFreePoolWithTag(buffer, HOOK_RULE_POOL_TAG);
    ZwClose(fileHandle);
    return status;
}

static VOID EnsureHookExcludeRulesLoaded(VOID)
{
    static const PCWSTR ruleFiles[] = {
        OWLY_DYNAMIC_HOOK_RULE_FILE_KERNEL
    };

    //
    // FIX: FAST_MUTEX raises IRQL to APC_LEVEL which disables kernel APCs.
    // ZwCreateFile with FILE_SYNCHRONOUS_IO_NONALERT needs a kernel APC to signal
    // I/O completion. Holding the mutex during the file read was a guaranteed
    // deadlock. Do ALL file I/O before acquiring the mutex.
    //
    EnsureHookExcludeRuleMutex();

    // Fast path check (brief mutex hold, no I/O)
    ExAcquireFastMutex(&g_HookExcludeRules.Mutex);
    BOOLEAN alreadyLoaded = g_HookExcludeRules.Loaded;
    ExReleaseFastMutex(&g_HookExcludeRules.Mutex);

    if (alreadyLoaded)
        return;

    // Reset rule storage under the mutex (no I/O, safe at APC_LEVEL)
    ExAcquireFastMutex(&g_HookExcludeRules.Mutex);
    FreeHookExcludeRulesUnlocked();
    ExReleaseFastMutex(&g_HookExcludeRules.Mutex);

    // File I/O happens here with NO mutex held (PASSIVE_LEVEL, APCs enabled)
    for (ULONG i = 0; i < RTL_NUMBER_OF(ruleFiles); ++i)
    {
        UNICODE_STRING ruleFile;
        RtlInitUnicodeString(&ruleFile, ruleFiles[i]);
        (VOID)LoadHookExcludeRulesFromFileUnlocked(&ruleFile);
    }

    // Mark loaded under the mutex (no I/O, safe at APC_LEVEL)
    ExAcquireFastMutex(&g_HookExcludeRules.Mutex);
    g_HookExcludeRules.Loaded = TRUE;
    ExReleaseFastMutex(&g_HookExcludeRules.Mutex);
}

static BOOLEAN IsNormalizedPathExcludedByHookRules(_In_ PCUNICODE_STRING NormalizedPath)
{
    BOOLEAN matched = FALSE;

    if (NormalizedPath == NULL ||
        NormalizedPath->Buffer == NULL ||
        NormalizedPath->Length < 3 * sizeof(WCHAR))
    {
        return FALSE;
    }

    // Strictly enforce C:\ for user-defined exclusions.
    if (!(NormalizedPath->Buffer[0] == L'c' &&
          NormalizedPath->Buffer[1] == L':' &&
          NormalizedPath->Buffer[2] == L'\\'))
    {
        return FALSE;
    }

    EnsureHookExcludeRulesLoaded();
    EnsureHookExcludeRuleMutex();
    ExAcquireFastMutex(&g_HookExcludeRules.Mutex);
    for (ULONG i = 0; i < g_HookExcludeRules.Count; ++i)
    {
        PCWSTR rule = g_HookExcludeRules.Rules[i];
        if (rule != NULL && rule[0] != L'\0' && wcsstr(NormalizedPath->Buffer, rule) != NULL)
        {
            matched = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_HookExcludeRules.Mutex);

    return matched;
}

static BOOLEAN IsSensitiveSystemPathForHookingProcess(_In_ PEPROCESS Process)
{
    PUNICODE_STRING processImagePath = NULL;
    UNICODE_STRING normalizedPath;
    WCHAR normalizedPathBuffer[MAX_FILE_NAME_LENGTH] = {0};
    NTSTATUS status;

    if (Process == NULL)
    {
        return FALSE;
    }

    status = SeLocateProcessImageName(Process, &processImagePath);
    if (!NT_SUCCESS(status) ||
        processImagePath == NULL ||
        processImagePath->Buffer == NULL ||
        processImagePath->Length == 0)
    {
        if (processImagePath != NULL)
        {
            ExFreePool(processImagePath);
        }
        return FALSE;
    }

    if (!NormalizeKernelPathLower(processImagePath, normalizedPathBuffer, &normalizedPath))
    {
        ExFreePool(processImagePath);
        return FALSE;
    }

    // No hardcoded process-path allow/deny list: rules-only.
    BOOLEAN isSensitive = IsNormalizedPathExcludedByHookRules(&normalizedPath);
    ExFreePool(processImagePath);
    return isSensitive;
}

static BOOLEAN ShouldSkipHookingProcess(_In_ PEPROCESS Process, _In_ ULONG ProcessId)
{
    if (Process == NULL)
    {
        return TRUE;
    }

    if (ProcessId <= 4)
    {
        return TRUE;
    }

    if (fnPsIsProtectedProcess != NULL && fnPsIsProtectedProcess(Process))
    {
        return TRUE;
    }

    if (fnPsIsProtectedProcessLight != NULL && fnPsIsProtectedProcessLight(Process))
    {
        return TRUE;
    }

    if (IsSensitiveSystemPathForHookingProcess(Process))
    {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN IsSameHookConfig(_In_ const HOOK_CONFIG_DATA* A, _In_ const HOOK_CONFIG_DATA* B)
{
    ANSI_STRING aFunc;
    ANSI_STRING bFunc;

    if (A == NULL || B == NULL)
    {
        return FALSE;
    }

    RtlInitAnsiString(&aFunc, A->FunctionName);
    RtlInitAnsiString(&bFunc, B->FunctionName);

    return (_wcsicmp(A->ModuleName, B->ModuleName) == 0) &&
           RtlEqualString(&aFunc, &bFunc, TRUE);
}

NTSTATUS AddCustomHook(_In_ PHOOK_CONFIG_DATA Config)
{
    if (Config == NULL || Config->ModuleName[0] == L'\0' || Config->FunctionName[0] == '\0')
    {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&g_ConfigMutex);

    for (ULONG i = 0; i < g_CustomHookCount; ++i)
    {
        if (IsSameHookConfig(&g_GlobalCustomHooks[i], Config))
        {
            if (Config->EventId != 0)
            {
                g_GlobalCustomHooks[i].EventId = Config->EventId;
            }
            ExReleaseFastMutex(&g_ConfigMutex);
            return STATUS_SUCCESS;
        }
    }

    if (g_CustomHookCount >= MAX_CUSTOM_HOOKS) {
        ExReleaseFastMutex(&g_ConfigMutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlCopyMemory(&g_GlobalCustomHooks[g_CustomHookCount], Config, sizeof(HOOK_CONFIG_DATA));
    g_GlobalCustomHooks[g_CustomHookCount].ModuleName[RTL_NUMBER_OF(g_GlobalCustomHooks[g_CustomHookCount].ModuleName) - 1] = L'\0';
    g_GlobalCustomHooks[g_CustomHookCount].FunctionName[RTL_NUMBER_OF(g_GlobalCustomHooks[g_CustomHookCount].FunctionName) - 1] = '\0';
    if (g_GlobalCustomHooks[g_CustomHookCount].EventId == 0)
    {
        g_GlobalCustomHooks[g_CustomHookCount].EventId = 0x6000u;
    }
    g_CustomHookCount++;
    
    ExReleaseFastMutex(&g_ConfigMutex);
    return STATUS_SUCCESS;
}

BOOLEAN ResolveHookNameByEventId(_In_ ULONG EventId, _Out_writes_(MAX_FILE_NAME_LENGTH) PWCHAR OutName, _In_ ULONG OutNameCch)
{
    BOOLEAN found = FALSE;

    if (OutName == NULL || OutNameCch == 0)
    {
        return FALSE;
    }

    OutName[0] = L'\0';

    ExAcquireFastMutex(&g_ConfigMutex);
    for (ULONG i = 0; i < g_CustomHookCount; ++i)
    {
        if (g_GlobalCustomHooks[i].EventId != EventId)
        {
            continue;
        }

        WCHAR functionNameW[256] = {0};
        ANSI_STRING functionNameA;
        UNICODE_STRING functionNameU;
        NTSTATUS status;

        RtlInitAnsiString(&functionNameA, g_GlobalCustomHooks[i].FunctionName);
        functionNameU.Buffer = functionNameW;
        functionNameU.Length = 0;
        functionNameU.MaximumLength = sizeof(functionNameW);
        status = RtlAnsiStringToUnicodeString(&functionNameU, &functionNameA, FALSE);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        functionNameW[RTL_NUMBER_OF(functionNameW) - 1] = L'\0';

        if (g_GlobalCustomHooks[i].ModuleName[0] != L'\0' && _wcsicmp(g_GlobalCustomHooks[i].ModuleName, L"*") != 0)
        {
            (VOID)RtlStringCchPrintfW(OutName,
                                      OutNameCch,
                                      L"%ws!%ws",
                                      g_GlobalCustomHooks[i].ModuleName,
                                      functionNameW);
        }
        else
        {
            (VOID)RtlStringCchCopyW(OutName, OutNameCch, functionNameW);
        }

        found = TRUE;
        break;
    }
    ExReleaseFastMutex(&g_ConfigMutex);

    return found;
}

// -------------------------------------------------------------------------
// FIX #4a: Define the IOCTL code used by the injected shellcode.
// HOOK_NOTIFY_IOCTL_CODE must match the driver-side CTL_CODE definition.
// -------------------------------------------------------------------------
#ifndef HOOK_NOTIFY_IOCTL_CODE
#define HOOK_NOTIFY_IOCTL_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

// -------------------------------------------------------------------------
// FIX #4b: ContainsUnrelocatableInstructions
//
// Scans the first StolenSize bytes of a function's prologue for any
// RIP-relative instruction that CANNOT be trivially relocated.  If found,
// the hook is skipped rather than copying broken bytes into the shellcode.
//
// Handles the most common x64 patterns:
//   • REX prefix (optional) + opcode + ModRM(00_xxx_101) + disp32
//   • FF /2 CALL [RIP+d32] and FF /4 JMP [RIP+d32]
//   • EB/E9/E8 short/near relative branches (always skip – branch target
//     would also be wrong from the new VA)
//
// Returns TRUE if at least one unrelocatable instruction was found.
// -------------------------------------------------------------------------
static BOOLEAN ContainsUnrelocatableInstructions(
    _In_reads_bytes_(StolenSize) const UCHAR *Bytes,
    _In_ SIZE_T StolenSize)
{
    SIZE_T i = 0;

    while (i < StolenSize)
    {
        UCHAR b = Bytes[i];
        BOOLEAN hasRex = FALSE;

        // Consume REX prefix (40..4F)
        if ((b & 0xF0) == 0x40)
        {
            hasRex = TRUE;
            ++i;
            if (i >= StolenSize)
                break;
            b = Bytes[i];
        }

        // Short/near relative branches – target changes at new VA.
        if (b == 0xEB || b == 0xE9 || b == 0xE8)
            return TRUE;

        // Two-byte opcode escape (0F xx)
        if (b == 0x0F)
        {
            ++i;
            if (i >= StolenSize)
                break;
            b = Bytes[i];
            // 0F 1F etc. – check ModRM
            if (i + 1 < StolenSize)
            {
                UCHAR modrm = Bytes[i + 1];
                if ((modrm & 0xC7) == 0x05)   // mod=00, rm=101 = RIP-relative
                    return TRUE;
            }
            // Consume this byte and keep going (simplified)
            i += 2;
            continue;
        }

        // One-byte opcodes that may carry a RIP-relative ModRM:
        // 8x, 0x–3x (ALU), C7, FF, etc.
        static const UCHAR kModrmOpcodes[] = {
            0x01, 0x03, 0x09, 0x0B, 0x11, 0x13,    // ADD/OR/ADC/SBB
            0x21, 0x23, 0x29, 0x2B, 0x31, 0x33,    // AND/SUB/XOR
            0x39, 0x3B,                              // CMP
            0x85, 0x87, 0x89, 0x8B, 0x8D,           // TEST/XCHG/MOV/LEA
            0xC7,                                    // MOV r/m, imm
            0xFF,                                    // INC/DEC/CALL/JMP/PUSH
        };
        BOOLEAN hasModrm = FALSE;
        for (SIZE_T k = 0; k < RTL_NUMBER_OF(kModrmOpcodes); ++k)
        {
            if (b == kModrmOpcodes[k])
            {
                hasModrm = TRUE;
                break;
            }
        }

        if (hasModrm && i + 1 < StolenSize)
        {
            UCHAR modrm = Bytes[i + 1];
            if ((modrm & 0xC7) == 0x05)   // mod=00, rm=101 = RIP-relative
                return TRUE;

            // Estimate instruction length to advance i correctly
            // (simplified – good enough for 14-byte prologues)
            UCHAR mod = (modrm >> 6) & 0x03;
            UCHAR rm  = modrm & 0x07;
            SIZE_T instrLen = 2;   // opcode + ModRM
            if (mod == 0x01) instrLen += 1;        // +disp8
            else if (mod == 0x02) instrLen += 4;   // +disp32
            else if (mod == 0x00 && rm == 0x04)    // SIB byte follows
                instrLen += 1;
            // special case: C7 also carries an imm32
            if (b == 0xC7 && mod == 0x03) instrLen += 4;
            else if (b == 0xC7) instrLen += 4;

            i += instrLen;
            continue;
        }

        // Default: advance one byte (handles short instructions like PUSH/POP/NOP/RET)
        ++i;
    }

    return FALSE;
}

// -------------------------------------------------------------------------
//
// Previous version only set 2 of the 10 required arguments for
// NtDeviceIoControlFile, leaving the rest as garbage — causing an access
// violation inside the kernel on almost every hooked call.
//
// STACK LAYOUT (RSP = RSP_entry - 304 after pushes + sub):
//   RSP+0x00..0x1F  shadow space for the call
//   RSP+0x20        arg5:  &IO_STATUS_BLOCK  (points to RSP+0x80)
//   RSP+0x28        arg6:  IoControlCode     (patched: HOOK_NOTIFY_IOCTL_CODE)
//   RSP+0x30        arg7:  InputBuffer       (points to RSP+0x90 = HOOK_EVENT_DATA)
//   RSP+0x38        arg8:  InputBufferLength (patched: sizeof HOOK_EVENT_DATA)
//   RSP+0x40        arg9:  OutputBuffer      NULL
//   RSP+0x48        arg10: OutputBufferLength 0
//   RSP+0x80..0x8F  IO_STATUS_BLOCK (16 bytes, zeroed)
//   RSP+0x90+0x00   HOOK_EVENT_DATA.EventType    (patched: EventId)
//   RSP+0x90+0x04   HOOK_EVENT_DATA.ProcessId    (patched: ProcessId)
//   RSP+0x90+0x48   HOOK_EVENT_DATA.Arg1         (copied from original RCX)
//   RSP+0x90+0x50   HOOK_EVENT_DATA.Arg2         (copied from original RDX)
//   RSP+0xF0        saved R11 ... RAX (8 * 8 = 64 bytes)
//
// Register sources (from the saved register block above RSP+0xF0):
//   saved RCX (original arg1 of hooked fn) lives at RSP + 0xF8
//   saved RDX (original arg2 of hooked fn) lives at RSP + 0x100
// -------------------------------------------------------------------------
UCHAR g_ShellcodeTemplate[] = {
    // ---- Save volatile registers ----------------------------------------
    0x50,                                           // push rax
    0x51,                                           // push rcx
    0x52,                                           // push rdx
    0x53,                                           // push rbx
    0x41, 0x50,                                     // push r8
    0x41, 0x51,                                     // push r9
    0x41, 0x52,                                     // push r10
    0x41, 0x53,                                     // push r11
    // ---- Allocate 0xF8 bytes of local space --------------------------------
    // RSP at shellcode entry: RSP%16 == 8 (entered via JMP after hooked CALL).
    // After 8 pushes (64 bytes): RSP%16 still == 8.
    // We need RSP%16 == 0 at the CALL instruction (x64 ABI).
    // Required: N%16 == 8  →  0xF8 (248) is correct. 0xF0 (240) was WRONG.
    0x48, 0x81, 0xEC, 0xF8, 0x00, 0x00, 0x00,      // sub rsp, 0xF8

    // ---- Zero IO_STATUS_BLOCK at RSP+0x80 ----------------------------------
    0x48, 0x31, 0xC0,                               // xor rax, rax
    0x48, 0x89, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00,// mov [rsp+0x80], rax
    0x48, 0x89, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00,// mov [rsp+0x88], rax

    // ---- Fill HOOK_EVENT_DATA (starts at RSP+0x90) -------------------------
    // EventType at RSP+0x90  — patched with EventId (ULONG)
    0xC7, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, 0x11, 0x11, 0x11, 0x11,
    // ProcessId at RSP+0x94 — patched with ProcessId (ULONG)
    0xC7, 0x84, 0x24, 0x94, 0x00, 0x00, 0x00, 0x22, 0x22, 0x22, 0x22,

    // ---- Copy original RCX (arg1) → HOOK_EVENT_DATA.Arg1 at RSP+0xD8 ------
    // Push order: rax,rcx,rdx,rbx,r8,r9,r10,r11.  After sub rsp,0xF8:
    //   r11=[RSP+0xF8], r10=[RSP+0x100], r9=[RSP+0x108], r8=[RSP+0x110]
    //   rbx=[RSP+0x118], rdx=[RSP+0x120], rcx=[RSP+0x128], rax=[RSP+0x130]
    0x48, 0x8B, 0x84, 0x24, 0x28, 0x01, 0x00, 0x00,// mov rax, [rsp+0x128]  ← saved RCX
    0x48, 0x89, 0x84, 0x24, 0xD8, 0x00, 0x00, 0x00,// mov [rsp+0xD8], rax   → Arg1

    // ---- Copy original RDX (arg2) → HOOK_EVENT_DATA.Arg2 at RSP+0xE0 ------
    0x48, 0x8B, 0x84, 0x24, 0x20, 0x01, 0x00, 0x00,// mov rax, [rsp+0x120]  ← saved RDX
    0x48, 0x89, 0x84, 0x24, 0xE0, 0x00, 0x00, 0x00,// mov [rsp+0xE0], rax   → Arg2

    // ---- Build NtDeviceIoControlFile argument frame ------------------------
    // RCX = FileHandle (arg1) — patched
    0x48, 0xB9, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    // RDX = Event (arg2) = NULL
    0x31, 0xD2,                                     // xor edx, edx
    // R8  = ApcRoutine (arg3) = NULL
    0x45, 0x31, 0xC0,                               // xor r8d, r8d
    // R9  = ApcContext (arg4) = NULL
    0x45, 0x31, 0xC9,                               // xor r9d, r9d
    // arg5: [rsp+0x20] = &IO_STATUS_BLOCK = lea rax,[rsp+0x80]; store
    0x48, 0x8D, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00,// lea rax, [rsp+0x80]
    0x48, 0x89, 0x44, 0x24, 0x20,                   // mov [rsp+0x20], rax
    // arg6: [rsp+0x28] = IoControlCode — patched (0x6666... placeholder)
    0x48, 0xB8, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x48, 0x89, 0x44, 0x24, 0x28,                   // mov [rsp+0x28], rax
    // arg7: [rsp+0x30] = InputBuffer = &HOOK_EVENT_DATA at RSP+0x90
    0x48, 0x8D, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00,// lea rax, [rsp+0x90]
    0x48, 0x89, 0x44, 0x24, 0x30,                   // mov [rsp+0x30], rax
    // arg8: [rsp+0x38] = InputBufferLength — patched (0x7777... placeholder)
    0x48, 0xB8, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
    0x48, 0x89, 0x44, 0x24, 0x38,                   // mov [rsp+0x38], rax
    // arg9 + arg10: [rsp+0x40] = NULL, [rsp+0x48] = 0
    0x48, 0x31, 0xC0,                               // xor rax, rax
    0x48, 0x89, 0x44, 0x24, 0x40,                   // mov [rsp+0x40], rax
    0x48, 0x89, 0x44, 0x24, 0x48,                   // mov [rsp+0x48], rax

    // ---- Call NtDeviceIoControlFile ----------------------------------------
    // Address patched (0x4444... placeholder)
    0x48, 0xB8, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
    0xFF, 0xD0,                                     // call rax

    // ---- Restore local space and registers ---------------------------------
    0x48, 0x81, 0xC4, 0xF8, 0x00, 0x00, 0x00,      // add rsp, 0xF8
    0x41, 0x5B,                                     // pop r11
    0x41, 0x5A,                                     // pop r10
    0x41, 0x59,                                     // pop r9
    0x41, 0x58,                                     // pop r8
    0x5B,                                           // pop rbx
    0x5A,                                           // pop rdx
    0x59,                                           // pop rcx
    0x58,                                           // pop rax

    // ---- 14-byte stolen-instructions placeholder ---------------------------
    // Patched at runtime with the original bytes from the hooked function.
    // ContainsUnrelocatableInstructions() guarantees these are safe to run
    // at this new virtual address before we ever reach this point.
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

    // ---- Return jump -------------------------------------------------------
    // Target patched to (original function base + USERMODE_HOOK_SIZE)
    0x48, 0xB8, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, // mov rax, <ret>
    0xFF, 0xE0,                                     // jmp rax

    // ---- Padding -----------------------------------------------------------
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90
};


//
// Initialize the user-mode hooking engine
//

NTSTATUS UserModeHookEngineInitialize(VOID)
{
    DbgPrint("!!! UserModeHook: Initializing user-mode hooking engine...\n");

    // ---------------------------------------------------------------------
    // FIX: Resolve system routines dynamically to avoid Linker Errors
    // ---------------------------------------------------------------------
    UNICODE_STRING routineName;

    // Resolve ZwProtectVirtualMemory
    RtlInitUnicodeString(&routineName, L"ZwProtectVirtualMemory");
    fnZwProtectVirtualMemory = (PZW_PROTECT_VIRTUAL_MEMORY)MmGetSystemRoutineAddress(&routineName);

    if (!fnZwProtectVirtualMemory)
    {
        DbgPrint("!!! UserModeHook: Failed to resolve ZwProtectVirtualMemory\n");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // Resolve PsGetProcessPeb
    RtlInitUnicodeString(&routineName, L"PsGetProcessPeb");
    fnPsGetProcessPeb = (PPS_GET_PROCESS_PEB)MmGetSystemRoutineAddress(&routineName);

    if (!fnPsGetProcessPeb)
    {
        DbgPrint("!!! UserModeHook: Failed to resolve PsGetProcessPeb\n");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // Resolve ZwAllocateVirtualMemory
    RtlInitUnicodeString(&routineName, L"ZwAllocateVirtualMemory");
    fnZwAllocateVirtualMemory = (PZW_ALLOCATE_VIRTUAL_MEMORY)MmGetSystemRoutineAddress(&routineName);
    if (!fnZwAllocateVirtualMemory) {
        DbgPrint("!!! UserModeHook: Failed to resolve ZwAllocateVirtualMemory\n");
    }

    // Resolve ZwDuplicateObject
    RtlInitUnicodeString(&routineName, L"ZwDuplicateObject");
    fnZwDuplicateObject = (PZW_DUPLICATE_OBJECT)MmGetSystemRoutineAddress(&routineName);
    
    // Resolve ZwFreeVirtualMemory
    RtlInitUnicodeString(&routineName, L"ZwFreeVirtualMemory");
    fnZwFreeVirtualMemory = (PZW_FREE_VIRTUAL_MEMORY)MmGetSystemRoutineAddress(&routineName);
    // FIX 2a: original code checked !fnZwDuplicateObject here instead of !fnZwFreeVirtualMemory.
    if (!fnZwFreeVirtualMemory) {
         DbgPrint("!!! UserModeHook: Failed to resolve ZwFreeVirtualMemory\n");
    }
    if (!fnZwDuplicateObject) {
         DbgPrint("!!! UserModeHook: Failed to resolve ZwDuplicateObject\n");
    }

    // Resolve optional process protection helpers (best-effort).
    RtlInitUnicodeString(&routineName, L"PsIsProtectedProcess");
    fnPsIsProtectedProcess = (PPS_IS_PROTECTED_PROCESS)MmGetSystemRoutineAddress(&routineName);
    RtlInitUnicodeString(&routineName, L"PsIsProtectedProcessLight");
    fnPsIsProtectedProcessLight = (PPS_IS_PROTECTED_PROCESS_LIGHT)MmGetSystemRoutineAddress(&routineName);

    // ---------------------------------------------------------------------
    // Allocate Engine
    // ---------------------------------------------------------------------

    g_UserHookEngine =
        (PUSERMODE_HOOK_ENGINE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(USERMODE_HOOK_ENGINE), 'UMHk');

    if (g_UserHookEngine == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_UserHookEngine, sizeof(USERMODE_HOOK_ENGINE));
    ExInitializeFastMutex(&g_UserHookEngine->EngineMutex);
    ExInitializeFastMutex(&g_ConfigMutex);
    g_CustomHookCount = 0;
    RtlZeroMemory(g_GlobalCustomHooks, sizeof(g_GlobalCustomHooks));
    g_UserHookEngine->IsInitialized = TRUE;

    return STATUS_SUCCESS;
}

//
// Cleanup
//

VOID UserModeHookEngineCleanup(VOID)
{
    ULONG hookedPids[MAX_HOOKED_PROCESSES];
    ULONG hookedPidCount = 0;

    if (g_UserHookEngine == NULL || !g_UserHookEngine->IsInitialized)
        return;

    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);

    for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++)
    {
        if (g_UserHookEngine->Processes[i].IsHooked &&
            g_UserHookEngine->Processes[i].ProcessId != 0 &&
            hookedPidCount < MAX_HOOKED_PROCESSES)
        {
            hookedPids[hookedPidCount++] = g_UserHookEngine->Processes[i].ProcessId;
        }
    }

    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);

    for (ULONG i = 0; i < hookedPidCount; ++i)
    {
        (VOID)UserModeUnhookProcess(hookedPids[i]);
    }

    ExAcquireFastMutex(&g_ConfigMutex);
    g_CustomHookCount = 0;
    RtlZeroMemory(g_GlobalCustomHooks, sizeof(g_GlobalCustomHooks));
    ExReleaseFastMutex(&g_ConfigMutex);

    EnsureHookExcludeRuleMutex();
    ExAcquireFastMutex(&g_HookExcludeRules.Mutex);
    FreeHookExcludeRulesUnlocked();
    g_HookExcludeRules.Loaded = FALSE;
    ExReleaseFastMutex(&g_HookExcludeRules.Mutex);

    ExFreePoolWithTag(g_UserHookEngine, 'UMHk');
    g_UserHookEngine = NULL;
}

//
// Find module base address
//

PVOID FindModuleBaseAddress(_In_ PEPROCESS Process, _In_ PCWSTR ModuleName, _Out_opt_ PSIZE_T ModuleSize)
{
    PVOID moduleBase = NULL;

    if (ModuleSize != NULL)
        *ModuleSize = 0;

    __try
    {
        // Guard against failed dynamic resolve at init time.
        if (fnPsGetProcessPeb == NULL)
            return NULL;

        // FIX: Use the function pointer
        PPEB peb = fnPsGetProcessPeb(Process);

        if (peb)
        {
            ProbeForRead(peb, sizeof(PEB), 1);
            PPEB_LDR_DATA ldr = (PPEB_LDR_DATA)peb->Ldr;
            if (ldr)
            {
                ProbeForRead(ldr, sizeof(PEB_LDR_DATA), 1);
                PLIST_ENTRY listHead = &ldr->InLoadOrderModuleList;
                PLIST_ENTRY listEntry = listHead->Flink;

                while (listEntry != listHead)
                {
                    PLDR_DATA_TABLE_ENTRY ldrEntry =
                        CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                    ProbeForRead(ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), 1);

                    if (ldrEntry->BaseDllName.Buffer && ldrEntry->BaseDllName.Length > 0)
                    {
                        ProbeForRead(ldrEntry->BaseDllName.Buffer, ldrEntry->BaseDllName.Length, 1);
                        if (_wcsicmp(ldrEntry->BaseDllName.Buffer, ModuleName) == 0)
                        {
                            moduleBase = ldrEntry->DllBase;
                            if (ModuleSize)
                                *ModuleSize = ldrEntry->SizeOfImage;
                            break;
                        }
                    }
                    listEntry = listEntry->Flink;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        moduleBase = NULL;
    }

    return moduleBase;
}

//
// Find exported function
//

PVOID FindExportedFunction(_In_ PVOID ModuleBase, _In_ PCSTR FunctionName)
{
    PVOID functionAddress = NULL;
    __try
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
        ProbeForRead(dosHeader, sizeof(IMAGE_DOS_HEADER), 1);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return NULL;

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleBase + dosHeader->e_lfanew);
        ProbeForRead(ntHeaders, sizeof(IMAGE_NT_HEADERS), 1);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            return NULL;

        PIMAGE_EXPORT_DIRECTORY exportDir =
            (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase +
                                      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                          .VirtualAddress);
        ProbeForRead(exportDir, sizeof(IMAGE_EXPORT_DIRECTORY), 1);

        PULONG addressOfFunctions = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfFunctions);
        PULONG addressOfNames = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfNames);
        PUSHORT addressOfNameOrdinals = (PUSHORT)((PUCHAR)ModuleBase + exportDir->AddressOfNameOrdinals);

        for (ULONG i = 0; i < exportDir->NumberOfNames; i++)
        {
            PCSTR currentName = (PCSTR)((PUCHAR)ModuleBase + addressOfNames[i]);
            ProbeForRead((PVOID)currentName, strlen(FunctionName) + 1, 1);

            if (strcmp(currentName, FunctionName) == 0)
            {
                USHORT ordinal = addressOfNameOrdinals[i];
                ULONG rva = addressOfFunctions[ordinal];
                functionAddress = (PVOID)((PUCHAR)ModuleBase + rva);
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        functionAddress = NULL;
    }
    return functionAddress;
}

//
// Install a hook in user-mode memory
//

NTSTATUS InstallUsermodeHook(_In_ PEPROCESS Process, _In_ PVOID TargetAddress, _In_ PVOID DetourAddress,
                             _Out_writes_bytes_(USERMODE_HOOK_SIZE) PUCHAR OriginalBytes)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID baseAddress = TargetAddress;
    SIZE_T regionSize = USERMODE_HOOK_SIZE;
    ULONG oldProtect = 0;
    ULONG newProtect = PAGE_EXECUTE_READWRITE;
    UNREFERENCED_PARAMETER(Process);

    if (!DetourAddress)
        return STATUS_INVALID_PARAMETER;

    DbgPrint("!!! UserModeHook: Hooking %p -> Detour %p\n", TargetAddress, DetourAddress);

    __try
    {
        // 1. Change Protection to RWX so we can write the JMP
        // FIX: Use the function pointer
        status = fnZwProtectVirtualMemory(ZwCurrentProcess(), &baseAddress, &regionSize, newProtect, &oldProtect);

        if (!NT_SUCCESS(status))
        {
            DbgPrint("!!! UserModeHook: Protect failed: 0x%X\n", status);
            __leave;
        }

        // 2. Save original bytes
        ProbeForRead(TargetAddress, USERMODE_HOOK_SIZE, 1);
        RtlCopyMemory(OriginalBytes, TargetAddress, USERMODE_HOOK_SIZE);

        // 3. Build hook shellcode (Absolute JMP to DetourAddress)
        // FF 25 00 00 00 00 [8 byte address]
        UCHAR hookShellcode[USERMODE_HOOK_SIZE];
        hookShellcode[0] = 0xFF;
        hookShellcode[1] = 0x25;
        *(PULONG)&hookShellcode[2] = 0x00000000;
        *(PVOID *)&hookShellcode[6] = DetourAddress;

        // 4. Write hook
        ProbeForWrite(TargetAddress, USERMODE_HOOK_SIZE, 1);
        RtlCopyMemory(TargetAddress, hookShellcode, USERMODE_HOOK_SIZE);

        // 5. Restore Protection
        // FIX: Use the function pointer
        fnZwProtectVirtualMemory(ZwCurrentProcess(), &baseAddress, &regionSize, oldProtect, &oldProtect);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = STATUS_ACCESS_VIOLATION;
    }

    return status;
}

//
// Hook a specific process
//

//
// Helper to Inject a Single Hook
//
NTSTATUS InjectSingleHook(
    _In_ PEPROCESS Process,
    _In_ ULONG ProcessId,
    _Inout_ PPROCESS_HOOK_ENTRY HookEntry,
    _Inout_ PHOOK_DEF HookDef,
    _In_ ULONG EventId,
    _In_ PVOID TargetNtDeviceIo
)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(Process);
    
    if (!HookDef->Address) return STATUS_INVALID_PARAMETER;
    if (HookDef->IsHooked) return STATUS_SUCCESS; // Already hooked

    // FIX #4: Reject hooks whose stolen bytes contain RIP-relative instructions.
    // Re-executing such bytes from the shellcode's different VA would silently
    // corrupt memory or jump to garbage.
    if (ContainsUnrelocatableInstructions((const UCHAR*)HookDef->Address, USERMODE_HOOK_SIZE))
    {
        DbgPrint("UserModeHook: Skipping %p — stolen bytes contain RIP-relative instructions\n",
                 HookDef->Address);
        return STATUS_NOT_SUPPORTED;
    }

    // Calculate Offset
    if (HookEntry->ShellcodeUsed + sizeof(g_ShellcodeTemplate) > HookEntry->ShellcodeSize) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    PVOID myShellcodeAddress = (PVOID)((ULONG_PTR)HookEntry->ShellcodeBase + HookEntry->ShellcodeUsed);

    // 1. Prepare Shellcode (Copy and Patch by signature to avoid fragile hardcoded offsets)
    UCHAR shellcode[sizeof(g_ShellcodeTemplate)];
    RtlCopyMemory(shellcode, g_ShellcodeTemplate, sizeof(shellcode));

    {
        // Updated signatures matching the corrected shellcode template
        static const UCHAR kEventSig[]  = {0xC7, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, 0x11, 0x11, 0x11, 0x11};
        static const UCHAR kPidSig[]    = {0xC7, 0x84, 0x24, 0x94, 0x00, 0x00, 0x00, 0x22, 0x22, 0x22, 0x22};
        static const UCHAR kHandleSig[] = {0x48, 0xB9, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33};
        static const UCHAR kIoctlSig[]  = {0x48, 0xB8, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
        static const UCHAR kSizeSig[]   = {0x48, 0xB8, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77};
        static const UCHAR kNtIoSig[]   = {0x48, 0xB8, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44};
        static const UCHAR kRetSig[]    = {0x48, 0xB8, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};

        SIZE_T offEvent  = FindPatternOffset(shellcode, sizeof(shellcode), kEventSig,  sizeof(kEventSig));
        SIZE_T offPid    = FindPatternOffset(shellcode, sizeof(shellcode), kPidSig,    sizeof(kPidSig));
        SIZE_T offHandle = FindPatternOffset(shellcode, sizeof(shellcode), kHandleSig, sizeof(kHandleSig));
        SIZE_T offIoctl  = FindPatternOffset(shellcode, sizeof(shellcode), kIoctlSig,  sizeof(kIoctlSig));
        SIZE_T offSize   = FindPatternOffset(shellcode, sizeof(shellcode), kSizeSig,   sizeof(kSizeSig));
        SIZE_T offNtIo   = FindPatternOffset(shellcode, sizeof(shellcode), kNtIoSig,   sizeof(kNtIoSig));
        SIZE_T offRet    = FindPatternOffset(shellcode, sizeof(shellcode), kRetSig,    sizeof(kRetSig));

        if (offEvent  == (SIZE_T)-1 ||
            offPid    == (SIZE_T)-1 ||
            offHandle == (SIZE_T)-1 ||
            offIoctl  == (SIZE_T)-1 ||
            offSize   == (SIZE_T)-1 ||
            offNtIo   == (SIZE_T)-1 ||
            offRet    == (SIZE_T)-1 ||
            offRet     < USERMODE_HOOK_SIZE)
        {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        // Patch EventId — ULONG at instruction+7 (mov dword ptr [rsp+0x90], imm32)
        *(PULONG)(shellcode + offEvent + 7) = EventId;

        // Patch ProcessId — ULONG at instruction+7
        *(PULONG)(shellcode + offPid + 7) = ProcessId;

        // Patch FileHandle — HANDLE (8 bytes) at mov rcx, imm64 offset+2
        *(PHANDLE)(shellcode + offHandle + 2) = HookEntry->DriverDeviceHandle;

        // Patch IoControlCode — store as ULONG64 in the mov rax, imm64 slot
        *(PULONG64)(shellcode + offIoctl + 2) = (ULONG64)HOOK_NOTIFY_IOCTL_CODE;

        // Patch InputBufferLength — sizeof(HOOK_EVENT_DATA) as ULONG64
        *(PULONG64)(shellcode + offSize + 2) = (ULONG64)sizeof(HOOK_EVENT_DATA);

        // Patch NtDeviceIoControlFile address
        *(PVOID *)(shellcode + offNtIo + 2) = TargetNtDeviceIo;

        // Save original bytes and embed them in the stolen-instruction slot
        // (which sits exactly USERMODE_HOOK_SIZE bytes before the return stub)
        RtlCopyMemory(HookDef->OriginalBytes, HookDef->Address, USERMODE_HOOK_SIZE);
        RtlCopyMemory(shellcode + (offRet - USERMODE_HOOK_SIZE), HookDef->Address, USERMODE_HOOK_SIZE);

        // Patch return target to original function + stolen bytes
        *(PVOID *)(shellcode + offRet + 2) = (PVOID)((ULONG_PTR)HookDef->Address + USERMODE_HOOK_SIZE);
    }

    // Write Shellcode to Target at specific offset
    RtlCopyMemory(myShellcodeAddress, shellcode, sizeof(shellcode));
    
    // 2. Install Hook (JMP to Shellcode)
    PVOID pageAddr = HookDef->Address;
    SIZE_T pageSize = 14;
    ULONG oldProt;
    if (fnZwProtectVirtualMemory) {
        status = fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, PAGE_EXECUTE_READWRITE, &oldProt);
        if (NT_SUCCESS(status)) {
            // Write JMP [RIP+0] -> Shellcode Address: FF 25 00 00 00 00 [Address]
            UCHAR jmp[14];
            RtlZeroMemory(jmp, 14);
            jmp[0] = 0xFF; jmp[1] = 0x25; 
            *(PULONG)&jmp[2] = 0;
            *(PVOID*)&jmp[6] = myShellcodeAddress;
            
            RtlCopyMemory(HookDef->Address, jmp, 14);
            
            fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, oldProt, &oldProt);
            
            HookEntry->ShellcodeUsed += sizeof(g_ShellcodeTemplate);
            HookDef->IsHooked = TRUE;
        }
        else
        {
            return status;
        }
    }
    else
    {
        return STATUS_NOT_SUPPORTED;
    }

    return STATUS_SUCCESS;
}

//
// Inject Shellcode Initialization (Alloc + Handle)
//
// FIX #3: ZwCreateFile with FILE_SYNCHRONOUS_IO_NONALERT must NOT be called
// while attached to another process via KeStackAttachProcess.  Completion of
// synchronous I/O is delivered via a kernel APC, and the APC subsystem is
// unreliable in a cross-process attach context, causing deadlocks or hangs.
//
// New design:
//   1. Before any attachment: open a reference to the device FILE_OBJECT from
//      system context using ObReferenceObjectByName (no I/O APC needed).
//   2. Inside the attach: use ObInsertObject to insert the FILE_OBJECT directly
//      into the target process handle table — a pure handle-table operation
//      that does not involve any I/O completion.
//   3. Allocate the shellcode region inside the attach (ZwAllocateVirtualMemory
//      with ZwCurrentProcess() is safe; it resolves to the attached process).
//
NTSTATUS InitializeShellcodeInfrastructure(_In_ PEPROCESS Process, _Inout_ PPROCESS_HOOK_ENTRY HookEntry)
{
    NTSTATUS  status;
    PVOID     baseAddress = NULL;
    UNREFERENCED_PARAMETER(Process);
    SIZE_T hookSlots = (SIZE_T)HookEntry->CustomHookCapacity;
    if (hookSlots == 0)
    {
        hookSlots = 32;
    }
    SIZE_T regionSize = (SIZE_T)(sizeof(g_ShellcodeTemplate) * (hookSlots + 32));
    if (regionSize < (SIZE_T)0x4000)
    {
        regionSize = (SIZE_T)0x4000;
    }
    regionSize = (regionSize + 0xFFF) & ~(SIZE_T)0xFFF;

    if (g_HookDeviceObject == NULL)
    {
        return STATUS_DEVICE_DOES_NOT_EXIST;
    }

    // -----------------------------------------------------------------------
    // STEP 1 (before attach): obtain a kernel reference to the device's
    // FILE_OBJECT without performing any synchronous file I/O.
    // -----------------------------------------------------------------------
    PFILE_OBJECT deviceFileObject = NULL;
    {
        static const PCWSTR hookDevicePaths[] = {
            L"\\DosDevices\\OwlyshieldHook",
            L"\\??\\OwlyshieldHook",
            L"\\Device\\OwlyshieldHook"
        };

        status = STATUS_OBJECT_NAME_NOT_FOUND;
        for (ULONG i = 0; i < RTL_NUMBER_OF(hookDevicePaths); ++i)
        {
            UNICODE_STRING devPath;
            OBJECT_ATTRIBUTES oa;
            IO_STATUS_BLOCK ioStatus = {0};

            RtlInitUnicodeString(&devPath, hookDevicePaths[i]);
            InitializeObjectAttributes(&oa, &devPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

            // Open a kernel handle first, then lift it to a FILE_OBJECT pointer.
            HANDLE tmpHandle = NULL;
            status = ZwCreateFile(
                &tmpHandle,
                FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
                &oa,
                &ioStatus,
                NULL,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                NULL,
                0);

            if (NT_SUCCESS(status))
            {
                // Elevate the handle to an object pointer so we can insert it
                // into any process handle table without another ZwCreateFile.
                status = ObReferenceObjectByHandle(
                    tmpHandle,
                    FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
                    *IoFileObjectType,
                    KernelMode,
                    (PVOID *)&deviceFileObject,
                    NULL);
                ZwClose(tmpHandle);
                if (NT_SUCCESS(status))
                    break;
            }
        }

        if (!NT_SUCCESS(status) || deviceFileObject == NULL)
        {
            return NT_SUCCESS(status) ? STATUS_OBJECT_NAME_NOT_FOUND : status;
        }
    }

    // -----------------------------------------------------------------------
    // STEP 2 (inside attach): allocate shellcode memory, then use
    // ObInsertObject to create a handle that lives in the TARGET process's
    // handle table — no file I/O, no kernel APCs required.
    // -----------------------------------------------------------------------
    {
        KAPC_STATE apcState;
        KeStackAttachProcess((PRKPROCESS)Process, &apcState);
        __try
        {
            // Allocate executable shellcode region in the target process.
            if (fnZwAllocateVirtualMemory)
            {
                status = fnZwAllocateVirtualMemory(
                    ZwCurrentProcess(), &baseAddress, 0,
                    &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            }
            else
            {
                status = STATUS_NOT_IMPLEMENTED;
            }

            if (!NT_SUCCESS(status))
            {
                __leave;
            }

            HookEntry->ShellcodeBase  = baseAddress;
            HookEntry->ShellcodeSize  = regionSize;
            HookEntry->ShellcodeUsed  = 0;

            // Insert the FILE_OBJECT into the CURRENT (= attached = target)
            // process handle table.  ObInsertObject takes a reference from
            // deviceFileObject, so we still need to dereference it below.
            HANDLE targetHandle = NULL;
            status = ObInsertObject(
                deviceFileObject,
                NULL,
                FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
                0,
                NULL,
                &targetHandle);

            if (NT_SUCCESS(status))
            {
                HookEntry->DriverDeviceHandle = targetHandle;
            }
            else
            {
                // Roll back shellcode allocation before leaving
                SIZE_T freeSize = 0;
                if (fnZwFreeVirtualMemory)
                    fnZwFreeVirtualMemory(ZwCurrentProcess(), &baseAddress, &freeSize, MEM_RELEASE);
                HookEntry->ShellcodeBase = NULL;
            }
        }
        __finally
        {
            KeUnstackDetachProcess(&apcState);
        }
    }

    // ObInsertObject consumes one reference, but ObReferenceObjectByHandle gave
    // us an extra one — release it regardless of success/failure.
    ObDereferenceObject(deviceFileObject);

    return status;
}

//
// Helper: Resolve and Prepare Hook
//
NTSTATUS ResolveAndHook(
    _In_ PEPROCESS Process,
    _In_ PPROCESS_HOOK_ENTRY HookEntry,
    _In_ PCWSTR ModuleName,
    _In_ PCSTR FunctionName,
    _Inout_ PHOOK_DEF HookDef,
    _In_ ULONG EventId,
    _In_ PVOID TargetNtDeviceIo
)
{
    SIZE_T modSize = 0;
    PVOID modBase = FindModuleBaseAddress(Process, ModuleName, &modSize);
    if (!modBase) return STATUS_NOT_FOUND;
    
    HookDef->Address = FindExportedFunction(modBase, FunctionName);

    if (!HookDef->Address) return STATUS_PROCEDURE_NOT_FOUND;

    return InjectSingleHook(Process, HookEntry->ProcessId, HookEntry, HookDef, EventId, TargetNtDeviceIo);
}

NTSTATUS UserModeHookProcess(_In_ ULONG ProcessId)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PPROCESS_HOOK_ENTRY hookEntry = NULL;
    ULONG customHookCountSnapshot = 0;
    ULONG customHookCountToApply = 0;
    PVOID ntdllBase = NULL;
    PVOID targetNtDeviceIo = NULL;
    BOOLEAN existingHookEntry = FALSE;

    if (g_UserHookEngine == NULL || !g_UserHookEngine->IsInitialized)
        return STATUS_DEVICE_NOT_READY;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status))
        return status;

    if (ShouldSkipHookingProcess(process, ProcessId))
    {
        ObDereferenceObject(process);
        return STATUS_ACCESS_DENIED;
    }

    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);

    // Re-use existing process slot to avoid duplicate infrastructure/handle creation.
    for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++)
    {
        if (g_UserHookEngine->Processes[i].ProcessId == ProcessId)
        {
            hookEntry = &g_UserHookEngine->Processes[i];
            existingHookEntry = TRUE;
            break;
        }
    }

    if (!existingHookEntry)
    {
        // Find free slot
        for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++)
        {
            if (!g_UserHookEngine->Processes[i].IsHooked && !g_UserHookEngine->Processes[i].IsInProgress)
            {
                hookEntry = &g_UserHookEngine->Processes[i];
                break;
            }
        }

        if (hookEntry == NULL)
        {
            ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
            ObDereferenceObject(process);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(hookEntry, sizeof(PROCESS_HOOK_ENTRY)); // Clear it
        hookEntry->ProcessId = ProcessId;
        hookEntry->ProcessObject = process;

        // Explicitly reference the object for the global array
        ObReferenceObject(process);
    
        ExAcquireFastMutex(&g_ConfigMutex);
        customHookCountSnapshot = g_CustomHookCount;
        ExReleaseFastMutex(&g_ConfigMutex);

        if (customHookCountSnapshot > MAX_CUSTOM_HOOKS)
        {
            customHookCountSnapshot = MAX_CUSTOM_HOOKS;
        }
        hookEntry->CustomHookCapacity = customHookCountSnapshot;
    }

    // Check if already in progress to avoid concurrent hooking of the same PID
    if (hookEntry->IsInProgress)
    {
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
        ObDereferenceObject(process);
        return STATUS_SUCCESS; // Already being processed
    }

    hookEntry->IsInProgress = TRUE;
    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);

    // -----------------------------------------------------------------------
    // FIX #3 (cont.): Initialize shellcode infrastructure BEFORE attaching.
    // InitializeShellcodeInfrastructure now manages its own internal attach
    // for the memory allocation step, but opens the device handle from system
    // context to avoid the ZwCreateFile-inside-KeStackAttachProcess deadlock.
    // -----------------------------------------------------------------------
    if (!existingHookEntry)
    {
        status = InitializeShellcodeInfrastructure(process, hookEntry);
        if (!NT_SUCCESS(status))
        {
            goto HookProcessFailure;
        }

        if (hookEntry->CustomHookCapacity > 0)
        {
            SIZE_T customHooksBytes = (SIZE_T)hookEntry->CustomHookCapacity * sizeof(HOOK_DEF);
            hookEntry->CustomHooks = (PHOOK_DEF)ExAllocatePool2(POOL_FLAG_NON_PAGED, customHooksBytes, 'cHuM');
            if (hookEntry->CustomHooks == NULL)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto HookProcessFailure;
            }
            RtlZeroMemory(hookEntry->CustomHooks, customHooksBytes);
        }
    }

    // Single attachment for resolving exports and writing hooks
    {
    KAPC_STATE apcState;
    KeStackAttachProcess((PRKPROCESS)process, &apcState);
    __try
    {
        // Resolve NtDeviceIoControlFile address in the target's ntdll
        ntdllBase = FindModuleBaseAddress(process, L"ntdll.dll", NULL);
        targetNtDeviceIo = FindExportedFunction(ntdllBase, "NtDeviceIoControlFile");
        if (!targetNtDeviceIo)
        {
            status = STATUS_NOT_FOUND;
            __leave;
        }

        // Inject hooks
        ExAcquireFastMutex(&g_ConfigMutex);
            customHookCountToApply = g_CustomHookCount;
            if (customHookCountToApply > hookEntry->CustomHookCapacity)
            {
                customHookCountToApply = hookEntry->CustomHookCapacity;
            }
            for (ULONG i = 0; i < customHookCountToApply; i++)
            {
                NTSTATUS hookStatus = ResolveAndHook(process, hookEntry, g_GlobalCustomHooks[i].ModuleName,
                                                     g_GlobalCustomHooks[i].FunctionName, &hookEntry->CustomHooks[i],
                                                     g_GlobalCustomHooks[i].EventId, targetNtDeviceIo);
                // Missing module/export is expected during refresh cycles; keep processing remaining entries.
                if (!NT_SUCCESS(hookStatus) && hookStatus != STATUS_NOT_FOUND &&
                    hookStatus != STATUS_PROCEDURE_NOT_FOUND)
                {
                    status = hookStatus;
                    ExReleaseFastMutex(&g_ConfigMutex);
                    __leave;
                }
            }
            ExReleaseFastMutex(&g_ConfigMutex);
        }
        __finally
        {
            KeUnstackDetachProcess(&apcState);
        }

        ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);
        hookEntry->IsInProgress = FALSE;
        if (NT_SUCCESS(status))
        {
            hookEntry->IsHooked = TRUE;
            if (!existingHookEntry)
            {
                g_UserHookEngine->HookedProcessCount++;
            }
        }
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);

        if (NT_SUCCESS(status))
        {
            DbgPrint("UserModeHook: Shellcodes processed for PID %lu (%s)\n", ProcessId,
                     existingHookEntry ? "refresh" : "initial");
        }
        else
        {
            goto HookProcessFailure;
        }

        ObDereferenceObject(process);
        return status;
    } // end attach scope block (unreachable — goto HookProcessFailure above)
    // Ensure busy flag is cleared on failure
    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);
    hookEntry->IsInProgress = FALSE;
    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);

    if (existingHookEntry)
    {
        ObDereferenceObject(process);
        return status;
    }

    if (hookEntry != NULL)
    {
        if (hookEntry->CustomHooks != NULL)
        {
            ExFreePoolWithTag(hookEntry->CustomHooks, 'cHuM');
            hookEntry->CustomHooks = NULL;
            hookEntry->CustomHookCapacity = 0;
        }

        if (hookEntry->DriverDeviceHandle != NULL || hookEntry->ShellcodeBase != NULL)
        {
            KAPC_STATE cleanupApcState;
            KeStackAttachProcess((PRKPROCESS)process, &cleanupApcState);
            __try
            {
                if (hookEntry->DriverDeviceHandle != NULL)
                {
                    ZwClose(hookEntry->DriverDeviceHandle);
                    hookEntry->DriverDeviceHandle = NULL;
                }

                if (hookEntry->ShellcodeBase != NULL && fnZwFreeVirtualMemory != NULL)
                {
                    SIZE_T freeSize = 0;
                    fnZwFreeVirtualMemory(ZwCurrentProcess(), &hookEntry->ShellcodeBase, &freeSize, MEM_RELEASE);
                    hookEntry->ShellcodeBase = NULL;
                }
            }
            __finally
            {
                KeUnstackDetachProcess(&cleanupApcState);
            }
        }

        // Drop the global array's reference before clearing the entry
        if (hookEntry->ProcessObject != NULL) {
            ObDereferenceObject(hookEntry->ProcessObject);
        }

        hookEntry->ProcessObject = NULL;
        RtlZeroMemory(hookEntry, sizeof(PROCESS_HOOK_ENTRY));
    }

    ObDereferenceObject(process);
    return status;
}
//
// Unhook
//

//
// Helper to Unhook Single Function
//
VOID UnhookSingleFunction(
    _In_ PEPROCESS Process,
    _Inout_ PHOOK_DEF HookDef
)
{
    NTSTATUS status;
    PVOID pageAddr = HookDef->Address;
    SIZE_T pageSize = 14; 
    ULONG oldProt;
    
    if (!HookDef->IsHooked || !HookDef->Address) 
        return;

    if (fnZwProtectVirtualMemory) {
        status = fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, PAGE_EXECUTE_READWRITE, &oldProt);
        if (NT_SUCCESS(status)) {
            // Restore Original Bytes
            RtlCopyMemory(HookDef->Address, HookDef->OriginalBytes, 14);
            
            // CRITICAL: Force the CPU to clear its execution pipeline for this memory
            // This prevents "Instruction Prefetch" errors that cause hard resets
            KeInvalidateAllCaches(); 

            fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, oldProt, &oldProt);
            HookDef->IsHooked = FALSE;
        }
    }
}

NTSTATUS UserModeUnhookProcess(_In_ ULONG ProcessId)
{
    PEPROCESS process = NULL;
    PPROCESS_HOOK_ENTRY hookEntry = NULL;
    NTSTATUS status;
    KAPC_STATE apcState;
    PVOID shellcodeToFree = NULL;

    if (g_UserHookEngine == NULL)
        return STATUS_DEVICE_NOT_READY;

    // 1. Lock the slot
    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);
    for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++) {
        if (g_UserHookEngine->Processes[i].IsHooked && g_UserHookEngine->Processes[i].ProcessId == ProcessId) {
            hookEntry = &g_UserHookEngine->Processes[i];
            break;
        }
    }

    if (hookEntry == NULL || hookEntry->IsInProgress) {
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
        return STATUS_NOT_FOUND;
    }

    hookEntry->IsInProgress = TRUE; 
    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);

    // 2. Lookup and Zombie Check
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) goto FinalCleanup;

    // Check if process is exiting/zombie - Attaching to a dying process causes hard resets
    if (PsGetProcessExitStatus(process) != STATUS_PENDING) {
        ObDereferenceObject(process);
        goto FinalCleanup;
    }

    // 3. PHASE 1: RESTORE BYTES
    KeEnterCriticalRegion(); // Disable kernel APCs during attachment
    KeStackAttachProcess((PRKPROCESS)process, &apcState);
    __try {
        for (ULONG i = 0; i < hookEntry->CustomHookCapacity; ++i) {
            if (hookEntry->CustomHooks != NULL && hookEntry->CustomHooks[i].IsHooked) {
                UnhookSingleFunction(process, &hookEntry->CustomHooks[i]);
            }
        }
        
        if (hookEntry->DriverDeviceHandle) {
            ZwClose(hookEntry->DriverDeviceHandle);
            hookEntry->DriverDeviceHandle = NULL;
        }
        shellcodeToFree = hookEntry->ShellcodeBase;
    }
    __finally {
        KeUnstackDetachProcess(&apcState);
        KeLeaveCriticalRegion();
    }

    // 4. PHASE 2: SAFETY DRAIN
    // FIX #5: Give threads more time to exit the shellcode before freeing it.
    // 100ms was insufficient under load.  We extend to 500ms and add the
    // missing NULL guard for fnZwFreeVirtualMemory (FIX #2).
    // NOTE: A true fix requires reference-counting active shellcode threads;
    // this is a best-effort improvement that greatly reduces the risk window.
    if (shellcodeToFree) {
        LARGE_INTEGER interval;
        interval.QuadPart = -500LL * 1000LL * 10LL;  // 500 ms
        KeDelayExecutionThread(KernelMode, FALSE, &interval);

        // 5. PHASE 3: FREE SHELLCODE
        // Re-check process health before final attachment
        if (PsGetProcessExitStatus(process) == STATUS_PENDING &&
            fnZwFreeVirtualMemory != NULL &&           // FIX #2: NULL guard
            fnZwProtectVirtualMemory != NULL)
        {
            KeStackAttachProcess((PRKPROCESS)process, &apcState);
            __try
            {
                // FIX #5 (enhancement): Overwrite shellcode pages with INT3
                // (0xCC) BEFORE freeing. Any thread that somehow re-enters the
                // trampoline after the bytes were restored will trap on INT3
                // rather than executing undefined freed-memory content.
                SIZE_T fillSize = hookEntry->ShellcodeSize;
                if (fillSize == 0) fillSize = 0x1000;  // safe fallback

                PVOID  fillAddr = shellcodeToFree;
                ULONG  oldProt  = 0;
                NTSTATUS protSt = fnZwProtectVirtualMemory(
                    ZwCurrentProcess(), &fillAddr, &fillSize,
                    PAGE_EXECUTE_READWRITE, &oldProt);

                if (NT_SUCCESS(protSt))
                {
                    __try
                    {
                        RtlFillMemory(shellcodeToFree, fillSize, 0xCC); // INT3
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) { /* ignore */ }

                    fnZwProtectVirtualMemory(
                        ZwCurrentProcess(), &fillAddr, &fillSize,
                        oldProt, &oldProt);
                }

                // Release the region.
                SIZE_T size = 0;
                fnZwFreeVirtualMemory(ZwCurrentProcess(), &shellcodeToFree,
                                      &size, MEM_RELEASE);
            }
            __finally
            {
                KeUnstackDetachProcess(&apcState);
            }
        }
    }

    ObDereferenceObject(process);

FinalCleanup:
    // 6. INTERNAL CLEANUP
    if (hookEntry->CustomHooks != NULL) {
        ExFreePoolWithTag(hookEntry->CustomHooks, 'cHuM');
    }

    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);
    RtlZeroMemory(hookEntry, sizeof(PROCESS_HOOK_ENTRY));
    if (g_UserHookEngine->HookedProcessCount > 0) g_UserHookEngine->HookedProcessCount--;
    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);

    return STATUS_SUCCESS;
}
