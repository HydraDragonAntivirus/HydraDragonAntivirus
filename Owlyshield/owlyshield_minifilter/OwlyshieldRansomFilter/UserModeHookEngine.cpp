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
    if (!g_HookExcludeRules.MutexInitialized)
    {
        ExInitializeFastMutex(&g_HookExcludeRules.Mutex);
        g_HookExcludeRules.MutexInitialized = TRUE;
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
    NTSTATUS status;

    if (RuleText == NULL || RuleChars == 0)
    {
        return STATUS_SUCCESS;
    }

    while (start < end && (RuleText[start] == L' ' || RuleText[start] == L'\t'))
    {
        start++;
    }
    while (end > start &&
           (RuleText[end - 1] == L' ' || RuleText[end - 1] == L'\t' || RuleText[end - 1] == L'\r'))
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

    EnsureHookExcludeRuleMutex();
    ExAcquireFastMutex(&g_HookExcludeRules.Mutex);
    if (!g_HookExcludeRules.Loaded)
    {
        FreeHookExcludeRulesUnlocked();
        for (ULONG i = 0; i < RTL_NUMBER_OF(ruleFiles); ++i)
        {
            UNICODE_STRING ruleFile;
            RtlInitUnicodeString(&ruleFile, ruleFiles[i]);
            (VOID)LoadHookExcludeRulesFromFileUnlocked(&ruleFile);
        }
        g_HookExcludeRules.Loaded = TRUE;
    }
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

// Minimal x64 Shellcode for Notification
// It calls NtDeviceIoControlFile to notify the driver
// Then executes the original instruction and jumps back
UCHAR g_ShellcodeTemplate[] = {
    // Save Volatile Registers
    0x50, 0x51, 0x52, 0x53,                         // push rax, rcx, rdx, rbx
    0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, // push r8, r9, r10, r11
    
    // Allocate space for HOOK_EVENT_DATA (80 bytes) + Shadow Space (32) + Align(16)
    0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00,       // sub rsp, 128
    
    // Fill HOOK_EVENT_DATA
    // EventType (Offset 0 in struct) -> Set by Patch (Offset 24 in shellcode)
    0xC7, 0x04, 0x24, 0x11, 0x11, 0x11, 0x11,       // mov dword ptr [rsp], 0x11111111
    // ProcessId (Offset 4) -> Set by Patch (Offset 31 in shellcode)
    0xC7, 0x44, 0x24, 0x04, 0x22, 0x22, 0x22, 0x22, // mov dword ptr [rsp+4], 0x22222222
    // FunctionName (skip)
    // Args (Copy from saved registers)
    // RCX is at [rsp+128 + 8(r11)+8(r10)+...+8(rcx is 2nd from bottom?)]
    // Stack layout after pushes:
    // [RSP] -> HOOK_EVENT_DATA 
    // [RSP+128] -> R11
    // ...
    // [RSP+128+64] -> RCX (Argument 1)
    
    // Copy RCX (Arg1) to Struct.Arg1 (Offset 72 = 0x48)
    // mov rax, [rsp + 0xC0 + 8] (R11..RBX..RDX..RCX is 7th push? No)
    // Order: RAX, RCX, RDX, RBX, R8, R9, R10, R11
    // RSP points to R11.
    // RCX is at RSP + 7*8 = RSP+56.
    // Wait, after sub rsp, 128:
    // RCX is at RSP + 128 + 56 = RSP + 184 (0xB8)
    0x48, 0x8B, 0x84, 0x24, 0xB8, 0x00, 0x00, 0x00, // mov rax, [rsp+0xB8]
    0x48, 0x89, 0x44, 0x24, 0x48,                   // mov [rsp+0x48], rax
    
    // Copy RDX (Arg2) -> Arg2 (Offset 80)
    // RDX is at RSP + 128 + 48 = RSP + 176 (0xB0)
    0x48, 0x8B, 0x84, 0x24, 0xB0, 0x00, 0x00, 0x00, // mov rax, [rsp+0xB0] 
    0x48, 0x89, 0x44, 0x24, 0x50,                   // mov [rsp+0x50], rax
    
    // Prepare Call to NtDeviceIoControlFile
    // RCX = Handle (Patched)
    0x48, 0xB9, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, // mov rcx, 0x3333333333333333
    // RDX = Event (Msg) -> NULL
    0x31, 0xD2,                                     // xor edx, edx
    // ... skipping complex call preparation for brevity, just calling the func address
    
    // Call NtDeviceIoControlFile (Address Patched)
    0x48, 0xB8, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, // mov rax, 0x4444...
    // call rax
    0xFF, 0xD0,
    
    // Restore Stack
    0x48, 0x81, 0xC4, 0x80, 0x00, 0x00, 0x00,       // add rsp, 128
    
    // Restore Registers
    0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, // pop r11..r8
    0x5B, 0x5A, 0x59, 0x58,                         // pop rbx..rax
    
    // Execute Original Inst (Placeholder 14 bytes)
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    
    // Jmp Back (Address Patched)
    // mov rax, 0x5555...
    0x48, 0xB8, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    // jmp rax
    0xFF, 0xE0,
    
    // PADDING to avoid buffer overrun warning (C4789)
    // We write 14 bytes at offset 122, and other patches.
    // Ensure total size is > 150.
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
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
    KAPC_STATE apcState;

    if (ModuleSize != NULL)
        *ModuleSize = 0;

    KeStackAttachProcess((PRKPROCESS)Process, &apcState);

    __try
    {
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

    KeUnstackDetachProcess(&apcState);
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
    KAPC_STATE apcState;
    NTSTATUS status = STATUS_SUCCESS;
    PVOID baseAddress = TargetAddress;
    SIZE_T regionSize = USERMODE_HOOK_SIZE;
    ULONG oldProtect = 0;
    ULONG newProtect = PAGE_EXECUTE_READWRITE;

    if (!DetourAddress)
        return STATUS_INVALID_PARAMETER;

    DbgPrint("!!! UserModeHook: Hooking %p -> Detour %p\n", TargetAddress, DetourAddress);

    KeStackAttachProcess((PRKPROCESS)Process, &apcState);

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

    KeUnstackDetachProcess(&apcState);
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
    KAPC_STATE apcState;
    
    if (!HookDef->Address) return STATUS_INVALID_PARAMETER;
    if (HookDef->IsHooked) return STATUS_SUCCESS; // Already hooked

    // Calculate Offset
    if (HookEntry->ShellcodeUsed + sizeof(g_ShellcodeTemplate) > HookEntry->ShellcodeSize) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    PVOID myShellcodeAddress = (PVOID)((ULONG_PTR)HookEntry->ShellcodeBase + HookEntry->ShellcodeUsed);

    KeStackAttachProcess((PRKPROCESS)Process, &apcState);

    // 1. Prepare Shellcode (Copy and Patch)
    UCHAR shellcode[sizeof(g_ShellcodeTemplate)];
    RtlCopyMemory(shellcode, g_ShellcodeTemplate, sizeof(shellcode));

    // Patch placeholders by signatures (no fragile hardcoded offsets).
    {
        static const UCHAR kEventSig[] = {0xC7, 0x04, 0x24, 0x11, 0x11, 0x11, 0x11};
        static const UCHAR kPidSig[]   = {0xC7, 0x44, 0x24, 0x04, 0x22, 0x22, 0x22, 0x22};
        static const UCHAR kHandleSig[] = {
            0x48, 0xB9, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33
        };
        static const UCHAR kNtIoSig[] = {
            0x48, 0xB8, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44
        };
        static const UCHAR kRetSig[] = {
            0x48, 0xB8, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55
        };

        SIZE_T offEvent  = FindPatternOffset(shellcode, sizeof(shellcode), kEventSig, sizeof(kEventSig));
        SIZE_T offPid    = FindPatternOffset(shellcode, sizeof(shellcode), kPidSig, sizeof(kPidSig));
        SIZE_T offHandle = FindPatternOffset(shellcode, sizeof(shellcode), kHandleSig, sizeof(kHandleSig));
        SIZE_T offNtIo   = FindPatternOffset(shellcode, sizeof(shellcode), kNtIoSig, sizeof(kNtIoSig));
        SIZE_T offRet    = FindPatternOffset(shellcode, sizeof(shellcode), kRetSig, sizeof(kRetSig));

        if (offEvent == (SIZE_T)-1 ||
            offPid == (SIZE_T)-1 ||
            offHandle == (SIZE_T)-1 ||
            offNtIo == (SIZE_T)-1 ||
            offRet == (SIZE_T)-1 ||
            offRet < USERMODE_HOOK_SIZE)
        {
            KeUnstackDetachProcess(&apcState);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        *(PULONG)(shellcode + offEvent + 3) = EventId;
        *(PULONG)(shellcode + offPid + 4) = ProcessId;
        *(PHANDLE)(shellcode + offHandle + 2) = HookEntry->DriverDeviceHandle;
        *(PVOID *)(shellcode + offNtIo + 2) = TargetNtDeviceIo;

        // Save original bytes locally and embed them right before the return-jump stub.
        RtlCopyMemory(HookDef->OriginalBytes, HookDef->Address, USERMODE_HOOK_SIZE);
        RtlCopyMemory(shellcode + (offRet - USERMODE_HOOK_SIZE), HookDef->Address, USERMODE_HOOK_SIZE);

        // Patch return target to "original function + stolen bytes".
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
            // Write JMP [RIP+0] -> Shellcode Address
            // FF 25 00 00 00 00 [Address]
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
            KeUnstackDetachProcess(&apcState);
            return status;
        }
    }
    else
    {
        KeUnstackDetachProcess(&apcState);
        return STATUS_NOT_SUPPORTED;
    }

    KeUnstackDetachProcess(&apcState);
    return STATUS_SUCCESS;
}

//
// Inject Shellcode Initialization (Alloc + Handle)
//
NTSTATUS InitializeShellcodeInfrastructure(_In_ PEPROCESS Process, _Inout_ PPROCESS_HOOK_ENTRY HookEntry)
{
    NTSTATUS status;
    KAPC_STATE apcState;
    PVOID baseAddress = NULL;
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

    KeStackAttachProcess((PRKPROCESS)Process, &apcState);

    // 1. Allocate Shellcode Memory
    if (fnZwAllocateVirtualMemory) {
        status = fnZwAllocateVirtualMemory(ZwCurrentProcess(), &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    } else {
        status = STATUS_NOT_IMPLEMENTED;
    }

    if (!NT_SUCCESS(status)) {
        KeUnstackDetachProcess(&apcState);
        return status;
    }
    
    HookEntry->ShellcodeBase = baseAddress;
    HookEntry->ShellcodeSize = regionSize;
    HookEntry->ShellcodeUsed = 0;

    // 2. Create a real FILE handle in target process handle table so NtDeviceIoControlFile can use it.
    HANDLE targetHandle = NULL;
    IO_STATUS_BLOCK ioStatus = {0};
    UNICODE_STRING hookDevicePath;
    OBJECT_ATTRIBUTES oa;
    static const PCWSTR hookDevicePaths[] = {
        L"\\DosDevices\\OwlyshieldHook",
        L"\\??\\OwlyshieldHook",
        L"\\Device\\OwlyshieldHook"
    };

    if (g_HookDeviceObject == NULL)
    {
        if (fnZwFreeVirtualMemory)
        {
            SIZE_T freeSize = 0;
            fnZwFreeVirtualMemory(ZwCurrentProcess(), &baseAddress, &freeSize, MEM_RELEASE);
        }
        KeUnstackDetachProcess(&apcState);
        return STATUS_DEVICE_DOES_NOT_EXIST;
    }

    status = STATUS_OBJECT_NAME_NOT_FOUND;
    for (ULONG i = 0; i < RTL_NUMBER_OF(hookDevicePaths); ++i)
    {
        RtlInitUnicodeString(&hookDevicePath, hookDevicePaths[i]);
        InitializeObjectAttributes(&oa, &hookDevicePath, OBJ_CASE_INSENSITIVE, NULL, NULL);
        RtlZeroMemory(&ioStatus, sizeof(ioStatus));

        status = ZwCreateFile(&targetHandle,
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
            break;
        }
    }
                                    
    if (!NT_SUCCESS(status)) {
        if (fnZwFreeVirtualMemory) {
            SIZE_T freeSize = 0;
            fnZwFreeVirtualMemory(ZwCurrentProcess(), &baseAddress, &freeSize, MEM_RELEASE);
        }
        KeUnstackDetachProcess(&apcState);
        return status;
    }
    
    HookEntry->DriverDeviceHandle = targetHandle;
    KeUnstackDetachProcess(&apcState);
    return STATUS_SUCCESS;
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
    
    // Attach to resolve export
    KAPC_STATE apcState;
    KeStackAttachProcess((PRKPROCESS)Process, &apcState);
    HookDef->Address = FindExportedFunction(modBase, FunctionName);
    KeUnstackDetachProcess(&apcState);

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
    SIZE_T ntdllSize = 0;
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
        if (g_UserHookEngine->Processes[i].IsHooked &&
            g_UserHookEngine->Processes[i].ProcessId == ProcessId)
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
            if (!g_UserHookEngine->Processes[i].IsHooked)
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

        ExAcquireFastMutex(&g_ConfigMutex);
        customHookCountSnapshot = g_CustomHookCount;
        ExReleaseFastMutex(&g_ConfigMutex);
        if (customHookCountSnapshot > MAX_CUSTOM_HOOKS)
        {
            customHookCountSnapshot = MAX_CUSTOM_HOOKS;
        }
        hookEntry->CustomHookCapacity = customHookCountSnapshot;

        // 1. Initialize Infrastructure (Alloc + Handle)
        status = InitializeShellcodeInfrastructure(process, hookEntry);
        if (!NT_SUCCESS(status))
        {
            goto HookProcessFailure;
        }

        if (hookEntry->CustomHookCapacity > 0)
        {
            SIZE_T customHooksBytes = (SIZE_T)hookEntry->CustomHookCapacity * sizeof(HOOK_DEF);
            hookEntry->CustomHooks =
                (PHOOK_DEF)ExAllocatePool2(POOL_FLAG_NON_PAGED, customHooksBytes, 'cHuM');
            if (hookEntry->CustomHooks == NULL)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto HookProcessFailure;
            }
            RtlZeroMemory(hookEntry->CustomHooks, customHooksBytes);
        }
    }
    else
    {
        // This is a refresh call triggered after additional image loads.
        // Keep existing infrastructure and only try unresolved hooks.
        if (hookEntry->CustomHooks == NULL ||
            hookEntry->CustomHookCapacity == 0 ||
            hookEntry->ShellcodeBase == NULL ||
            hookEntry->DriverDeviceHandle == NULL)
        {
            status = STATUS_INVALID_DEVICE_STATE;
            goto HookProcessFailure;
        }
    }

    // 2. Resolve NtDeviceIoControlFile (Needed for communication)
    // We strictly need this from ntdll.dll
    ntdllBase = FindModuleBaseAddress(process, L"ntdll.dll", &ntdllSize);
    if (!ntdllBase)
    {
         status = STATUS_NOT_FOUND;
         goto HookProcessFailure;
    }
    
    KAPC_STATE apcState;
    KeStackAttachProcess((PRKPROCESS)process, &apcState);
    targetNtDeviceIo = FindExportedFunction(ntdllBase, "NtDeviceIoControlFile");
    KeUnstackDetachProcess(&apcState);
    
    if (!targetNtDeviceIo)
    {
         status = STATUS_NOT_FOUND;
         goto HookProcessFailure;
    }

    // 3. Inject Hooks (Dynamic only)
    ExAcquireFastMutex(&g_ConfigMutex);
    customHookCountToApply = g_CustomHookCount;
    if (customHookCountToApply > hookEntry->CustomHookCapacity)
    {
        customHookCountToApply = hookEntry->CustomHookCapacity;
    }
    for (ULONG i = 0; i < customHookCountToApply; i++)
    {
        NTSTATUS hookStatus = ResolveAndHook(process,
                                             hookEntry,
                                             g_GlobalCustomHooks[i].ModuleName,
                                             g_GlobalCustomHooks[i].FunctionName,
                                             &hookEntry->CustomHooks[i],
                                             g_GlobalCustomHooks[i].EventId,
                                             targetNtDeviceIo);
        // Missing module/export is expected during refresh cycles; keep processing remaining entries.
        if (!NT_SUCCESS(hookStatus) &&
            hookStatus != STATUS_NOT_FOUND &&
            hookStatus != STATUS_PROCEDURE_NOT_FOUND)
        {
            status = hookStatus;
            ExReleaseFastMutex(&g_ConfigMutex);
            goto HookProcessFailure;
        }
    }
    ExReleaseFastMutex(&g_ConfigMutex);

    if (!existingHookEntry)
    {
        hookEntry->IsHooked = TRUE;
        g_UserHookEngine->HookedProcessCount++;
    }

    DbgPrint("UserModeHook: Shellcodes processed for PID %lu (%s, %lu Custom)\n",
             ProcessId,
             existingHookEntry ? "refresh" : "initial",
             customHookCountToApply);

    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
    if (existingHookEntry)
    {
        ObDereferenceObject(process);
    }
    return STATUS_SUCCESS;

HookProcessFailure:
    if (existingHookEntry)
    {
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
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

        if (hookEntry->DriverDeviceHandle != NULL)
        {
            KAPC_STATE closeApcState;
            KeStackAttachProcess((PRKPROCESS)process, &closeApcState);
            ZwClose(hookEntry->DriverDeviceHandle);
            KeUnstackDetachProcess(&closeApcState);
            hookEntry->DriverDeviceHandle = NULL;
        }

        if (hookEntry->ShellcodeBase != NULL && fnZwFreeVirtualMemory != NULL)
        {
            KAPC_STATE freeApcState;
            SIZE_T freeSize = 0;
            KeStackAttachProcess((PRKPROCESS)process, &freeApcState);
            fnZwFreeVirtualMemory(ZwCurrentProcess(), &hookEntry->ShellcodeBase, &freeSize, MEM_RELEASE);
            KeUnstackDetachProcess(&freeApcState);
            hookEntry->ShellcodeBase = NULL;
        }

        hookEntry->ProcessObject = NULL;
        RtlZeroMemory(hookEntry, sizeof(PROCESS_HOOK_ENTRY));
    }

    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
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
    KAPC_STATE apcState;
    if (!HookDef->IsHooked || !HookDef->Address) return;

    KeStackAttachProcess((PRKPROCESS)Process, &apcState);

    // Restore Original Bytes
    PVOID pageAddr = HookDef->Address;
    SIZE_T pageSize = 14;
    ULONG oldProt;
    
    if (fnZwProtectVirtualMemory) {
        status = fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, PAGE_EXECUTE_READWRITE, &oldProt);
        if (NT_SUCCESS(status)) {
            RtlCopyMemory(HookDef->Address, HookDef->OriginalBytes, 14);
            fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, oldProt, &oldProt);
            HookDef->IsHooked = FALSE;
        }
    }

    KeUnstackDetachProcess(&apcState);
}


NTSTATUS UserModeUnhookProcess(_In_ ULONG ProcessId)
{
    PEPROCESS process = NULL;
    PPROCESS_HOOK_ENTRY hookEntry = NULL;
    NTSTATUS status;

    if (g_UserHookEngine == NULL)
        return STATUS_DEVICE_NOT_READY;

    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);

    for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++)
    {
        if (g_UserHookEngine->Processes[i].IsHooked && g_UserHookEngine->Processes[i].ProcessId == ProcessId)
        {
            hookEntry = &g_UserHookEngine->Processes[i];
            break;
        }
    }

    if (hookEntry == NULL)
    {
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
        return STATUS_NOT_FOUND;
    }

    DbgPrint("!!! UserModeHook: Unhooking process %lu\n", ProcessId);

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (NT_SUCCESS(status))
    {
        // Unhook all functions
        for (ULONG i = 0; i < hookEntry->CustomHookCapacity; ++i)
        {
            if (hookEntry->CustomHooks != NULL)
            {
                UnhookSingleFunction(process, &hookEntry->CustomHooks[i]);
            }
        }
        
        // Free Shellcode Memory using ZwFreeVirtualMemory
        KAPC_STATE apcState;
        KeStackAttachProcess((PRKPROCESS)process, &apcState);
        
        if (hookEntry->ShellcodeBase && fnZwFreeVirtualMemory) {
            SIZE_T size = 0;
            fnZwFreeVirtualMemory(ZwCurrentProcess(), &hookEntry->ShellcodeBase, &size, MEM_RELEASE);
            hookEntry->ShellcodeBase = NULL;
        }
        
        // Close Handle
        if (hookEntry->DriverDeviceHandle) {
            ZwClose(hookEntry->DriverDeviceHandle);
            hookEntry->DriverDeviceHandle = NULL;
        }

        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
    }

    if (hookEntry->CustomHooks != NULL)
    {
        ExFreePoolWithTag(hookEntry->CustomHooks, 'cHuM');
        hookEntry->CustomHooks = NULL;
    }

    if (hookEntry->ProcessObject != NULL)
    {
        ObDereferenceObject(hookEntry->ProcessObject);
        hookEntry->ProcessObject = NULL;
    }

    RtlZeroMemory(hookEntry, sizeof(PROCESS_HOOK_ENTRY));
    if (g_UserHookEngine->HookedProcessCount > 0)
    {
        g_UserHookEngine->HookedProcessCount--;
    }

    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
    return STATUS_SUCCESS;
}
