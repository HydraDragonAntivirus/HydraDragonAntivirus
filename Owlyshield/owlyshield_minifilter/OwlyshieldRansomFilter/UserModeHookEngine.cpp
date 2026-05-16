/*++

Module Name:

    UserModeHookEngine.cpp

Abstract:

    Implementation of user-mode ntdll.dll hooking engine.
    Supports both native 64-bit processes and WoW64 (32-bit) processes on
    64-bit Windows.

    Architecture overview
    ---------------------
    64-bit process:
      Shellcode written to the target VA, uses 14-byte FF 25 indirect JMP.
      Stolen instructions: first 14 bytes of the target function.
      Notification: calls 64-bit ntdll!NtDeviceIoControlFile via absolute
      mov rax / call rax.  The driver opens one master hook-device handle
      with FILE_SYNCHRONOUS_IO_NONALERT, then duplicates that same FILE_OBJECT
      into each target process.  NtDeviceIoControlFile therefore runs
      synchronously and the shellcode's stack-resident IO_STATUS_BLOCK remains
      valid until completion.

    32-bit (WoW64) process:
      Module base resolved via PEB32 (PsGetProcessWow64Process).
      Shellcode written to the target VA, uses 5-byte E9 rel32 JMP.
      Stolen instructions: first 5 bytes of the target function.
      Notification: calls 32-bit ntdll!NtDeviceIoControlFile via 32-bit
      stdcall (mov eax / call eax).  It uses the same duplicated synchronous
      device handle, so the WoW64 shellcode also waits for completion before
      returning to the caller.

    NOTE - required changes to UserModeHookEngine.h
    -------------------------------------------------
      1. Add to PROCESS_HOOK_ENTRY:   BOOLEAN IsWow64;
      2. Add to HOOK_DEF:             ULONG   HookPatchSize;
         (14 for 64-bit hooks, 5 for WoW64 hooks; drives unhook byte count)
      3. Add define:                  #define USERMODE_HOOK_SIZE_32  5

Environment:

    Kernel mode

--*/

#include "UserModeHookEngine.h"
#include "DriverData.h"
#include <ntimage.h>
#include <ntstrsafe.h>

// Some WDK versions do not expose a named status for dynamic-code policy
// failures in the headers used by this project. Treat both the native
// NTSTATUS form and the HRESULT_FROM_WIN32 form seen in logs as recoverable
// hook-install failures, not as reasons to leave a half-installed hook.
#ifndef STATUS_DYNAMIC_CODE_BLOCKED
#define STATUS_DYNAMIC_CODE_BLOCKED ((NTSTATUS)0xC0000604L)
#endif
#ifndef OWLY_HRESULT_DYNAMIC_CODE_BLOCKED
#define OWLY_HRESULT_DYNAMIC_CODE_BLOCKED ((NTSTATUS)0x80070677L)
#endif

// -------------------------------------------------------------------------
// WoW64 / 32-bit PE type definitions
//
// UNICODE_STRING32 and LIST_ENTRY32 are defined by ntdef.h (pulled in via
// ntifs.h in WDK 10.0.26100.0+) - we must NOT redefine them.
//
// PEB_LDR_DATA32, LDR_DATA_TABLE_ENTRY32, and PEB32 are not exported by
// any WDK header and are defined here verbatim from public documentation.
// -------------------------------------------------------------------------

#pragma pack(push, 4)

typedef struct _PEB_LDR_DATA32
{
    ULONG Length;
    BOOLEAN Initialized;
    ULONG SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;    // 32-bit VA stored as ULONG
    ULONG EntryPoint; // 32-bit VA stored as ULONG
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
} LDR_DATA_TABLE_ENTRY32;

typedef struct _PEB32
{
    UCHAR InheritedAddressSpace;    // +0x00
    UCHAR ReadImageFileExecOptions; // +0x01
    UCHAR BeingDebugged;            // +0x02
    UCHAR BitField;                 // +0x03
    ULONG Mutant;                   // +0x04 (ptr32)
    ULONG ImageBaseAddress;         // +0x08 (ptr32)
    ULONG Ldr;                      // +0x0C (ptr32 -> PEB_LDR_DATA32)
} PEB32;

#pragma pack(pop)

// -------------------------------------------------------------------------
// DYNAMIC IMPORT DEFINITIONS
// -------------------------------------------------------------------------

// -------------------------------------------------------------------------
// RE-ENTRANCY GUARD MAGIC CONSTANTS
//
// The shellcode stores this sentinel in TEB.NtTib.ArbitraryUserPointer
// (GS:[0x28] on x64, FS:[0x14] on x86/WoW64) while it is executing.
// Before calling NtDeviceIoControlFile, the shellcode checks whether the
// sentinel is already present.  If it is, the IOCTL call is skipped and
// the stolen bytes + return jump execute normally.  This prevents infinite
// recursion when a hooked function is called from within the driver's own
// IOCTL dispatch path (e.g. minifilter pre-operation -> NtCreateFile hook ->
// shellcode -> NtDeviceIoControlFile -> minifilter pre-operation -> ...).
//
// The magic value is distinctive enough that accidental collision with a
// real ArbitraryUserPointer usage is negligible.  The old value is saved
// on the local stack frame ([RSP+0x70] / [ESP+0x78]) and restored after
// the IOCTL completes, so any pre-existing value in the field is preserved.
// -------------------------------------------------------------------------
#define HOOK_REENTRANCY_MAGIC_64 ((ULONG64)0xFEEDF00DFEEDF00DUI64)
#define HOOK_REENTRANCY_MAGIC_32 ((ULONG32)0xFEEDF00DUL)

// Function Pointer Types
typedef NTSTATUS(NTAPI *PZW_PROTECT_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                    _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtect,
                                                    _Out_ PULONG OldProtect);

typedef PPEB(NTAPI *PPS_GET_PROCESS_PEB)(_In_ PEPROCESS Process);

typedef NTSTATUS(NTAPI *PZW_ALLOCATE_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                     _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize,
                                                     _In_ ULONG AllocationType, _In_ ULONG Protect);
typedef NTSTATUS(NTAPI *PZW_FREE_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                 _Inout_ PSIZE_T RegionSize, _In_ ULONG FreeType);
typedef NTSTATUS(NTAPI *PZW_SET_INFORMATION_OBJECT)(_In_ HANDLE Handle,
                                                    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
                                                    _In_reads_bytes_(ObjectInformationLength) PVOID ObjectInformation,
                                                    _In_ ULONG ObjectInformationLength);
typedef BOOLEAN(NTAPI *PPS_IS_PROTECTED_PROCESS)(_In_ PEPROCESS Process);
typedef BOOLEAN(NTAPI *PPS_IS_PROTECTED_PROCESS_LIGHT)(_In_ PEPROCESS Process);
typedef HANDLE(NTAPI *PPS_GET_PROCESS_INHERITED_FROM_UNIQUE_PROCESS_ID)(_In_ PEPROCESS Process);

// PsGetProcessWow64Process - returns the PEB32 pointer for a WoW64 process,
// or NULL if the process is a native 64-bit process.
typedef PVOID(NTAPI *PPS_GET_PROCESS_WOW64_PROCESS)(_In_ PEPROCESS Process);

typedef struct _OWLY_OBJECT_HANDLE_FLAG_INFORMATION
{
    BOOLEAN Inherit;
    BOOLEAN ProtectFromClose;
} OWLY_OBJECT_HANDLE_FLAG_INFORMATION, *POWLY_OBJECT_HANDLE_FLAG_INFORMATION;

#define OWLY_OBJECT_HANDLE_FLAG_INFORMATION_CLASS ((OBJECT_INFORMATION_CLASS)4)

//
// Global Function Pointers
//
PZW_PROTECT_VIRTUAL_MEMORY fnZwProtectVirtualMemory = NULL;
PZW_ALLOCATE_VIRTUAL_MEMORY fnZwAllocateVirtualMemory = NULL;
PZW_FREE_VIRTUAL_MEMORY fnZwFreeVirtualMemory = NULL;
PZW_SET_INFORMATION_OBJECT fnZwSetInformationObject = NULL;
PPS_GET_PROCESS_PEB fnPsGetProcessPeb = NULL;
PPS_IS_PROTECTED_PROCESS fnPsIsProtectedProcess = NULL;
PPS_IS_PROTECTED_PROCESS_LIGHT fnPsIsProtectedProcessLight = NULL;
PPS_GET_PROCESS_INHERITED_FROM_UNIQUE_PROCESS_ID fnPsGetProcessInheritedFromUniqueProcessId = NULL;
PPS_GET_PROCESS_WOW64_PROCESS fnPsGetProcessWow64Process = NULL;

PUSERMODE_HOOK_ENGINE g_UserHookEngine = NULL;
// Master hook notification FILE_OBJECT. Opened once with synchronous I/O
// semantics during engine init, then re-opened as a user handle inside each
// target process so shellcode receives a normal user-visible handle without
// duplicating a kernel handle into the target token.
static HANDLE g_HookNotifyMasterHandle = NULL;
static POBJECT_TYPE *g_HookIoFileObjectType = NULL;
static volatile BOOLEAN g_HookEngineShuttingDown = FALSE;

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
    volatile LONG MutexInitialized; // FIX Bug3: 0=uninit, 1=initializing, 2=ready
    BOOLEAN Loaded;
} HOOK_EXCLUDE_RULE_SET, *PHOOK_EXCLUDE_RULE_SET;

static HOOK_EXCLUDE_RULE_SET g_HookExcludeRules = {0};

// Load-once guard for g_HookExcludeRules.
// 0 = unloaded, 1 = loading (one thread owns this), 2 = loaded.
// InterlockedCompareExchange(0->1) ensures exactly one thread runs the
// file-I/O path; all others wait until state reaches 2.
static volatile LONG g_HookExcludeLoadState = 0;

// FIX 3: Back-off for rule file loading failures.
// When the rule file is absent, state resets to 0, causing ZwCreateFile on
// every process-create event (a hot path). This stores the earliest absolute
// 100ns time at which a retry is allowed. Zero means "no active back-off".
// EnsureHookExcludeRulesLoaded respects this before claiming the loader role.
// ReloadHookExcludeRules clears it so an explicit reload always proceeds.
static volatile LONG64 g_HookExcludeFailRetryTime = 0;
#define HOOK_EXCLUDE_RETRY_INTERVAL_100NS (30LL * 10000000LL) // 30 seconds

static NTSTATUS AppendHookExcludeRulesFromBufferUnlocked(_In_reads_bytes_(BytesRead) PUCHAR Buffer,
                                                         _In_ ULONG BytesRead);

static NTSTATUS AddHookExcludeRuleNormalizedUnlocked(_In_reads_(RuleChars) PCWSTR RuleText, _In_ SIZE_T RuleChars);

static NTSTATUS ValidateHookNotifyUserHandle(_In_ HANDLE Handle)
{
    NTSTATUS status;
    PFILE_OBJECT fileObject = NULL;

    if (Handle == NULL || Handle == NtCurrentProcess() || Handle == NtCurrentThread())
    {
        return STATUS_INVALID_HANDLE;
    }

    if (g_HookIoFileObjectType == NULL || *g_HookIoFileObjectType == NULL)
    {
        return STATUS_SUCCESS;
    }

    status = ObReferenceObjectByHandle(Handle,
                                       FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
                                       *g_HookIoFileObjectType,
                                       UserMode,
                                       (PVOID *)&fileObject,
                                       NULL);
    if (NT_SUCCESS(status) && fileObject != NULL)
    {
        ObDereferenceObject(fileObject);
    }

    return status;
}

static VOID CloseHookNotifyHandleSafe(_Inout_ PHANDLE Handle)
{
    NTSTATUS status;

    if (Handle == NULL || *Handle == NULL)
    {
        return;
    }

    __try
    {
        status = ValidateHookNotifyUserHandle(*Handle);
        if (!NT_SUCCESS(status))
        {
            *Handle = NULL;
            return;
        }

        if (fnZwSetInformationObject != NULL)
        {
            OWLY_OBJECT_HANDLE_FLAG_INFORMATION handleFlags = {0};
            NTSTATUS flagStatus;
            handleFlags.Inherit = FALSE;
            handleFlags.ProtectFromClose = FALSE;
            flagStatus = fnZwSetInformationObject(*Handle,
                                                  OWLY_OBJECT_HANDLE_FLAG_INFORMATION_CLASS,
                                                  &handleFlags,
                                                  sizeof(handleFlags));
            if (!NT_SUCCESS(flagStatus))
            {
                *Handle = NULL;
                return;
            }
        }

        status = ZwClose(*Handle);
        if (!NT_SUCCESS(status))
        {
            *Handle = NULL;
            return;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // Ignore exception from invalid handles or destroyed handle tables
    }

    *Handle = NULL;
}

static BOOLEAN IsRecoverableHookInstallStatus(_In_ NTSTATUS Status)
{
    switch (Status)
    {
    case STATUS_NOT_FOUND:
    case STATUS_PROCEDURE_NOT_FOUND:
    case STATUS_NOT_SUPPORTED:
    case STATUS_ACCESS_VIOLATION:
    case STATUS_INVALID_ADDRESS:
    case STATUS_CONFLICTING_ADDRESSES:
    case STATUS_INVALID_PARAMETER:
    case STATUS_INVALID_HANDLE:
    case STATUS_ACCESS_DENIED:
    case STATUS_DYNAMIC_CODE_BLOCKED:
    case OWLY_HRESULT_DYNAMIC_CODE_BLOCKED:
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOLEAN IsRecoverableHookProcessStatus(_In_ NTSTATUS Status)
{
    if (IsRecoverableHookInstallStatus(Status))
    {
        return TRUE;
    }

    switch (Status)
    {
    case STATUS_DEVICE_NOT_READY:
    case STATUS_OBJECT_NAME_NOT_FOUND:
        return TRUE;
    default:
        return FALSE;
    }
}

static VOID EnsureHookExcludeRuleMutex(VOID)
{
    volatile LONG *pState = (volatile LONG *)&g_HookExcludeRules.MutexInitialized;

    if (InterlockedCompareExchange(pState, 0, 0) == 2)
    {
        KeMemoryBarrier();
        return;
    }

    if (InterlockedCompareExchange(pState, 1, 0) == 0)
    {
        // WINNER: Initialize directly in-place.
        ExInitializeFastMutex(&g_HookExcludeRules.Mutex);
        
        KeMemoryBarrier();
        InterlockedExchange(pState, 2);
        return;
    }

    // FIX 2: YieldProcessor() is just a PAUSE hint - it does not yield the CPU
    // to another thread. If the winner thread is preempted or slow, every other
    // thread here burns 100% of its logical core. Replace with a real 1ms sleep.
    {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000LL; // 1ms in 100ns units
        while (InterlockedCompareExchange(pState, 0, 0) != 2)
        {
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
    }
    KeMemoryBarrier();
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

static NTSTATUS InitializeHookExcludeRules(VOID)
{
    EnsureHookExcludeRuleMutex();

    ExAcquireFastMutex(&g_HookExcludeRules.Mutex);

    // Dynamic hook exclude rules (normalized/contains match, case-insensitive)
    (VOID) AddHookExcludeRuleNormalizedUnlocked(L"C:\\Program Files\\HydraDragonAntivirus", 38);
    (VOID) AddHookExcludeRuleNormalizedUnlocked(L"C:\\ProgramData\\HydraDragonAntivirus", 37);
    (VOID) AddHookExcludeRuleNormalizedUnlocked(L"C:\\ProgramData\\edrsvc", 22);
    (VOID) AddHookExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\tasks\\hydradragonantivirus", 45);
    (VOID) AddHookExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\edrpm64.dll", 29);
    (VOID) AddHookExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\edrpm32.dll", 29);
    (VOID) AddHookExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\edrmm.dll", 27);
    (VOID) AddHookExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\drivers\\sanctum.sys", 39);
    (VOID) AddHookExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\drivers\\edrdrv.sys", 38);
    (VOID) AddHookExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\drivers\\OwlyshieldRansomFilter.sys", 55);
    (VOID) AddHookExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\drivers\\RedDbg.sys", 38);
    (VOID) AddHookExcludeRuleNormalizedUnlocked(L"C:\\Windows\\System32\\drivers\\hyperhv.sys", 39);
    (VOID) AddHookExcludeRuleNormalizedUnlocked(L"C:\\Program Files\\HydraDragonAntivirus\\hydradragon\\sanctum", 56);

    g_HookExcludeRules.Loaded = TRUE;

    ExReleaseFastMutex(&g_HookExcludeRules.Mutex);
    InterlockedExchange(&g_HookExcludeLoadState, 2);
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS SetHookExcludeRulesFromBuffer(
    _In_reads_bytes_(BytesRead) PUCHAR Buffer,
    _In_ ULONG BytesRead)
{
    if (Buffer == NULL || BytesRead == 0 || BytesRead > (256 * 1024))
        return STATUS_INVALID_PARAMETER;

    EnsureHookExcludeRuleMutex();

    ExAcquireFastMutex(&g_HookExcludeRules.Mutex);
    FreeHookExcludeRulesUnlocked();
    NTSTATUS status = AppendHookExcludeRulesFromBufferUnlocked(Buffer, BytesRead);
    g_HookExcludeRules.Loaded = NT_SUCCESS(status);
    ExReleaseFastMutex(&g_HookExcludeRules.Mutex);

    return status;
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

static SIZE_T FindPatternOffset(_In_reads_bytes_(BufferLength) const UCHAR *Buffer, _In_ SIZE_T BufferLength,
                                _In_reads_bytes_(PatternLength) const UCHAR *Pattern, _In_ SIZE_T PatternLength)
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


static NTSTATUS AddHookExcludeRuleNormalizedUnlocked(_In_reads_(RuleChars) PCWSTR RuleText, _In_ SIZE_T RuleChars)
{
    WCHAR normalizedLine[HOOK_RULE_MAX_LINE_CHARS];
    SIZE_T lineLen = 0;
    NTSTATUS status;

    if (RuleText == NULL || RuleChars == 0)
    {
        return STATUS_SUCCESS;
    }

    if (!OwlyNormalizeRuleLineForMatch(RuleText, RuleChars, normalizedLine, RTL_NUMBER_OF(normalizedLine), FALSE,
                                       &lineLen) ||
        lineLen == 0)
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

static NTSTATUS AppendHookExcludeRulesFromBufferUnlocked(_In_reads_bytes_(BytesRead) PUCHAR Buffer,
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
                    (VOID) AddHookExcludeRuleNormalizedUnlocked(&utf16Buffer[start], i - start);
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
                    (VOID) AddHookExcludeRuleNormalizedUnlocked(lineBuffer, lineLen);
                }
                start = i + 1;
            }
        }
    }

    return STATUS_SUCCESS;
}



static VOID EnsureHookExcludeRulesLoaded(VOID)
{
    return;
}

VOID ReloadHookExcludeRules(VOID)
{
    EnsureHookExcludeRuleMutex();
    ExAcquireFastMutex(&g_HookExcludeRules.Mutex);
    FreeHookExcludeRulesUnlocked();
    g_HookExcludeRules.Loaded = FALSE;
    ExReleaseFastMutex(&g_HookExcludeRules.Mutex);
    // FIX 3: Clear the back-off so an explicit reload always proceeds immediately,
    // regardless of how recently the last automatic load attempt failed.
    InterlockedExchange64((volatile LONG64 *)&g_HookExcludeFailRetryTime, 0);
    InterlockedExchange(&g_HookExcludeLoadState, 0);
    EnsureHookExcludeRulesLoaded();
}

static BOOLEAN IsNormalizedPathExcludedByHookRules(_In_ PCUNICODE_STRING NormalizedPath)
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

    EnsureHookExcludeRulesLoaded();
    EnsureHookExcludeRuleMutex();
    ExAcquireFastMutex(&g_HookExcludeRules.Mutex);
    for (ULONG i = 0; i < g_HookExcludeRules.Count; ++i)
    {
        PCWSTR rule = g_HookExcludeRules.Rules[i];
        if (rule == NULL || rule[0] == L'\0')
        {
            continue;
        }

        // Use prefix matching: the process path must START WITH the rule.
        SIZE_T ruleLen = wcslen(rule);
        SIZE_T pathChars = NormalizedPath->Length / sizeof(WCHAR);
        if (pathChars >= ruleLen && _wcsnicmp(NormalizedPath->Buffer, rule, ruleLen) == 0)
        {
            matched = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_HookExcludeRules.Mutex);

    return matched;
}

static BOOLEAN IsRegisteredOwlyshieldAppProcess(_In_ ULONG ProcessId)
{
    if (ProcessId == 0 || driverData == NULL)
    {
        return FALSE;
    }

    return (ProcessId == driverData->getPID());
}

static BOOLEAN IsAlwaysSkippedProcessForHooking(_In_ ULONG ProcessId)
{
    if (IsRegisteredOwlyshieldAppProcess(ProcessId))
    {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN IsSensitiveSystemPathForHookingProcess(_In_ PEPROCESS Process, _In_ ULONG ProcessId)
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
    if (!NT_SUCCESS(status) || processImagePath == NULL || processImagePath->Buffer == NULL ||
        processImagePath->Length == 0)
    {
        if (processImagePath != NULL)
        {
            ExFreePool(processImagePath);
        }
        return TRUE; // SKIP hooking if the process has no image path (e.g., MemCompression, minimal processes)
    }

    if (IsAlwaysSkippedProcessForHooking(ProcessId))
    {
        ExFreePool(processImagePath);
        return TRUE;
    }

    if (!OwlyNormalizePathForMatch(processImagePath, normalizedPathBuffer, &normalizedPath))
    {
        ExFreePool(processImagePath);
        return FALSE;
    }

    // No hardcoded process-path allow/deny list: rules-only.
    BOOLEAN isSensitive = IsNormalizedPathExcludedByHookRules(&normalizedPath);
    ExFreePool(processImagePath);
    return isSensitive;
}

static BOOLEAN IsExcludedAncestorProcessForHooking(_In_ PEPROCESS Process)
{
    static const ULONG kMaxAncestorDepth = 16;
    WCHAR parentPathBuffer[MAX_FILE_NAME_LENGTH] = {0};
    WCHAR parentNormalizedPathBuffer[MAX_FILE_NAME_LENGTH] = {0};
    UNICODE_STRING parentPath;
    UNICODE_STRING parentNormalizedPath;
    ULONG visitedPids[kMaxAncestorDepth] = {0};
    ULONG visitedCount = 0;
    PEPROCESS currentProcess = Process;
    BOOLEAN currentProcessReferenced = FALSE;
    BOOLEAN shouldSkip = FALSE;

    if (Process == NULL || driverData == NULL || fnPsGetProcessInheritedFromUniqueProcessId == NULL)
    {
        return FALSE;
    }

    for (;;)
    {
        HANDLE parentHandle = fnPsGetProcessInheritedFromUniqueProcessId(currentProcess);
        ULONG parentPid = (ULONG)(ULONG_PTR)parentHandle;
        BOOLEAN seenBefore = FALSE;
        PEPROCESS parentProcess = NULL;

        if (parentPid <= 4)
        {
            break;
        }

        for (ULONG i = 0; i < visitedCount; ++i)
        {
            if (visitedPids[i] == parentPid)
            {
                seenBefore = TRUE;
                break;
            }
        }

        if (seenBefore)
        {
            break;
        }

        if (visitedCount >= RTL_NUMBER_OF(visitedPids))
        {
            break;
        }
        visitedPids[visitedCount++] = parentPid;

        if (IsRegisteredOwlyshieldAppProcess(parentPid))
        {
            shouldSkip = TRUE;
            break;
        }

        RtlZeroMemory(parentPathBuffer, sizeof(parentPathBuffer));
        if (driverData->CopyProcessPathByPid(parentPid, parentPathBuffer, RTL_NUMBER_OF(parentPathBuffer)))
        {
            RtlInitUnicodeString(&parentPath, parentPathBuffer);
            if (OwlyNormalizePathForMatch(&parentPath, parentNormalizedPathBuffer, &parentNormalizedPath) &&
                IsNormalizedPathExcludedByHookRules(&parentNormalizedPath))
            {
                shouldSkip = TRUE;
                break;
            }
        }

        if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)parentPid, &parentProcess)) ||
            parentProcess == NULL)
        {
            break;
        }

        if (currentProcessReferenced)
        {
            ObDereferenceObject(currentProcess);
        }

        currentProcess = parentProcess;
        currentProcessReferenced = TRUE;
    }

    if (currentProcessReferenced)
    {
        ObDereferenceObject(currentProcess);
    }

    return shouldSkip;
}

static BOOLEAN ShouldSkipHookingProcess(_In_ PEPROCESS Process, _In_ ULONG ProcessId)
{
    if (Process == NULL)
    {
        return TRUE;
    }

    // System (PID 4) and Idle (PID 0) cannot be hooked.
    if (ProcessId <= 4)
    {
        return TRUE;
    }

    if (fnPsIsProtectedProcess != NULL)
    {
        if (fnPsIsProtectedProcess(Process))
            return TRUE;
    }

    if (fnPsIsProtectedProcessLight != NULL)
    {
        if (fnPsIsProtectedProcessLight(Process))
            return TRUE;
    }

    if (IsRegisteredOwlyshieldAppProcess(ProcessId))
    {
        return TRUE;
    }

    {
        PACCESS_TOKEN primaryToken = PsReferencePrimaryToken(Process);
        if (primaryToken != NULL)
        {
            // TokenIsAppContainer is annoyingly version-sensitive in practice:
            // some builds return a pool buffer containing a ULONG, while others
            // can surface the ULONG value directly in the out pointer slot.
            // Treat small raw values as inline scalars and only dereference/free
            // when the returned address looks like a real kernel buffer.
            PVOID tokenInfoBuffer = NULL;
            NTSTATUS tokenStatus =
                SeQueryInformationToken(primaryToken, TokenIsAppContainer, &tokenInfoBuffer);
            PsDereferencePrimaryToken(primaryToken);

            if (NT_SUCCESS(tokenStatus) && tokenInfoBuffer != NULL)
            {
                ULONG_PTR tokenInfoRaw = (ULONG_PTR)tokenInfoBuffer;
                ULONG isAppContainer = 0;
                BOOLEAN freeTokenInfoBuffer = FALSE;

                if (tokenInfoRaw <= MAXULONG)
                {
                    isAppContainer = (ULONG)tokenInfoRaw;
                }
                else
                {
                    isAppContainer = *(PULONG)tokenInfoBuffer;
                    freeTokenInfoBuffer = TRUE;
                }

                if (freeTokenInfoBuffer)
                {
                    ExFreePool(tokenInfoBuffer);
                }

                if (isAppContainer != 0)
                {
                    return TRUE;
                }
            }
        }
    }

    if (IsSensitiveSystemPathForHookingProcess(Process, ProcessId))
    {
        return TRUE;
    }

    if (IsExcludedAncestorProcessForHooking(Process))
    {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN IsSameHookConfig(_In_ const HOOK_CONFIG_DATA *A, _In_ const HOOK_CONFIG_DATA *B)
{
    ANSI_STRING aFunc;
    ANSI_STRING bFunc;

    if (A == NULL || B == NULL)
    {
        return FALSE;
    }

    RtlInitAnsiString(&aFunc, A->FunctionName);
    RtlInitAnsiString(&bFunc, B->FunctionName);

    if (_wcsicmp(A->ModuleName, B->ModuleName) != 0)
        return FALSE;
    return RtlEqualString(&aFunc, &bFunc, TRUE);
}

static BOOLEAN EqualsInsensitiveA(_In_z_ PCSTR Value, _In_z_ PCSTR Literal)
{
    ANSI_STRING valueString;
    ANSI_STRING literalString;

    if (Value == NULL || Literal == NULL)
        return FALSE;

    RtlInitAnsiString(&valueString, Value);
    RtlInitAnsiString(&literalString, Literal);
    return RtlEqualString(&valueString, &literalString, TRUE);
}

NTSTATUS AddCustomHook(_In_ PHOOK_CONFIG_DATA Config)
{
    HOOK_CONFIG_DATA normalizedConfig;

    if (Config == NULL || Config->FunctionName[0] == '\0')
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(&normalizedConfig, Config, sizeof(normalizedConfig));
    normalizedConfig.ModuleName[RTL_NUMBER_OF(normalizedConfig.ModuleName) - 1] = L'\0';
    normalizedConfig.FunctionName[RTL_NUMBER_OF(normalizedConfig.FunctionName) - 1] = '\0';

    // Accept empty module as wildcard-all-modules to avoid rejecting
    // malformed-but-recoverable usermode API labels such as "!LoadLibraryA".
    if (normalizedConfig.ModuleName[0] == L'\0')
    {
        (VOID) RtlStringCchCopyW(normalizedConfig.ModuleName, RTL_NUMBER_OF(normalizedConfig.ModuleName), L"*");
    }

    ExAcquireFastMutex(&g_ConfigMutex);

    for (ULONG i = 0; i < g_CustomHookCount; ++i)
    {
        if (IsSameHookConfig(&g_GlobalCustomHooks[i], &normalizedConfig))
        {
            if (normalizedConfig.EventId != 0)
            {
                g_GlobalCustomHooks[i].EventId = normalizedConfig.EventId;
            }
            ExReleaseFastMutex(&g_ConfigMutex);
            return STATUS_SUCCESS;
        }
    }

    if (g_CustomHookCount >= MAX_CUSTOM_HOOKS)
    {
        ExReleaseFastMutex(&g_ConfigMutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(&g_GlobalCustomHooks[g_CustomHookCount], &normalizedConfig, sizeof(HOOK_CONFIG_DATA));
    g_GlobalCustomHooks[g_CustomHookCount]
        .ModuleName[RTL_NUMBER_OF(g_GlobalCustomHooks[g_CustomHookCount].ModuleName) - 1] = L'\0';
    g_GlobalCustomHooks[g_CustomHookCount]
        .FunctionName[RTL_NUMBER_OF(g_GlobalCustomHooks[g_CustomHookCount].FunctionName) - 1] = '\0';
    if (g_GlobalCustomHooks[g_CustomHookCount].EventId == 0)
    {
        g_GlobalCustomHooks[g_CustomHookCount].EventId = 0x6000u;
    }
    g_CustomHookCount++;

    ExReleaseFastMutex(&g_ConfigMutex);
    return STATUS_SUCCESS;
}

_Success_(return != FALSE) BOOLEAN
    ResolveHookNameByEventId(_In_ ULONG EventId, _Out_writes_(MAX_FILE_NAME_LENGTH) PWCHAR OutName,
                             _In_ ULONG OutNameCch)
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
            (VOID)
                RtlStringCchPrintfW(OutName, OutNameCch, L"%ws!%ws", g_GlobalCustomHooks[i].ModuleName, functionNameW);
        }
        else
        {
            (VOID) RtlStringCchCopyW(OutName, OutNameCch, functionNameW);
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
#define HOOK_NOTIFY_IOCTL_CODE IOCTL_REPORT_HOOK_EVENT
#endif

// -------------------------------------------------------------------------
// -------------------------------------------------------------------------
// X64InstrLen
//
// Returns the byte length of the x64 instruction at p[0..maxLen-1].
// Returns 0 for unknown or truncated instructions.
// Handles all instruction classes found in real function prologues.
// -------------------------------------------------------------------------
static SIZE_T X64InstrLen(_In_reads_bytes_(maxLen) const UCHAR *p, _In_ SIZE_T maxLen)
{
    if (maxLen == 0)
        return 0;
    SIZE_T i = 0;

    BOOLEAN hasRexW = FALSE;
    BOOLEAN has66 = FALSE;
    while (i < maxLen)
    {
        UCHAR b = p[i];
        if (b == 0x66)
        {
            has66 = TRUE;
            i++;
            continue;
        }
        if (b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3)
        {
            i++;
            continue;
        }
        if (b == 0x2E || b == 0x3E || b == 0x26 || b == 0x36 || b == 0x64 || b == 0x65)
        {
            i++;
            continue;
        }
        if ((b & 0xF0) == 0x40)
        {
            hasRexW = (b & 0x08) != 0;
            i++;
            continue;
        }
        break;
    }
    if (i >= maxLen)
        return 0;
    UCHAR op = p[i++];

    // 0F two-byte escape
    if (op == 0x0F)
    {
        if (i >= maxLen)
            return 0;
        UCHAR op2 = p[i++];
        // Jcc near: 0F 80-8F rel32
        if (op2 >= 0x80 && op2 <= 0x8F)
            return i + 4;
        // No-operand: SYSCALL(05) SYSRET(07) WRMSR(30) RDMSR(32) RDTSC(31) CPUID(A2)
        if (op2 == 0x05 || op2 == 0x07 || op2 == 0x30 || op2 == 0x31 || op2 == 0x32 || op2 == 0xA2)
            return i;
        // Everything else: assume ModRM follows
        if (i >= maxLen)
            return 0;
        UCHAR modrm = p[i++];
        UCHAR mod = (modrm >> 6) & 3;
        UCHAR rm = modrm & 7;
        SIZE_T disp = 0;
        if (mod == 1)
            disp = 1;
        else if (mod == 2)
            disp = 4;
        else if (mod == 0 && rm == 5)
            disp = 4;
        if (rm == 4 && mod != 3)
        {
            if (i >= maxLen)
                return 0;
            UCHAR sib = p[i++];
            if (mod == 0 && (sib & 7) == 5)
                disp = 4;
        }
        i += disp;
        return i;
    }

    // Single-byte, no operands
    if ((op >= 0x50 && op <= 0x5F) || op == 0x90 || op == 0x9C || op == 0x9D || op == 0xC3 || op == 0xC9 || op == 0xCB)
        return i;
    // INT n
    if (op == 0xCD)
        return i + 1;
    // RET imm16
    if (op == 0xC2)
        return i + 2;
    // Short relative (EB rel8, Jcc rel8 70-7F)
    if (op == 0xEB || (op >= 0x70 && op <= 0x7F))
        return i + 1;
    // Near relative (E9 rel32, E8 rel32 CALL)
    if (op == 0xE9 || op == 0xE8)
        return i + 4;
    // MOV reg, imm8 (B0-B7)
    if (op >= 0xB0 && op <= 0xB7)
        return i + 1;
    // MOV reg, imm (B8-BF)
    if (op >= 0xB8 && op <= 0xBF)
        return i + (hasRexW ? 8 : (has66 ? 2 : 4));
    // PUSH imm
    if (op == 0x6A)
        return i + 1;
    if (op == 0x68)
        return i + 4;
    // TEST (r)AX, imm
    if (op == 0xA8)
        return i + 1;
    if (op == 0xA9)
        return i + (has66 ? 2 : 4);
    // MOV moffs (A0-A3): 64-bit absolute address
    if (op >= 0xA0 && op <= 0xA3)
        return i + 8;

    // ModRM opcodes
    {
        static const UCHAR kModrm[] = {
            0x01, 0x03, 0x09, 0x0B, 0x11, 0x13, 0x19, 0x1B, 0x21, 0x23, 0x29, 0x2B, 0x31, 0x33,
            0x39, 0x3B, 0x63, 0x69, 0x6B, 0x80, 0x81, 0x83, 0x84, 0x85, 0x87, 0x88, 0x89, 0x8B,
            0x8D, 0x8F, 0xC0, 0xC1, 0xC7, 0xD0, 0xD1, 0xD2, 0xD3, 0xF6, 0xF7, 0xFF,
        };
        BOOLEAN hm = FALSE;
        for (SIZE_T k = 0; k < RTL_NUMBER_OF(kModrm); k++)
            if (op == kModrm[k])
            {
                hm = TRUE;
                break;
            }
        if (!hm)
            return 0;

        if (i >= maxLen)
            return 0;
        UCHAR modrm = p[i++];
        UCHAR mod = (modrm >> 6) & 3;
        UCHAR reg = (modrm >> 3) & 7;
        UCHAR rm = modrm & 7;
        SIZE_T disp = 0;
        if (mod == 1)
            disp = 1;
        else if (mod == 2)
            disp = 4;
        else if (mod == 0 && rm == 5)
            disp = 4;
        if (rm == 4 && mod != 3)
        {
            if (i >= maxLen)
                return 0;
            UCHAR sib = p[i++];
            if (mod == 0 && (sib & 7) == 5)
                disp = 4;
        }
        i += disp;
        // Immediates
        if (op == 0x80 || op == 0x83 || op == 0x6B || op == 0xC0 || op == 0xC1)
            i += 1;
        else if (op == 0x81 || op == 0xC7 || op == 0x69)
            i += (has66 ? 2 : 4);
        else if (op == 0xF6 && reg == 0)
            i += 1;
        else if (op == 0xF7 && reg == 0)
            i += (hasRexW ? 4 : (has66 ? 2 : 4));
        return i;
    }
}

// -------------------------------------------------------------------------
// ComputeStolenSize64
//
// Walks the instruction stream from Code until we have accumulated at least
// USERMODE_HOOK_SIZE bytes AND are at an instruction boundary.
//
// Returns 0 (reject hook) if:
//   * an unrecognised opcode is encountered, OR
//   * no boundary is found within USERMODE_HOOK_STOLEN_MAX bytes.
// -------------------------------------------------------------------------
static SIZE_T ComputeStolenSize64(_In_reads_bytes_(USERMODE_HOOK_STOLEN_MAX) const UCHAR *Code)
{
    SIZE_T pos = 0;
    while (pos < USERMODE_HOOK_SIZE)
    {
        SIZE_T ilen = X64InstrLen(Code + pos, USERMODE_HOOK_STOLEN_MAX - pos);
        if (ilen == 0 || pos + ilen > USERMODE_HOOK_STOLEN_MAX)
            return 0;
        pos += ilen;
    }
    return pos; // first instruction boundary >= USERMODE_HOOK_SIZE
}

// FIX #4b: ContainsUnrelocatableInstructions
//
// Scans the first StolenSize bytes of a function's prologue for any
// RIP-relative instruction that CANNOT be trivially relocated.  If found,
// the hook is skipped rather than copying broken bytes into the shellcode.
//
// Handles the most common x64 patterns:
//   * REX prefix (optional) + opcode + ModRM(00_xxx_101) + disp32
//   * FF /2 CALL [RIP+d32] and FF /4 JMP [RIP+d32]
//   * EB/E9/E8 short/near relative branches (always skip - branch target
//     would also be wrong from the new VA)
//
// Returns TRUE if at least one unrelocatable instruction was found.
// -------------------------------------------------------------------------
static BOOLEAN ContainsUnrelocatableInstructions(_In_reads_bytes_(StolenSize) const UCHAR *Bytes,
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

        // Short/near relative branches - target changes at new VA.
        if (b == 0xEB || b == 0xE9 || b == 0xE8)
            return TRUE;
        if ((b & 0xF0) == 0x70) // Jcc rel8: JO/JNO/JB/JAE/JE/JNE/.../JG
            return TRUE;

        // Two-byte opcode escape (0F xx)
        if (b == 0x0F)
        {
            ++i;
            if (i >= StolenSize)
                break;
            b = Bytes[i];
            // Jcc near: 0F 80-8F rel32 - always unrelocatable.
            if (b >= 0x80 && b <= 0x8F)
                return TRUE;
            // 0F 1F etc. - check ModRM for RIP-relative
            if (i + 1 < StolenSize)
            {
                UCHAR modrm = Bytes[i + 1];
                if ((modrm & 0xC7) == 0x05) // mod=00, rm=101 = RIP-relative
                    return TRUE;
            }
            // Consume this byte and keep going (simplified)
            i += 2;
            continue;
        }

        // One-byte opcodes that may carry a RIP-relative ModRM:
        // 8x, 0x-3x (ALU), C7, FF, F6, F7, etc.
        // FIX Bug1+Bug2: Added 0xF6 and 0xF7 which were missing.  Without
        // them the scanner consumes each byte of TEST/NOT/NEG/MUL/DIV
        // instructions individually, misaligning the parser for every
        // subsequent instruction.  A misaligned parser can skip over a real
        // RIP-relative instruction and let a broken trampoline through.
        static const UCHAR kModrmOpcodes[] = {
            0x01, 0x03, 0x09, 0x0B, 0x11, 0x13, // ADD/OR/ADC/SBB
            0x21, 0x23, 0x29, 0x2B, 0x31, 0x33, // AND/SUB/XOR
            0x39, 0x3B,                         // CMP
            0x85, 0x87, 0x89, 0x8B, 0x8D,       // TEST/XCHG/MOV/LEA
            0xC7,                               // MOV r/m, imm
            0xFF,                               // INC/DEC/CALL/JMP/PUSH
            0xF6, 0xF7,                         // FIX Bug2: TEST/NOT/NEG/MUL/DIV r/m8 and r/m
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
            if ((modrm & 0xC7) == 0x05) // mod=00, rm=101 = RIP-relative
                return TRUE;

            // Estimate instruction length to advance i correctly.
            UCHAR mod = (modrm >> 6) & 0x03;
            UCHAR rm  = modrm & 0x07;
            SIZE_T instrLen = 2; // opcode + ModRM

            // FIX Bug1: A SIB byte is present whenever mod != 3 AND rm == 4,
            // regardless of whether mod is 0, 1, or 2.  The old code only
            // handled mod==0, so for mod==1 (disp8+SIB) and mod==2
            // (disp32+SIB) the SIB byte was silently dropped, advancing i
            // one byte short.  The next iteration then consumed the SIB byte
            // as if it were an opcode, potentially matching kModrmOpcodes and
            // reading the displacement bytes as a ModRM -- which could mask a
            // real RIP-relative instruction that follows.
            if (rm == 0x04 && mod != 0x03)
            {
                instrLen += 1; // SIB byte present for mod 0/1/2 when rm==4
                // For mod==0: if SIB.base == 5 there is an additional disp32.
                if (mod == 0x00 && i + 2 < StolenSize && (Bytes[i + 2] & 0x07) == 0x05)
                    instrLen += 4;
            }
            else if (mod == 0x00 && rm == 0x05)
            {
                // RIP-relative or abs disp32 (no SIB).  Already detected
                // above via the (modrm & 0xC7) == 0x05 check, but include
                // the disp32 in the length so we keep the parser aligned.
                instrLen += 4;
            }

            if (mod == 0x01)
                instrLen += 1; // +disp8
            else if (mod == 0x02)
                instrLen += 4; // +disp32

            // Opcodes that also carry an immediate.
            if (b == 0xC7)
                instrLen += 4; // imm32
            else if (b == 0xF6 && ((modrm >> 3) & 0x07) == 0)
                instrLen += 1; // TEST r/m8, imm8
            else if (b == 0xF7 && ((modrm >> 3) & 0x07) == 0)
                instrLen += 4; // TEST r/m, imm32

            i += instrLen;
            continue;
        }

        // Default: advance one byte (handles short instructions like PUSH/POP/NOP/RET)
        ++i;
    }

    return FALSE;
}

// -------------------------------------------------------------------------
// ContainsUnrelocatableInstructions32
//
// x86 (32-bit) equivalent of ContainsUnrelocatableInstructions.
//
// 32-bit mode does NOT have RIP-relative addressing, so the only genuinely
// unrelocatable instructions are those with PC-relative operands:
//   E8 rel32   CALL near        5 bytes - relative to EIP after the call
//   E9 rel32   JMP  near        5 bytes
//   EB rel8    JMP  short       2 bytes
//   70..7F cb  Jcc  short       2 bytes
//   0F 80..8F  Jcc  near        6 bytes
//
// MOV, PUSH, POP, SUB, AND, etc. are all safe regardless of position.
// Indirect call/jmp through registers or memory (FF /2, FF /4) are also
// safe because they use absolute addresses.
//
// For USERMODE_HOOK_SIZE_32 = 5 stolen bytes the check only needs to confirm
// that no relative branch starts inside the first 5 bytes.
// -------------------------------------------------------------------------
static BOOLEAN ContainsUnrelocatableInstructions32(_In_reads_bytes_(StolenSize) const UCHAR *Bytes,
                                                   _In_ SIZE_T StolenSize)
{
    SIZE_T i = 0;

    while (i < StolenSize)
    {
        UCHAR b = Bytes[i];

        // Unconditional near/short jumps and near calls - all relative.
        if (b == 0xE8 || b == 0xE9 || b == 0xEB)
            return TRUE;

        // Conditional short jumps: 70..7F (Jcc rel8)
        if ((b & 0xF0) == 0x70)
            return TRUE;

        // Two-byte escape: 0F xx
        if (b == 0x0F)
        {
            if (i + 1 >= StolenSize)
                break;
            UCHAR b2 = Bytes[i + 1];
            // 0F 80..8F: conditional near jumps (Jcc rel32)
            if ((b2 & 0xF0) == 0x80)
                return TRUE;
            // Other 0F xx are safe; advance past both bytes (simplified).
            i += 2;
            continue;
        }

        // All other instructions: advance one byte.
        // This is a deliberate simplification - it is correct for all
        // instructions we realistically expect in a function prologue (PUSH,
        // MOV, SUB, AND, NOP, etc.) and safe because any false advance at
        // most causes us to inspect the middle of a longer instruction, which
        // will not falsely match any of the patterns above.
        ++i;
    }

    return FALSE;
}

// -------------------------------------------------------------------------
// g_ShellcodeTemplate32
//
// 32-bit (WoW64) hook notification shellcode.
//
// Calling convention: the shellcode is entered via a 5-byte E9 rel32 JMP
// that replaces the first 5 bytes of the hooked function.  The CPU is in
// x86 (IA-32) compatibility mode (CS = 0x23 in the WoW64 context).
//
// Stack layout at shellcode entry (JMP already executed):
//   [ESP+0x00]  return address (pushed by the caller's CALL instruction)
//   [ESP+0x04]  arg1 of the hooked function
//   [ESP+0x08]  arg2 of the hooked function
//   ...
//
// After PUSHAD + PUSHFD + SUB ESP, 0x80 (local_base = new ESP):
//   [LB+0x00..0x07]  IoStatusBlock (8 bytes, zeroed)
//   [LB+0x08]        HOOK_EVENT_DATA.EventType   (patched: EventId)
//   [LB+0x0C]        HOOK_EVENT_DATA.ProcessId   (patched)
//   [LB+0x10]        HOOK_EVENT_DATA.FunctionName[0] = 0
//   [LB+0x50]        HOOK_EVENT_DATA.Arg1 low  32 bits (from hooked arg1)
//   [LB+0x54]        HOOK_EVENT_DATA.Arg1 high 32 bits (zero)
//   [LB+0x58]        HOOK_EVENT_DATA.Arg2 low  32 bits (from hooked arg2)
//   [LB+0x5C]        HOOK_EVENT_DATA.Arg2 high 32 bits (zero)
//   [LB+0x80]        EFLAGS
//   [LB+0x84..0xA0]  EDI, ESI, EBP, ESP_orig, EBX, EDX, ECX, EAX (PUSHAD order)
//   [LB+0xA4]        return address of the hooked call
//   [LB+0xA8]        arg1 of the hooked function
//   [LB+0xAC]        arg2 of the hooked function
//
// NtDeviceIoControlFile call (stdcall, 10 args, callee cleans 40 bytes):
//   Args are pushed right-to-left.  IoStatusBlock and InputBuffer addresses
//   are computed via LEA relative to ESP at the moment of each push, fully
//   accounting for prior pushes.
//
// PATCH SIGNATURES
//   EventId              C7 44 24 08 [11 11 11 11]  -> imm32 at +4
//   ProcessId            C7 44 24 0C [22 22 22 22]  -> imm32 at +4
//   InputBufferLength    68          [77 77 77 77]   -> imm32 at +1
//   IoControlCode        68          [66 66 66 66]   -> imm32 at +1
//   FileHandle           68          [33 33 33 33]   -> imm32 at +1
//   NtDeviceIoControlFile B8         [44 44 44 44]   -> imm32 at +1
//   ReturnJMP            E9          [55 55 55 55]   -> rel32 at +1
//   StolenBytes          5 x NOP (at offset offRet32 - USERMODE_HOOK_SIZE_32)
// -------------------------------------------------------------------------
// -------------------------------------------------------------------------
// g_ShellcodeTemplate32  (WoW64 / 32-bit process hook)
//
// RE-ENTRANCY GUARD:
//   After PUSHAD+PUSHFD+SUB ESP,0x80, loads HOOK_REENTRANCY_MAGIC_32 into
//   EBX (already saved by PUSHAD).  Reads FS:[0x14] (TEB32.NtTib.
//   ArbitraryUserPointer) into EAX and saves it at [ESP+0x78].  If EAX
//   already equals the magic, jumps (JE rel32) past the IOCTL block.
//   Otherwise sets FS:[0x14] to the magic, runs the IOCTL, then restores
//   FS:[0x14] from [ESP+0x78] before falling into the skip label.
//
// STACK LAYOUT at entry (JMP already taken, return addr on stack):
//   [LB]        = ESP after sub ESP,0x80  (LB = Local Base)
//   [LB+0x00]   IoStatusBlock (8 bytes)
//   [LB+0x08]   HOOK_EVENT_DATA.EventType    <- PATCH
//   [LB+0x0C]   HOOK_EVENT_DATA.ProcessId    <- PATCH
//   [LB+0x10]   HOOK_EVENT_DATA.FunctionName[0] = 0
//   [LB+0x50]   HOOK_EVENT_DATA.Arg1 lo
//   [LB+0x54]   HOOK_EVENT_DATA.Arg1 hi = 0
//   [LB+0x58]   HOOK_EVENT_DATA.Arg2 lo
//   [LB+0x5C]   HOOK_EVENT_DATA.Arg2 hi = 0
//   [LB+0x60]   HOOK_EVENT_DATA.Arg3 = 0
//   [LB+0x68]   HOOK_EVENT_DATA.Arg4 = 0
//   [LB+0x78]   saved old FS:[0x14]          <- NEW
//   [LB+0x80]   EFLAGS  (PUSHFD)
//   [LB+0x84]   EDI,ESI,EBP,ESP_orig,EBX,EDX,ECX,EAX  (PUSHAD, 32 bytes)
//   [LB+0xA4]   return address (caller's CALL pushed this)
//   [LB+0xA8]   arg1 of hooked function
//   [LB+0xAC]   arg2 of hooked function
//
// PATCH SIGNATURES:
//   kGuardMagicSig32  BB [88x4]             -> imm32 = HOOK_REENTRANCY_MAGIC_32
//   kJeSig32          0F 84 [00x4]          -> rel32  = offset to kSkipLabelSig32
//   kEventSig32       C7 44 24 08 [11x4]    -> imm32  = EventId
//   kPidSig32         C7 44 24 0C [22x4]    -> imm32  = ProcessId
//   kSizeSig32        68 [77x4]             -> imm32  = sizeof(HOOK_EVENT_DATA)
//   kIoctlSig32       68 [66x4]             -> imm32  = HOOK_NOTIFY_IOCTL_CODE
//   kHandleSig32      68 [33x4]             -> imm32  = DriverDeviceHandle
//   kNtIoSig32        B8 [44x4]             -> imm32  = NtDeviceIoControlFile VA
//   kSkipLabelSig32   0F 1F 00              -> (3-byte NOP - JE rel32 target)
//   kRetSig32         E9 [55x4]             -> rel32  = return target
// -------------------------------------------------------------------------
UCHAR g_ShellcodeTemplate32[] = {
    // ---- Save all GP registers and flags --------------------------------
    0x60, // pushad
    0x9C, // pushfd

    // ---- Allocate local frame: 0x80 bytes --------------------------------
    0x81, 0xEC, 0x80, 0x00, 0x00, 0x00, // sub esp, 0x80

    // ---- RE-ENTRANCY GUARD (new) -----------------------------------------
    // Load sentinel into EBX (already saved by PUSHAD at [LB+0x90]).
    // kGuardMagicSig32 = { 0xBB, 0x88, 0x88, 0x88, 0x88 }
    0xBB, 0x88, 0x88, 0x88, 0x88, // mov ebx, MAGIC32

    // Read TEB32.NtTib.ArbitraryUserPointer from FS:[0x14]
    // FS(64) A1 [14 00 00 00]  = MOV EAX, moffs32 with FS prefix (6 bytes)
    0x64, 0xA1, 0x14, 0x00, 0x00, 0x00, // mov eax, fs:[0x14]

    // Save old value so we can restore it after the IOCTL
    0x89, 0x44, 0x24, 0x78, // mov [esp+0x78], eax
    // Preserve TEB32.LastErrorValue so the helper NtDeviceIoControlFile does
    // not leak its failure state into the hooked API's caller.
    0x64, 0xA1, 0x34, 0x00, 0x00, 0x00, // mov eax, fs:[0x34]
    0x89, 0x44, 0x24, 0x7C,             // mov [esp+0x7C], eax
    // Reload the saved ArbitraryUserPointer before comparing with the
    // re-entrancy sentinel.
    0x8B, 0x44, 0x24, 0x78, // mov eax, [esp+0x78]

    // If eax == magic -> already inside shellcode, skip IOCTL
    0x3B, 0xC3, // cmp eax, ebx

    // je rel32 - kJeSig32 = { 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 }
    // rel32 patched at install time to reach kSkipLabelSig32
    0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, // je skip_notification32

    // Set guard: FS(64) 89 1D [14 00 00 00] = MOV [moffs32], EBX
    0x64, 0x89, 0x1D, 0x14, 0x00, 0x00, 0x00, // mov fs:[0x14], ebx

    // ---- Zero IoStatusBlock at [esp+0x00..0x07] -------------------------
    0x31, 0xC0,             // xor eax, eax
    0x89, 0x04, 0x24,       // mov [esp+0x00], eax
    0x89, 0x44, 0x24, 0x04, // mov [esp+0x04], eax

    // ---- Fill HOOK_EVENT_DATA at [esp+0x08] -----------------------------
    // EventType <- patched: kEventSig32
    0xC7, 0x44, 0x24, 0x08, 0x11, 0x11, 0x11, 0x11,
    // ProcessId <- patched: kPidSig32
    0xC7, 0x44, 0x24, 0x0C, 0x22, 0x22, 0x22, 0x22,
    // FunctionName[0] = '\0'
    0xC6, 0x44, 0x24, 0x10, 0x00,

    // ---- Arg1 -> HOOK_EVENT_DATA.Arg1 ------------------------------------
    // [esp+0xA8] = arg1 of hooked fn (LB+0x80=EFLAGS + 0x84..0xA0=PUSHAD + 0xA4=retaddr)
    0x8B, 0x84, 0x24, 0xA8, 0x00, 0x00, 0x00,       // mov eax, [esp+0xA8]
    0x89, 0x44, 0x24, 0x50,                         // mov [esp+0x50], eax
    0xC7, 0x44, 0x24, 0x54, 0x00, 0x00, 0x00, 0x00, // dword [esp+0x54] = 0

    // ---- Arg2 -> HOOK_EVENT_DATA.Arg2 ------------------------------------
    0x8B, 0x84, 0x24, 0xAC, 0x00, 0x00, 0x00,       // mov eax, [esp+0xAC]
    0x89, 0x44, 0x24, 0x58,                         // mov [esp+0x58], eax
    0xC7, 0x44, 0x24, 0x5C, 0x00, 0x00, 0x00, 0x00, // dword [esp+0x5C] = 0

    // ---- Arg3/Arg4 are unknown for generic hooks; keep the wire data clean
    0xC7, 0x44, 0x24, 0x60, 0x00, 0x00, 0x00, 0x00, // Arg3 low  = 0
    0xC7, 0x44, 0x24, 0x64, 0x00, 0x00, 0x00, 0x00, // Arg3 high = 0
    0xC7, 0x44, 0x24, 0x68, 0x00, 0x00, 0x00, 0x00, // Arg4 low  = 0
    0xC7, 0x44, 0x24, 0x6C, 0x00, 0x00, 0x00, 0x00, // Arg4 high = 0

    // ---- Build NtDeviceIoControlFile args (stdcall, right-to-left) ------
    // arg10: OutputBufferLength = 0
    0x6A, 0x00, // push 0               ESP=LB-4
    // arg9: OutputBuffer = NULL
    0x6A, 0x00, // push 0               ESP=LB-8
    // arg8: InputBufferLength <- patched: kSizeSig32
    0x68, 0x77, 0x77, 0x77, 0x77, //                       ESP=LB-0xC
    // arg7: InputBuffer = &HOOK_EVENT_DATA = [esp+0x14] at this point
    0x8D, 0x44, 0x24, 0x14, // lea eax,[esp+0x14]
    0x50,                   // push eax              ESP=LB-0x10
    // arg6: IoControlCode <- patched: kIoctlSig32
    0x68, 0x66, 0x66, 0x66, 0x66, //                       ESP=LB-0x14
    // arg5: &IoStatusBlock = [esp+0x14] at this point
    0x8D, 0x44, 0x24, 0x14, // lea eax,[esp+0x14]
    0x50,                   // push eax              ESP=LB-0x18
    // arg4: ApcContext = NULL
    0x6A, 0x00, //                       ESP=LB-0x1C
    // arg3: ApcRoutine = NULL
    0x6A, 0x00, //                       ESP=LB-0x20
    // arg2: Event = NULL
    0x6A, 0x00, //                       ESP=LB-0x24
    // arg1: FileHandle <- patched: kHandleSig32
    0x68, 0x33, 0x33, 0x33, 0x33, //                       ESP=LB-0x28

    // ---- Call NtDeviceIoControlFile (stdcall - callee cleans 40 bytes) --
    // Address <- patched: kNtIoSig32
    0xB8, 0x44, 0x44, 0x44, 0x44, // mov eax, imm32
    0xFF, 0xD0,                   // call eax

    // ---- Restore TEB32.LastErrorValue and re-entrancy guard -------------
    0x8B, 0x44, 0x24, 0x7C,       // mov eax, [esp+0x7C]
    0x64, 0xA3, 0x34, 0x00, 0x00, 0x00, // mov fs:[0x34], eax
    // ---- Restore re-entrancy guard (clear back to old FS:[0x14] value) --
    0x8B, 0x44, 0x24, 0x78, // mov eax, [esp+0x78]
    // FS(64) A3 [14 00 00 00] = MOV [moffs32], EAX
    0x64, 0xA3, 0x14, 0x00, 0x00, 0x00, // mov fs:[0x14], eax

    // ---- skip_notification32 label <- JE rel32 target --------------------
    // kSkipLabelSig32 = { 0x0F, 0x1F, 0x00 }  (3-byte NOP)
    0x0F, 0x1F, 0x00, // nop dword ptr [eax]

    // ---- Restore local frame and all registers --------------------------
    0x81, 0xC4, 0x80, 0x00, 0x00, 0x00, // add esp, 0x80
    0x9D,                               // popfd
    0x61,                               // popad

    // ---- 5-byte stolen-instruction placeholder --------------------------
    0x90, 0x90, 0x90, 0x90, 0x90,

    // ---- Return jump <- patched: kRetSig32 (E9 rel32) --------------------
    0xE9, 0x55, 0x55, 0x55, 0x55,

    // ---- Padding --------------------------------------------------------
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
// NtDeviceIoControlFile, leaving the rest as garbage - causing an access
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
//   RSP+0x90+0x58   HOOK_EVENT_DATA.Arg3         0
//   RSP+0x90+0x60   HOOK_EVENT_DATA.Arg4         0
//   RSP+0xF8        saved R11 ... RAX (8 * 8 = 64 bytes)
//
// Register sources (from the saved register block above RSP+0xF0):
//   saved RCX (original arg1 of hooked fn) lives at RSP + 0xF8
//   saved RDX (original arg2 of hooked fn) lives at RSP + 0x100
// -------------------------------------------------------------------------
// -------------------------------------------------------------------------
// g_ShellcodeTemplate  (native 64-bit process hook)
//
// Changes from previous version:
//   RE-ENTRANCY GUARD (NEW):
//     After allocating the frame, loads HOOK_REENTRANCY_MAGIC_64 into R10
//     (which is already saved on the stack).  Reads the current thread's
//     TEB.NtTib.ArbitraryUserPointer via GS:[0x28] and saves it at
//     [RSP+0x70].  If it already equals the magic, jumps (JE rel32) past
//     the entire IOCTL block directly to the skip_notification label.
//     Otherwise, sets GS:[0x28] to the magic, runs the IOCTL, then restores
//     GS:[0x28] from [RSP+0x70] before falling into the skip label.
//
// STACK LAYOUT (RSP = RSP_entry - 0x138 after pushes + sub):
//   [RSP+0x00..0x1F]  shadow space for NtDeviceIoControlFile
//   [RSP+0x20]        arg5:  &IO_STATUS_BLOCK  (-> RSP+0x80)
//   [RSP+0x28]        arg6:  IoControlCode     (patched)
//   [RSP+0x30]        arg7:  InputBuffer       (-> RSP+0x90)
//   [RSP+0x38]        arg8:  InputBufferLength (patched)
//   [RSP+0x40]        arg9:  OutputBuffer      NULL
//   [RSP+0x48]        arg10: OutputBufferLength 0
//   [RSP+0x50..0x6F]  (unused)
//   [RSP+0x70]        saved old TEB.ArbitraryUserPointer  <- NEW
//   [RSP+0x80..0x8F]  IO_STATUS_BLOCK
//   [RSP+0x90+0x00]   HOOK_EVENT_DATA.EventType    (patched)
//   [RSP+0x90+0x04]   HOOK_EVENT_DATA.ProcessId    (patched)
//   [RSP+0x90+0x08]   HOOK_EVENT_DATA.FunctionName[0] = 0
//   [RSP+0xD8]        HOOK_EVENT_DATA.Arg1
//   [RSP+0xE0]        HOOK_EVENT_DATA.Arg2
//   [RSP+0xE8]        HOOK_EVENT_DATA.Arg3 = 0
//   [RSP+0xF0]        HOOK_EVENT_DATA.Arg4 = 0
//   [RSP+0xF8]        saved R11  (last pushed, first popped)
//   [RSP+0x100]       saved R10
//   [RSP+0x108]       saved R9
//   [RSP+0x110]       saved R8
//   [RSP+0x118]       saved RBX
//   [RSP+0x120]       saved RDX  <- Arg2 source
//   [RSP+0x128]       saved RCX  <- Arg1 source
//   [RSP+0x130]       saved RAX
//
// PATCH SIGNATURES (searched by FindPatternOffset at install time):
//   kGuardMagicSig  49 BA [88x8]         -> imm64  = HOOK_REENTRANCY_MAGIC_64
//   kJeSig64        0F 84 [00x4]         -> rel32  = offset to kSkipLabelSig
//   kEventSig       C7 84 24 90 .. 11x4  -> imm32  = EventId
//   kPidSig         C7 84 24 94 .. 22x4  -> imm32  = ProcessId
//   kHandleSig      48 B9 [33x8]         -> imm64  = DriverDeviceHandle
//   kIoctlSig       48 B8 [66x8]         -> imm64  = HOOK_NOTIFY_IOCTL_CODE
//   kSizeSig        48 B8 [77x8]         -> imm64  = sizeof(HOOK_EVENT_DATA)
//   kNtIoSig        48 B8 [44x8]         -> imm64  = NtDeviceIoControlFile VA
//   kSkipLabelSig   0F 1F 44 00 00       -> (5-byte NOP - JE rel32 target)
//   kRetSig         48 B8 [55x8]         -> imm64  = return target VA
// -------------------------------------------------------------------------
UCHAR g_ShellcodeTemplate[] = {
    // ---- Save volatile registers ----------------------------------------
    0x50,       // push rax
    0x51,       // push rcx
    0x52,       // push rdx
    0x53,       // push rbx
    0x41, 0x50, // push r8
    0x41, 0x51, // push r9
    0x41, 0x52, // push r10
    0x41, 0x53, // push r11

    // ---- Allocate 0xF8 bytes of local frame -----------------------------
    // After 8 pushes (64 bytes) RSP%16 == 8.  sub 0xF8 (248, 8 mod 16):
    // RSP%16 -> 0 at the CALL, satisfying the x64 ABI.
    0x48, 0x81, 0xEC, 0xF8, 0x00, 0x00, 0x00, // sub rsp, 0xF8

    // ---- RE-ENTRANCY GUARD (new) ----------------------------------------
    // Load sentinel into R10 (already saved at [RSP+0x100]).
    // Placeholder 0x88... is patched with HOOK_REENTRANCY_MAGIC_64.
    // kGuardMagicSig = { 0x49,0xBA,0x88,0x88,0x88,0x88,0x88,0x88,0x88,0x88 }
    0x49, 0xBA, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, // mov r10, MAGIC  (imm64)

    // Read TEB.NtTib.ArbitraryUserPointer from GS:[0x28]
    // Encoding: GS(65) REX.W(48) 8B /r SIB(04 25) disp32
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, // mov rax, gs:[0x28]

    // Save old value so we can restore it after the IOCTL
    0x48, 0x89, 0x84, 0x24, 0x70, 0x00, 0x00, 0x00, // mov [rsp+0x70], rax
    // Preserve TEB.LastErrorValue and LastStatusValue so the helper
    // NtDeviceIoControlFile remains side-effect free for the hooked caller.
    0x65, 0x8B, 0x04, 0x25, 0x68, 0x00, 0x00, 0x00, // mov eax, gs:[0x68]
    0x89, 0x84, 0x24, 0x78, 0x00, 0x00, 0x00,       // mov [rsp+0x78], eax
    0x65, 0x8B, 0x04, 0x25, 0x50, 0x12, 0x00, 0x00, // mov eax, gs:[0x1250]
    0x89, 0x84, 0x24, 0x7C, 0x00, 0x00, 0x00,       // mov [rsp+0x7C], eax
    // Reload the saved ArbitraryUserPointer before comparing with the
    // re-entrancy sentinel.
    0x48, 0x8B, 0x84, 0x24, 0x70, 0x00, 0x00, 0x00, // mov rax, [rsp+0x70]

    // If rax == magic -> already inside shellcode on this thread, skip IOCTL
    // cmp rax, r10  -> REX.WB(49) 3B C2
    0x49, 0x3B, 0xC2, // cmp rax, r10

    // je rel32 - kJeSig64 = { 0x0F,0x84,0x00,0x00,0x00,0x00 }
    // rel32 patched at install time to reach kSkipLabelSig
    0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, // je skip_notification

    // Set guard: mark this thread as inside our shellcode
    // mov gs:[0x28], r10  -> GS(65) REX.WR(4C) 89 SIB(14 25) disp32
    0x65, 0x4C, 0x89, 0x14, 0x25, 0x28, 0x00, 0x00, 0x00, // mov gs:[0x28], r10

    // ---- Zero IO_STATUS_BLOCK at RSP+0x80 --------------------------------
    0x48, 0x31, 0xC0,                               // xor rax, rax
    0x48, 0x89, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, // mov [rsp+0x80], rax
    0x48, 0x89, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00, // mov [rsp+0x88], rax

    // ---- Fill HOOK_EVENT_DATA (starts at RSP+0x90) -----------------------
    // EventType at RSP+0x90  <- patched: kEventSig
    0xC7, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, 0x11, 0x11, 0x11, 0x11,
    // ProcessId at RSP+0x94 <- patched: kPidSig
    0xC7, 0x84, 0x24, 0x94, 0x00, 0x00, 0x00, 0x22, 0x22, 0x22, 0x22,
    // FunctionName[0] = '\0'
    0xC6, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00, 0x00,

    // ---- Copy original RCX (arg1) -> HOOK_EVENT_DATA.Arg1 at RSP+0xD8 ----
    // Register save layout after sub rsp,0xF8:
    //   r11=[RSP+0xF8] r10=[RSP+0x100] r9=[RSP+0x108] r8=[RSP+0x110]
    //   rbx=[RSP+0x118] rdx=[RSP+0x120] rcx=[RSP+0x128] rax=[RSP+0x130]
    0x48, 0x8B, 0x84, 0x24, 0x28, 0x01, 0x00, 0x00, // mov rax,[rsp+0x128] <- RCX
    0x48, 0x89, 0x84, 0x24, 0xD8, 0x00, 0x00, 0x00, // mov [rsp+0xD8],rax -> Arg1

    // ---- Copy original RDX (arg2) -> HOOK_EVENT_DATA.Arg2 at RSP+0xE0 ----
    0x48, 0x8B, 0x84, 0x24, 0x20, 0x01, 0x00, 0x00, // mov rax,[rsp+0x120] <- RDX
    0x48, 0x89, 0x84, 0x24, 0xE0, 0x00, 0x00, 0x00, // mov [rsp+0xE0],rax -> Arg2

    // ---- Arg3/Arg4 are not reliably known for generic hooks -------------
    0x48, 0x31, 0xC0,                               // xor rax, rax
    0x48, 0x89, 0x84, 0x24, 0xE8, 0x00, 0x00, 0x00, // mov [rsp+0xE8],rax -> Arg3
    0x48, 0x89, 0x84, 0x24, 0xF0, 0x00, 0x00, 0x00, // mov [rsp+0xF0],rax -> Arg4

    // ---- Build NtDeviceIoControlFile argument frame ----------------------
    // RCX = FileHandle <- patched: kHandleSig
    0x48, 0xB9, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    // RDX = Event = NULL
    0x31, 0xD2, // xor edx, edx
    // R8 = ApcRoutine = NULL
    0x45, 0x31, 0xC0, // xor r8d, r8d
    // R9 = ApcContext = NULL
    0x45, 0x31, 0xC9, // xor r9d, r9d
    // arg5 [rsp+0x20] = &IoStatusBlock
    0x48, 0x8D, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, // lea rax,[rsp+0x80]
    0x48, 0x89, 0x44, 0x24, 0x20,                   // mov [rsp+0x20], rax
    // arg6 [rsp+0x28] = IoControlCode <- patched: kIoctlSig
    0x48, 0xB8, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x48, 0x89, 0x44, 0x24, 0x28, // mov [rsp+0x28], rax
    // arg7 [rsp+0x30] = InputBuffer = &HOOK_EVENT_DATA
    0x48, 0x8D, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, // lea rax,[rsp+0x90]
    0x48, 0x89, 0x44, 0x24, 0x30,                   // mov [rsp+0x30], rax
    // arg8 [rsp+0x38] = InputBufferLength <- patched: kSizeSig
    0x48, 0xB8, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x48, 0x89, 0x44, 0x24, 0x38, // mov [rsp+0x38], rax
    // arg9 [rsp+0x40] = NULL, arg10 [rsp+0x48] = 0
    0x48, 0x31, 0xC0,             // xor rax, rax
    0x48, 0x89, 0x44, 0x24, 0x40, // mov [rsp+0x40], rax
    0x48, 0x89, 0x44, 0x24, 0x48, // mov [rsp+0x48], rax

    // ---- Call NtDeviceIoControlFile <- patched: kNtIoSig -----------------
    0x48, 0xB8, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0xFF, 0xD0, // call rax

    // ---- Restore TEB error/status and re-entrancy guard ------------------
    0x8B, 0x84, 0x24, 0x7C, 0x00, 0x00, 0x00,       // mov eax, [rsp+0x7C]
    0x65, 0x89, 0x04, 0x25, 0x50, 0x12, 0x00, 0x00, // mov gs:[0x1250], eax
    0x8B, 0x84, 0x24, 0x78, 0x00, 0x00, 0x00,       // mov eax, [rsp+0x78]
    0x65, 0x89, 0x04, 0x25, 0x68, 0x00, 0x00, 0x00, // mov gs:[0x68], eax
    // Restores the old TEB.ArbitraryUserPointer value saved at [RSP+0x70].
    // This correctly handles the case where the field was non-zero before we
    // set the sentinel (e.g. the CRT had its own value there).
    0x48, 0x8B, 0x84, 0x24, 0x70, 0x00, 0x00, 0x00, // mov rax, [rsp+0x70]
    // mov gs:[0x28], rax -> GS(65) REX.W(48) 89 SIB(04 25) disp32
    0x65, 0x48, 0x89, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, // mov gs:[0x28], rax

    // ---- skip_notification label <- JE rel32 target ----------------------
    // kSkipLabelSig = { 0x0F,0x1F,0x44,0x00,0x00 }
    // 5-byte NOP: nop dword ptr [rax+rax*1+0h]
    // On the re-entrant path the JE jumps here, bypassing the IOCTL entirely.
    // On the normal path execution falls through from the guard restore above.
    0x0F, 0x1F, 0x44, 0x00, 0x00, // (5-byte NPAD)

    // ---- Restore local space and registers ------------------------------
    0x48, 0x81, 0xC4, 0xF8, 0x00, 0x00, 0x00, // add rsp, 0xF8
    0x41, 0x5B,                               // pop r11
    0x41, 0x5A,                               // pop r10
    0x41, 0x59,                               // pop r9
    0x41, 0x58,                               // pop r8
    0x5B,                                     // pop rbx
    0x5A,                                     // pop rdx
    0x59,                                     // pop rcx
    0x58,                                     // pop rax

    // ---- 28-byte stolen-instruction placeholder -------------------------
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

    // ---- Return jump <- patched: kRetSig ---------------------------------
    // jmp qword ptr [rip+0] followed by the 8-byte address
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,

    // ---- Padding --------------------------------------------------------
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90};

//
// Initialize the user-mode hooking engine
//

NTSTATUS UserModeHookEngineInitialize(VOID)
{
    
#if IS_DEBUG_IRP
DbgPrint("!!! UserModeHook: Initializing user-mode hooking engine...\n");
#endif

    NTSTATUS status;

    // ---------------------------------------------------------------------
    // FIX: Resolve system routines dynamically to avoid Linker Errors
    // ---------------------------------------------------------------------
    UNICODE_STRING routineName;

    // Resolve ZwProtectVirtualMemory
    RtlInitUnicodeString(&routineName, L"ZwProtectVirtualMemory");
    fnZwProtectVirtualMemory = (PZW_PROTECT_VIRTUAL_MEMORY)MmGetSystemRoutineAddress(&routineName);

    if (!fnZwProtectVirtualMemory)
    {
        
#if IS_DEBUG_IRP
DbgPrint("!!! UserModeHook: Failed to resolve ZwProtectVirtualMemory\n");
#endif

        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // Resolve PsGetProcessPeb
    RtlInitUnicodeString(&routineName, L"PsGetProcessPeb");
    fnPsGetProcessPeb = (PPS_GET_PROCESS_PEB)MmGetSystemRoutineAddress(&routineName);

    if (!fnPsGetProcessPeb)
    {
        
#if IS_DEBUG_IRP
DbgPrint("!!! UserModeHook: Failed to resolve PsGetProcessPeb\n");
#endif

        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // Resolve ZwAllocateVirtualMemory
    RtlInitUnicodeString(&routineName, L"ZwAllocateVirtualMemory");
    fnZwAllocateVirtualMemory = (PZW_ALLOCATE_VIRTUAL_MEMORY)MmGetSystemRoutineAddress(&routineName);
    if (!fnZwAllocateVirtualMemory)
    {
        
#if IS_DEBUG_IRP
DbgPrint("!!! UserModeHook: Failed to resolve ZwAllocateVirtualMemory\n");
#endif

    }

    // Resolve ZwFreeVirtualMemory
    RtlInitUnicodeString(&routineName, L"ZwFreeVirtualMemory");
    fnZwFreeVirtualMemory = (PZW_FREE_VIRTUAL_MEMORY)MmGetSystemRoutineAddress(&routineName);
    // FIX 2a: original code checked !fnZwDuplicateObject here instead of !fnZwFreeVirtualMemory.
    if (!fnZwFreeVirtualMemory)
    {
        
#if IS_DEBUG_IRP
DbgPrint("!!! UserModeHook: Failed to resolve ZwFreeVirtualMemory\n");
#endif

    }

    // Resolve ZwSetInformationObject - used to protect the per-process hook
    // device handle from user-mode close sanitizers such as browser sandboxes.
    RtlInitUnicodeString(&routineName, L"ZwSetInformationObject");
    fnZwSetInformationObject = (PZW_SET_INFORMATION_OBJECT)MmGetSystemRoutineAddress(&routineName);

    RtlInitUnicodeString(&routineName, L"IoFileObjectType");
    g_HookIoFileObjectType = (POBJECT_TYPE *)MmGetSystemRoutineAddress(&routineName);

    // Resolve optional process protection helpers (best-effort).
    RtlInitUnicodeString(&routineName, L"PsIsProtectedProcess");
    fnPsIsProtectedProcess = (PPS_IS_PROTECTED_PROCESS)MmGetSystemRoutineAddress(&routineName);
    RtlInitUnicodeString(&routineName, L"PsIsProtectedProcessLight");
    fnPsIsProtectedProcessLight = (PPS_IS_PROTECTED_PROCESS_LIGHT)MmGetSystemRoutineAddress(&routineName);
    RtlInitUnicodeString(&routineName, L"PsGetProcessInheritedFromUniqueProcessId");
    fnPsGetProcessInheritedFromUniqueProcessId =
        (PPS_GET_PROCESS_INHERITED_FROM_UNIQUE_PROCESS_ID)MmGetSystemRoutineAddress(&routineName);

    // Resolve PsGetProcessWow64Process - used to detect WoW64 processes and
    // obtain their PEB32 pointer.  Best-effort: if unavailable (e.g., on very
    // old kernels), WoW64 hooking is disabled and only 64-bit processes are
    // hooked.
    RtlInitUnicodeString(&routineName, L"PsGetProcessWow64Process");
    fnPsGetProcessWow64Process = (PPS_GET_PROCESS_WOW64_PROCESS)MmGetSystemRoutineAddress(&routineName);
    if (!fnPsGetProcessWow64Process)
    {
        
#if IS_DEBUG_IRP
DbgPrint("!!! UserModeHook: PsGetProcessWow64Process unavailable - WoW64 hooking disabled\n");
#endif

    }

    {
        UNICODE_STRING devName;
        OBJECT_ATTRIBUTES oa;
        IO_STATUS_BLOCK ioStatus;

        RtlInitUnicodeString(&devName, L"\\Device\\OwlyshieldHook");
        InitializeObjectAttributes(&oa, &devName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        RtlZeroMemory(&ioStatus, sizeof(ioStatus));

        status = ZwCreateFile(&g_HookNotifyMasterHandle,
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
        if (!NT_SUCCESS(status))
        {
            g_HookNotifyMasterHandle = NULL;
            
#if IS_DEBUG_IRP
DbgPrint("!!! UserModeHook: ZwCreateFile master notify handle failed 0x%X\n", status);
#endif

            return status;
        }
    }

    // ---------------------------------------------------------------------
    // Allocate Engine
    // ---------------------------------------------------------------------

    g_UserHookEngine =
        (PUSERMODE_HOOK_ENGINE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(USERMODE_HOOK_ENGINE), 'UMHk');

    if (g_UserHookEngine == NULL)
    {
        ZwClose(g_HookNotifyMasterHandle);
        g_HookNotifyMasterHandle = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_UserHookEngine, sizeof(USERMODE_HOOK_ENGINE));
    ExInitializeFastMutex(&g_UserHookEngine->EngineMutex);
    ExInitializeFastMutex(&g_ConfigMutex);
    g_CustomHookCount = 0;
    RtlZeroMemory(g_GlobalCustomHooks, sizeof(g_GlobalCustomHooks));
    g_UserHookEngine->IsInitialized = TRUE;

    (VOID)InitializeHookExcludeRules();

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

    g_HookEngineShuttingDown = TRUE;

    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);

    for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++)
    {
        if (g_UserHookEngine->Processes[i].IsHooked && g_UserHookEngine->Processes[i].ProcessId != 0 &&
            hookedPidCount < MAX_HOOKED_PROCESSES)
        {
            hookedPids[hookedPidCount++] = g_UserHookEngine->Processes[i].ProcessId;
        }
    }

    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);

    for (ULONG i = 0; i < hookedPidCount; ++i)
    {
        (VOID) UserModeUnhookProcess(hookedPids[i]);
    }

    // FIX: wait up to 1 s for IsInProgress threads to finish.
    // Slots with IsInProgress=TRUE were not in the IsHooked list above
    // and were therefore skipped.  They will call UserModeUnhookProcess
    // themselves via NeedsCleanup, or we force-release below.
    for (ULONG spin = 0; spin < 100; spin++)
    {
        BOOLEAN anyInProgress = FALSE;
        ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);
        for (ULONG j = 0; j < MAX_HOOKED_PROCESSES; j++)
        {
            if (g_UserHookEngine->Processes[j].IsInProgress)
            {
                anyInProgress = TRUE;
                break;
            }
        }
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
        if (!anyInProgress)
            break;
        LARGE_INTEGER w;
        w.QuadPart = -10LL * 1000LL * 10LL; // 10 ms
        KeDelayExecutionThread(KernelMode, FALSE, &w);
    }

    // Final pass: force-release any surviving ProcessObject refs and
    // CustomHooks allocations so ExFreePoolWithTag below does not leave
    // dangling PEPROCESS refs that keep zombie objects alive after unload.
    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);
    for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++)
    {
        PPROCESS_HOOK_ENTRY e = &g_UserHookEngine->Processes[i];
        if (e->CustomHooks != NULL)
        {
            ExFreePoolWithTag(e->CustomHooks, 'cHuM');
            e->CustomHooks = NULL;
        }
        if (e->ProcessObject != NULL)
        {
            ObDereferenceObject(e->ProcessObject);
            e->ProcessObject = NULL;
        }
    }
    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);

    ExAcquireFastMutex(&g_ConfigMutex);
    g_CustomHookCount = 0;
    RtlZeroMemory(g_GlobalCustomHooks, sizeof(g_GlobalCustomHooks));
    ExReleaseFastMutex(&g_ConfigMutex);

    EnsureHookExcludeRuleMutex();
    ExAcquireFastMutex(&g_HookExcludeRules.Mutex);
    FreeHookExcludeRulesUnlocked();
    g_HookExcludeRules.Loaded = FALSE;
    ExReleaseFastMutex(&g_HookExcludeRules.Mutex);
    // FIX 3: Reset back-off timer so a fresh driver load can load rules immediately.
    InterlockedExchange64((volatile LONG64 *)&g_HookExcludeFailRetryTime, 0);
    InterlockedExchange(&g_HookExcludeLoadState, 0);

    if (g_HookNotifyMasterHandle != NULL)
    {
        ZwClose(g_HookNotifyMasterHandle);
        g_HookNotifyMasterHandle = NULL;
    }

    ExFreePoolWithTag(g_UserHookEngine, 'UMHk');
    g_UserHookEngine = NULL;
    g_HookEngineShuttingDown = FALSE;
}

//
// Find module base address
//

PVOID FindModuleBaseAddress(_In_ PEPROCESS Process, _In_ PCWSTR ModuleName, _Out_opt_ PSIZE_T ModuleSize)
{
    PVOID moduleBase = NULL;
    UNICODE_STRING targetModuleName;

    RtlInitUnicodeString(&targetModuleName, ModuleName);

    if (ModuleSize != NULL)
        *ModuleSize = 0;

    __try
    {
        if (fnPsGetProcessPeb == NULL)
            return NULL;

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
                ULONG safetyCounter = 0;

                while (listEntry != listHead && safetyCounter++ < 1024)
                {
                    ProbeForRead(listEntry, sizeof(LIST_ENTRY), sizeof(PVOID));

                    PLDR_DATA_TABLE_ENTRY ldrEntry =
                        CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                    ProbeForRead(ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), 1);

                    if (ldrEntry->BaseDllName.Buffer && ldrEntry->BaseDllName.Length > 0)
                    {
                        UNICODE_STRING currentBaseName;

                        ProbeForRead(ldrEntry->BaseDllName.Buffer, ldrEntry->BaseDllName.Length, sizeof(WCHAR));
                        currentBaseName.Length = ldrEntry->BaseDllName.Length;
                        currentBaseName.MaximumLength = ldrEntry->BaseDllName.Length;
                        currentBaseName.Buffer = ldrEntry->BaseDllName.Buffer;

                        if (RtlEqualUnicodeString(&currentBaseName, &targetModuleName, TRUE))
                        {
                            moduleBase = ldrEntry->DllBase;
                            if (ModuleSize)
                                *ModuleSize = ldrEntry->SizeOfImage;
                            break;
                        }
                    }
                    listEntry = ldrEntry->InLoadOrderLinks.Flink;
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

static BOOLEAN IsMainExecutableHookModule(_In_opt_z_ PCWSTR ModuleName)
{
    return ModuleName != NULL && _wcsicmp(ModuleName, L"exe") == 0;
}

static PVOID FindMainImageBaseAddress(_In_ PEPROCESS Process, _Out_opt_ PSIZE_T ModuleSize)
{
    PVOID moduleBase = NULL;

    if (ModuleSize != NULL)
        *ModuleSize = 0;

    __try
    {
        if (fnPsGetProcessPeb == NULL)
            return NULL;

        PPEB peb = fnPsGetProcessPeb(Process);
        if (peb == NULL)
            return NULL;

        ProbeForRead(peb, sizeof(PEB), 1);
        PPEB_LDR_DATA ldr = (PPEB_LDR_DATA)peb->Ldr;
        if (ldr == NULL)
            return NULL;

        ProbeForRead(ldr, sizeof(PEB_LDR_DATA), 1);
        PLIST_ENTRY listHead = &ldr->InLoadOrderModuleList;
        PLIST_ENTRY listEntry = listHead->Flink;
        if (listEntry == NULL || listEntry == listHead)
            return NULL;

        ProbeForRead(listEntry, sizeof(LIST_ENTRY), sizeof(PVOID));
        PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        ProbeForRead(ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), 1);

        moduleBase = ldrEntry->DllBase;
        if (ModuleSize != NULL)
            *ModuleSize = ldrEntry->SizeOfImage;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        moduleBase = NULL;
        if (ModuleSize != NULL)
            *ModuleSize = 0;
    }

    return moduleBase;
}

//
// Find exported function
//

#define USERMODE_HOOK_MAX_FORWARDER_DEPTH 8

static BOOLEAN ReadNullTerminatedAnsiString(_In_ PCSTR Source, _Out_writes_(DestinationCount) PCHAR Destination,
                                            _In_ SIZE_T DestinationCount)
{
    if (Source == NULL || Destination == NULL || DestinationCount < 2)
        return FALSE;

    __try
    {
        for (SIZE_T i = 0; i < DestinationCount - 1; ++i)
        {
            ProbeForRead((PVOID)(Source + i), 1, 1);
            Destination[i] = Source[i];
            if (Destination[i] == '\0')
                return TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Destination[0] = '\0';
        return FALSE;
    }

    Destination[0] = '\0';
    return FALSE;
}

_Success_(return != FALSE) static BOOLEAN
    ParseForwarderString(_In_ PCSTR ForwarderString, _Out_writes_(ModuleNameCch) PWSTR ModuleNameW,
                         _In_ SIZE_T ModuleNameCch, _Out_writes_(ExportNameCch) PCHAR ExportNameA,
                         _In_ SIZE_T ExportNameCch)
{
    CHAR forwarder[256];
    LONG splitIndex = -1;
    SIZE_T forwarderLen = 0;
    SIZE_T moduleLen = 0;
    BOOLEAN hasDotInModuleName = FALSE;

    if (ModuleNameW == NULL || ExportNameA == NULL || ModuleNameCch < RTL_NUMBER_OF(L".dll") + 1 || ExportNameCch < 2)
    {
        return FALSE;
    }

    ModuleNameW[0] = L'\0';
    ExportNameA[0] = '\0';

    if (!ReadNullTerminatedAnsiString(ForwarderString, forwarder, RTL_NUMBER_OF(forwarder)))
        return FALSE;

    forwarderLen = strlen(forwarder);
    if (forwarderLen < 3)
        return FALSE;

    for (LONG i = (LONG)forwarderLen - 1; i >= 0; --i)
    {
        if (forwarder[i] == '.')
        {
            splitIndex = i;
            break;
        }
    }

    if (splitIndex <= 0 || (SIZE_T)(splitIndex + 1) >= forwarderLen)
        return FALSE;

    moduleLen = (SIZE_T)splitIndex;
    for (SIZE_T i = 0; i < moduleLen; ++i)
    {
        if (forwarder[i] == '.')
        {
            hasDotInModuleName = TRUE;
            break;
        }
    }

    if ((forwarderLen - ((SIZE_T)splitIndex + 1) + 1) > ExportNameCch)
        return FALSE;

    for (SIZE_T i = 0; i < moduleLen; ++i)
    {
        if (i + 1 >= ModuleNameCch)
            return FALSE;
        ModuleNameW[i] = (WCHAR)(UCHAR)forwarder[i];
    }
    ModuleNameW[moduleLen] = L'\0';

    if (!hasDotInModuleName)
    {
        if (!NT_SUCCESS(RtlStringCchCatW(ModuleNameW, ModuleNameCch, L".dll")))
            return FALSE;
    }

    if (!NT_SUCCESS(RtlStringCchCopyA(ExportNameA, ExportNameCch, forwarder + splitIndex + 1)))
        return FALSE;

    return TRUE;
}

static PVOID FindExportedFunctionDirect(_In_ PVOID ModuleBase, _In_opt_z_ PCSTR FunctionName, _In_ USHORT Ordinal,
                                        _In_ BOOLEAN ResolveByOrdinal, _Out_opt_ PCSTR *ForwarderString)
{
    PVOID functionAddress = NULL;
    SIZE_T targetLen = 0;

    if (ForwarderString != NULL)
        *ForwarderString = NULL;

    if (ModuleBase == NULL)
        return NULL;

    if (!ResolveByOrdinal)
    {
        if (FunctionName == NULL)
            return NULL;

        targetLen = strlen(FunctionName);
        if (targetLen == 0 || targetLen > 255)
            return NULL;
    }

    __try
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
        ProbeForRead(dosHeader, sizeof(IMAGE_DOS_HEADER), 1);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return NULL;

        if (dosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER) || dosHeader->e_lfanew > 0x10000000UL)
            return NULL;

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleBase + dosHeader->e_lfanew);
        ProbeForRead(ntHeaders, sizeof(IMAGE_NT_HEADERS), 1);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            return NULL;

        ULONG exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG exportDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        if (exportDirRva == 0 || exportDirSize < sizeof(IMAGE_EXPORT_DIRECTORY))
            return NULL;

        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + exportDirRva);
        ProbeForRead(exportDir, sizeof(IMAGE_EXPORT_DIRECTORY), 1);

        if (exportDir->NumberOfFunctions == 0)
            return NULL;

        PULONG addressOfFunctions = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfFunctions);
        ProbeForRead(addressOfFunctions, (SIZE_T)exportDir->NumberOfFunctions * sizeof(ULONG), sizeof(ULONG));

        ULONG funcRva = 0;

        if (ResolveByOrdinal)
        {
            if ((ULONG)Ordinal < exportDir->Base)
                return NULL;

            ULONG functionIndex = (ULONG)Ordinal - exportDir->Base;
            if (functionIndex >= exportDir->NumberOfFunctions)
                return NULL;

            funcRva = addressOfFunctions[functionIndex];
        }
        else
        {
            if (exportDir->NumberOfNames == 0)
                return NULL;

            PULONG addressOfNames = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfNames);
            PUSHORT addressOfNameOrdinals = (PUSHORT)((PUCHAR)ModuleBase + exportDir->AddressOfNameOrdinals);

            ProbeForRead(addressOfNames, (SIZE_T)exportDir->NumberOfNames * sizeof(ULONG), sizeof(ULONG));
            ProbeForRead(addressOfNameOrdinals, (SIZE_T)exportDir->NumberOfNames * sizeof(USHORT), sizeof(USHORT));

            for (ULONG i = 0; i < exportDir->NumberOfNames; i++)
            {
                ULONG nameRva = addressOfNames[i];
                if (nameRva == 0)
                    continue;

                PCSTR currentName = (PCSTR)((PUCHAR)ModuleBase + nameRva);
                ProbeForRead((PVOID)currentName, targetLen + 1, 1);

                if (strncmp(currentName, FunctionName, targetLen + 1) == 0)
                {
                    USHORT ordinalIndex = addressOfNameOrdinals[i];
                    if (ordinalIndex >= exportDir->NumberOfFunctions)
                        break;

                    funcRva = addressOfFunctions[ordinalIndex];
                    break;
                }
            }
        }

        if (funcRva == 0)
            return NULL;

        if (funcRva >= exportDirRva && funcRva < exportDirRva + exportDirSize)
        {
            if (ForwarderString != NULL)
            {
                *ForwarderString = (PCSTR)((PUCHAR)ModuleBase + funcRva);
            }
            return NULL;
        }

        functionAddress = (PVOID)((PUCHAR)ModuleBase + funcRva);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        functionAddress = NULL;
        if (ForwarderString != NULL)
            *ForwarderString = NULL;
    }
    return functionAddress;
}

PVOID FindExportedFunction(_In_ PVOID ModuleBase, _In_ PCSTR FunctionName)
{
    return FindExportedFunctionDirect(ModuleBase, FunctionName, 0, FALSE, NULL);
}

static PVOID FindExportedFunctionResolvedInternal(_In_ PEPROCESS Process, _In_ PVOID ModuleBase,
                                                  _In_opt_z_ PCSTR FunctionName, _In_ USHORT Ordinal,
                                                  _In_ BOOLEAN ResolveByOrdinal, _In_ ULONG ForwarderDepth)
{
    PCSTR forwarderString = NULL;
    PVOID functionAddress =
        FindExportedFunctionDirect(ModuleBase, FunctionName, Ordinal, ResolveByOrdinal, &forwarderString);

    if (functionAddress != NULL || forwarderString == NULL || ForwarderDepth >= USERMODE_HOOK_MAX_FORWARDER_DEPTH)
    {
        return functionAddress;
    }

    WCHAR forwardedModuleName[128];
    CHAR forwardedExportName[128];
    if (!ParseForwarderString(forwarderString, forwardedModuleName, RTL_NUMBER_OF(forwardedModuleName),
                              forwardedExportName, RTL_NUMBER_OF(forwardedExportName)))
    {
        return NULL;
    }

    PVOID forwardedModuleBase = FindModuleBaseAddress(Process, forwardedModuleName, NULL);
    if (forwardedModuleBase == NULL)
        return NULL;

    if (forwardedExportName[0] == '#' && forwardedExportName[1] != '\0')
    {
        ULONG ordinalValue = 0;
        if (!NT_SUCCESS(RtlCharToInteger(forwardedExportName + 1, 10, &ordinalValue)) || ordinalValue > 0xFFFFUL)
        {
            return NULL;
        }

        return FindExportedFunctionResolvedInternal(Process, forwardedModuleBase, NULL, (USHORT)ordinalValue, TRUE,
                                                    ForwarderDepth + 1);
    }

    return FindExportedFunctionResolvedInternal(Process, forwardedModuleBase, forwardedExportName, 0, FALSE,
                                                ForwarderDepth + 1);
}

PVOID FindExportedFunctionResolved(_In_ PEPROCESS Process, _In_ PVOID ModuleBase, _In_ PCSTR FunctionName)
{
    return FindExportedFunctionResolvedInternal(Process, ModuleBase, FunctionName, 0, FALSE, 0);
}

// -------------------------------------------------------------------------
// FindModuleBaseAddress32
//
// Resolves a module's 32-bit base address in a WoW64 process by walking
// the 32-bit PEB's LDR list.  Must be called from within a
// KeStackAttachProcess context for the target process.
//
// Key difference from FindModuleBaseAddress: uses PsGetProcessWow64Process
// to obtain the PEB32 (not PsGetProcessPeb which returns PEB64), and casts
// all inter-node pointers through ULONG (32-bit) rather than PVOID (64-bit).
// -------------------------------------------------------------------------
PVOID FindModuleBaseAddress32(_In_ PEPROCESS Process, _In_ PCWSTR ModuleName, _Out_opt_ PSIZE_T ModuleSize)
{
    PVOID moduleBase = NULL;
    UNICODE_STRING targetModuleName;

    RtlInitUnicodeString(&targetModuleName, ModuleName);

    if (ModuleSize != NULL)
        *ModuleSize = 0;

    if (fnPsGetProcessWow64Process == NULL)
        return NULL;

    __try
    {
        // PsGetProcessWow64Process returns the PEB32 pointer (as PVOID on x64).
        // Returns NULL for native 64-bit processes.
        PEB32 *peb32 = (PEB32 *)fnPsGetProcessWow64Process(Process);
        if (peb32 == NULL)
            return NULL;

        ProbeForRead(peb32, sizeof(PEB32), 1);

        if (peb32->Ldr == 0)
            return NULL;

        PEB_LDR_DATA32 *ldr = (PEB_LDR_DATA32 *)(ULONG_PTR)peb32->Ldr;
        ProbeForRead(ldr, sizeof(PEB_LDR_DATA32), 1);

        // Compute the address of the list head (InLoadOrderModuleList inside the
        // LDR structure) so we know when we have looped back to the start.
        ULONG listHeadAddr = peb32->Ldr + (ULONG)FIELD_OFFSET(PEB_LDR_DATA32, InLoadOrderModuleList);
        ULONG entryAddr = ldr->InLoadOrderModuleList.Flink;

        ULONG safetyCounter = 0;
        while (entryAddr != listHeadAddr && entryAddr != 0 && safetyCounter++ < 1024)
        {
            // All 32-bit pointers are stored as ULONG; cast through ULONG_PTR
            // to suppress sign-extension warnings on x64.
            LDR_DATA_TABLE_ENTRY32 *entry = (LDR_DATA_TABLE_ENTRY32 *)(ULONG_PTR)entryAddr;

            ProbeForRead(entry, sizeof(LDR_DATA_TABLE_ENTRY32), 1);

            if (entry->BaseDllName.Buffer != 0 && entry->BaseDllName.Length > 0)
            {
                PWSTR nameBuffer = (PWSTR)(ULONG_PTR)entry->BaseDllName.Buffer;
                UNICODE_STRING currentBaseName;

                // The 32-bit LDR stores a counted UNICODE_STRING32.  Do not call
                // _wcsicmp on it: that assumes NUL termination and can read past
                // the probed buffer into an unmapped page, faulting with
                // STATUS_ACCESS_VIOLATION.  Compare as counted strings instead.
                ProbeForRead(nameBuffer, entry->BaseDllName.Length, sizeof(WCHAR));
                currentBaseName.Length = (USHORT)entry->BaseDllName.Length;
                currentBaseName.MaximumLength = (USHORT)entry->BaseDllName.Length;
                currentBaseName.Buffer = nameBuffer;

                if (RtlEqualUnicodeString(&currentBaseName, &targetModuleName, TRUE))
                {
                    moduleBase = (PVOID)(ULONG_PTR)entry->DllBase;
                    if (ModuleSize != NULL)
                        *ModuleSize = (SIZE_T)entry->SizeOfImage;
                    break;
                }
            }

            entryAddr = entry->InLoadOrderLinks.Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        moduleBase = NULL;
    }

    return moduleBase;
}

static PVOID FindMainImageBaseAddress32(_In_ PEPROCESS Process, _Out_opt_ PSIZE_T ModuleSize)
{
    PVOID moduleBase = NULL;

    if (ModuleSize != NULL)
        *ModuleSize = 0;

    if (fnPsGetProcessWow64Process == NULL)
        return NULL;

    __try
    {
        PEB32 *peb32 = (PEB32 *)fnPsGetProcessWow64Process(Process);
        if (peb32 == NULL)
            return NULL;

        ProbeForRead(peb32, sizeof(PEB32), 1);
        if (peb32->Ldr == 0)
            return NULL;

        PEB_LDR_DATA32 *ldr = (PEB_LDR_DATA32 *)(ULONG_PTR)peb32->Ldr;
        ProbeForRead(ldr, sizeof(PEB_LDR_DATA32), 1);

        ULONG listHeadAddr = peb32->Ldr + (ULONG)FIELD_OFFSET(PEB_LDR_DATA32, InLoadOrderModuleList);
        ULONG entryAddr = ldr->InLoadOrderModuleList.Flink;
        if (entryAddr == 0 || entryAddr == listHeadAddr)
            return NULL;

        LDR_DATA_TABLE_ENTRY32 *entry = (LDR_DATA_TABLE_ENTRY32 *)(ULONG_PTR)entryAddr;
        ProbeForRead(entry, sizeof(LDR_DATA_TABLE_ENTRY32), 1);

        moduleBase = (PVOID)(ULONG_PTR)entry->DllBase;
        if (ModuleSize != NULL)
            *ModuleSize = (SIZE_T)entry->SizeOfImage;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        moduleBase = NULL;
        if (ModuleSize != NULL)
            *ModuleSize = 0;
    }

    return moduleBase;
}

// -------------------------------------------------------------------------
// FindExportedFunction32
//
// Resolves an exported symbol from a 32-bit PE image mapped in the current
// (attached) process's address space.  The image was compiled as PE32 so its
// NT headers are IMAGE_NT_HEADERS32, not the 64-bit variant that the compiler
// would produce for IMAGE_NT_HEADERS on an x64 build.
//
// Must be called from within a KeStackAttachProcess context.
// -------------------------------------------------------------------------
static PVOID FindExportedFunction32Direct(_In_ PVOID ModuleBase, _In_opt_z_ PCSTR FunctionName, _In_ USHORT Ordinal,
                                          _In_ BOOLEAN ResolveByOrdinal, _Out_opt_ PCSTR *ForwarderString)
{
    PVOID functionAddress = NULL;
    SIZE_T targetLen = 0;

    if (ForwarderString != NULL)
        *ForwarderString = NULL;

    if (ModuleBase == NULL)
        return NULL;

    if (!ResolveByOrdinal)
    {
        if (FunctionName == NULL)
            return NULL;

        targetLen = strlen(FunctionName);
        if (targetLen == 0 || targetLen > 255)
            return NULL;
    }

    __try
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
        ProbeForRead(dosHeader, sizeof(IMAGE_DOS_HEADER), 1);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return NULL;

        if (dosHeader->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) || dosHeader->e_lfanew > 0x10000000L)
            return NULL;

        PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((PUCHAR)ModuleBase + dosHeader->e_lfanew);
        ProbeForRead(ntHeaders, sizeof(IMAGE_NT_HEADERS32), 1);

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            return NULL;

        if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            return NULL;

        ULONG exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG exportDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        if (exportDirRva == 0 || exportDirSize < sizeof(IMAGE_EXPORT_DIRECTORY))
            return NULL;

        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + exportDirRva);
        ProbeForRead(exportDir, sizeof(IMAGE_EXPORT_DIRECTORY), 1);

        if (exportDir->NumberOfFunctions == 0)
            return NULL;

        PULONG addressOfFunctions = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfFunctions);
        ProbeForRead(addressOfFunctions, (SIZE_T)exportDir->NumberOfFunctions * sizeof(ULONG), sizeof(ULONG));

        ULONG funcRva = 0;

        if (ResolveByOrdinal)
        {
            if ((ULONG)Ordinal < exportDir->Base)
                return NULL;

            ULONG functionIndex = (ULONG)Ordinal - exportDir->Base;
            if (functionIndex >= exportDir->NumberOfFunctions)
                return NULL;

            funcRva = addressOfFunctions[functionIndex];
        }
        else
        {
            if (exportDir->NumberOfNames == 0)
                return NULL;

            PULONG addressOfNames = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfNames);
            PUSHORT addressOfNameOrdinals = (PUSHORT)((PUCHAR)ModuleBase + exportDir->AddressOfNameOrdinals);

            ProbeForRead(addressOfNames, (SIZE_T)exportDir->NumberOfNames * sizeof(ULONG), sizeof(ULONG));
            ProbeForRead(addressOfNameOrdinals, (SIZE_T)exportDir->NumberOfNames * sizeof(USHORT), sizeof(USHORT));

            for (ULONG i = 0; i < exportDir->NumberOfNames; i++)
            {
                ULONG nameRva = addressOfNames[i];
                if (nameRva == 0)
                    continue;

                PCSTR currentName = (PCSTR)((PUCHAR)ModuleBase + nameRva);
                ProbeForRead((PVOID)currentName, targetLen + 1, 1);

                if (strncmp(currentName, FunctionName, targetLen + 1) == 0)
                {
                    USHORT ordinalIndex = addressOfNameOrdinals[i];
                    if (ordinalIndex >= exportDir->NumberOfFunctions)
                        break;

                    funcRva = addressOfFunctions[ordinalIndex];
                    break;
                }
            }
        }

        if (funcRva == 0)
            return NULL;

        if (funcRva >= exportDirRva && funcRva < exportDirRva + exportDirSize)
        {
            if (ForwarderString != NULL)
            {
                *ForwarderString = (PCSTR)((PUCHAR)ModuleBase + funcRva);
            }
            return NULL;
        }

        functionAddress = (PVOID)((PUCHAR)ModuleBase + funcRva);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        functionAddress = NULL;
        if (ForwarderString != NULL)
            *ForwarderString = NULL;
    }

    return functionAddress;
}

PVOID FindExportedFunction32(_In_ PVOID ModuleBase, _In_ PCSTR FunctionName)
{
    return FindExportedFunction32Direct(ModuleBase, FunctionName, 0, FALSE, NULL);
}

static PVOID FindExportedFunction32ResolvedInternal(_In_ PEPROCESS Process, _In_ PVOID ModuleBase,
                                                    _In_opt_z_ PCSTR FunctionName, _In_ USHORT Ordinal,
                                                    _In_ BOOLEAN ResolveByOrdinal, _In_ ULONG ForwarderDepth)
{
    PCSTR forwarderString = NULL;
    PVOID functionAddress =
        FindExportedFunction32Direct(ModuleBase, FunctionName, Ordinal, ResolveByOrdinal, &forwarderString);

    if (functionAddress != NULL || forwarderString == NULL || ForwarderDepth >= USERMODE_HOOK_MAX_FORWARDER_DEPTH)
    {
        return functionAddress;
    }

    WCHAR forwardedModuleName[128];
    CHAR forwardedExportName[128];
    if (!ParseForwarderString(forwarderString, forwardedModuleName, RTL_NUMBER_OF(forwardedModuleName),
                              forwardedExportName, RTL_NUMBER_OF(forwardedExportName)))
    {
        return NULL;
    }

    PVOID forwardedModuleBase = FindModuleBaseAddress32(Process, forwardedModuleName, NULL);
    if (forwardedModuleBase == NULL)
        return NULL;

    if (forwardedExportName[0] == '#' && forwardedExportName[1] != '\0')
    {
        ULONG ordinalValue = 0;
        if (!NT_SUCCESS(RtlCharToInteger(forwardedExportName + 1, 10, &ordinalValue)) || ordinalValue > 0xFFFFUL)
        {
            return NULL;
        }

        return FindExportedFunction32ResolvedInternal(Process, forwardedModuleBase, NULL, (USHORT)ordinalValue, TRUE,
                                                      ForwarderDepth + 1);
    }

    return FindExportedFunction32ResolvedInternal(Process, forwardedModuleBase, forwardedExportName, 0, FALSE,
                                                  ForwarderDepth + 1);
}

PVOID FindExportedFunction32Resolved(_In_ PEPROCESS Process, _In_ PVOID ModuleBase, _In_ PCSTR FunctionName)
{
    return FindExportedFunction32ResolvedInternal(Process, ModuleBase, FunctionName, 0, FALSE, 0);
}

static BOOLEAN IsAsciiHexDigit(_In_ CHAR ch)
{
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

static UCHAR AsciiHexValue(_In_ CHAR ch)
{
    if (ch >= '0' && ch <= '9')
        return (UCHAR)(ch - '0');
    if (ch >= 'a' && ch <= 'f')
        return (UCHAR)(ch - 'a' + 10);
    if (ch >= 'A' && ch <= 'F')
        return (UCHAR)(ch - 'A' + 10);
    return 0xFF;
}

static CHAR AsciiLower(_In_ CHAR ch)
{
    if (ch >= 'A' && ch <= 'Z')
        return (CHAR)(ch - 'A' + 'a');
    return ch;
}

static BOOLEAN StartsWithInsensitiveA(_In_z_ PCSTR Text, _In_z_ PCSTR Prefix)
{
    if (Text == NULL || Prefix == NULL)
        return FALSE;

    while (*Prefix != '\0')
    {
        if (*Text == '\0' || AsciiLower(*Text) != AsciiLower(*Prefix))
            return FALSE;
        ++Text;
        ++Prefix;
    }

    return TRUE;
}

static BOOLEAN IsNumericAddressLiteralA(_In_z_ PCSTR Text)
{
    PCSTR p = Text;

    if (p == NULL || *p == '\0')
        return FALSE;

    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        p += 2;

    if (*p == '\0')
        return FALSE;

    while (*p != '\0')
    {
        if (*p == 'h' || *p == 'H')
            return p[1] == '\0' && p != Text;
        if (!IsAsciiHexDigit(*p))
            return FALSE;
        ++p;
    }

    return TRUE;
}

static BOOLEAN ParseUnsigned64A(_In_z_ PCSTR Text, _In_ BOOLEAN ForceHex, _Out_ PULONGLONG Value)
{
    PCSTR p = Text;
    SIZE_T len = 0;
    ULONG base = ForceHex ? 16 : 10;
    ULONGLONG value = 0;

    if (Text == NULL || Value == NULL)
        return FALSE;

    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
    {
        base = 16;
        p += 2;
    }

    len = strlen(p);
    if (len == 0)
        return FALSE;

    if (p[len - 1] == 'h' || p[len - 1] == 'H')
    {
        base = 16;
        --len;
        if (len == 0)
            return FALSE;
    }
    else if (!ForceHex)
    {
        for (SIZE_T i = 0; i < len; ++i)
        {
            if ((p[i] >= 'a' && p[i] <= 'f') || (p[i] >= 'A' && p[i] <= 'F'))
            {
                base = 16;
                break;
            }
        }
    }

    for (SIZE_T i = 0; i < len; ++i)
    {
        UCHAR digit = AsciiHexValue(p[i]);
        if (digit == 0xFF || digit >= base)
            return FALSE;
        if (value > ((((ULONGLONG)~0ULL) - digit) / base))
            return FALSE;
        value = value * base + digit;
    }

    *Value = value;
    return TRUE;
}

static NTSTATUS ReadPreferredImageBase64(_In_ PVOID ModuleBase, _Out_ PULONGLONG PreferredImageBase)
{
    if (PreferredImageBase == NULL)
        return STATUS_INVALID_PARAMETER;

    *PreferredImageBase = 0;
    if (ModuleBase == NULL)
        return STATUS_INVALID_PARAMETER;

    __try
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
        ProbeForRead(dosHeader, sizeof(IMAGE_DOS_HEADER), 1);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return STATUS_INVALID_IMAGE_FORMAT;
        if (dosHeader->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) || dosHeader->e_lfanew > 0x10000000L)
            return STATUS_INVALID_IMAGE_FORMAT;

        PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + dosHeader->e_lfanew);
        ProbeForRead(ntHeaders, sizeof(IMAGE_NT_HEADERS64), 1);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE ||
            ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        *PreferredImageBase = ntHeaders->OptionalHeader.ImageBase;
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }
}

static NTSTATUS ReadPreferredImageBase32(_In_ PVOID ModuleBase, _Out_ PULONGLONG PreferredImageBase)
{
    if (PreferredImageBase == NULL)
        return STATUS_INVALID_PARAMETER;

    *PreferredImageBase = 0;
    if (ModuleBase == NULL)
        return STATUS_INVALID_PARAMETER;

    __try
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
        ProbeForRead(dosHeader, sizeof(IMAGE_DOS_HEADER), 1);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return STATUS_INVALID_IMAGE_FORMAT;
        if (dosHeader->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) || dosHeader->e_lfanew > 0x10000000L)
            return STATUS_INVALID_IMAGE_FORMAT;

        PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((PUCHAR)ModuleBase + dosHeader->e_lfanew);
        ProbeForRead(ntHeaders, sizeof(IMAGE_NT_HEADERS32), 1);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE ||
            ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        *PreferredImageBase = ntHeaders->OptionalHeader.ImageBase;
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }
}

static NTSTATUS ResolveHookAddressValue(_In_ PVOID ModuleBase, _In_ SIZE_T ModuleSize, _In_ ULONGLONG PreferredImageBase,
                                        _In_ ULONGLONG Value, _In_ BOOLEAN TreatAsRva, _Out_ PVOID *ResolvedAddress)
{
    ULONGLONG moduleSize64 = (ULONGLONG)ModuleSize;
    ULONGLONG loadedBase = (ULONGLONG)(ULONG_PTR)ModuleBase;
    ULONGLONG rva = 0;

    if (ResolvedAddress == NULL)
        return STATUS_INVALID_PARAMETER;
    *ResolvedAddress = NULL;

    if (ModuleBase == NULL || ModuleSize == 0)
        return STATUS_INVALID_PARAMETER;

    if (TreatAsRva || Value < moduleSize64)
    {
        rva = Value;
    }
    else if (PreferredImageBase != 0 && Value >= PreferredImageBase &&
             (Value - PreferredImageBase) < moduleSize64)
    {
        rva = Value - PreferredImageBase;
    }
    else if (Value >= loadedBase && (Value - loadedBase) < moduleSize64)
    {
        rva = Value - loadedBase;
    }
    else
    {
        return STATUS_INVALID_ADDRESS;
    }

    if (rva == 0 || rva >= moduleSize64 || rva > (ULONGLONG)((SIZE_T)~0))
        return STATUS_INVALID_ADDRESS;

    __try
    {
        PVOID address = (PVOID)((PUCHAR)ModuleBase + (SIZE_T)rva);
        ProbeForRead(address, 1, 1);
        *ResolvedAddress = address;
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }
}

static NTSTATUS ResolveHookAddressSpecifier(_In_ PVOID ModuleBase, _In_ SIZE_T ModuleSize, _In_z_ PCSTR FunctionName,
                                            _In_ BOOLEAN IsWow64, _Out_ PVOID *ResolvedAddress)
{
    PCSTR valueText = FunctionName;
    BOOLEAN treatAsRva = FALSE;
    BOOLEAN forceHex = FALSE;
    BOOLEAN isAddressSpec = FALSE;
    ULONGLONG value = 0;
    ULONGLONG preferredImageBase = 0;

    if (ResolvedAddress == NULL)
        return STATUS_INVALID_PARAMETER;
    *ResolvedAddress = NULL;

    if (FunctionName == NULL || FunctionName[0] == '\0')
        return STATUS_NOT_FOUND;

    if (StartsWithInsensitiveA(FunctionName, "rva:"))
    {
        valueText = FunctionName + 4;
        treatAsRva = TRUE;
        forceHex = TRUE;
        isAddressSpec = TRUE;
    }
    else if (StartsWithInsensitiveA(FunctionName, "rva+"))
    {
        valueText = FunctionName + 4;
        treatAsRva = TRUE;
        forceHex = TRUE;
        isAddressSpec = TRUE;
    }
    else if (StartsWithInsensitiveA(FunctionName, "rva_"))
    {
        valueText = FunctionName + 4;
        treatAsRva = TRUE;
        forceHex = TRUE;
        isAddressSpec = TRUE;
    }
    else if (FunctionName[0] == '+')
    {
        valueText = FunctionName + 1;
        treatAsRva = TRUE;
        forceHex = TRUE;
        isAddressSpec = TRUE;
    }
    else if (StartsWithInsensitiveA(FunctionName, "sub_"))
    {
        valueText = FunctionName + 4;
        forceHex = TRUE;
        isAddressSpec = TRUE;
    }
    else if (StartsWithInsensitiveA(FunctionName, "loc_"))
    {
        valueText = FunctionName + 4;
        forceHex = TRUE;
        isAddressSpec = TRUE;
    }
    else if (StartsWithInsensitiveA(FunctionName, "j_"))
    {
        valueText = FunctionName + 2;
        forceHex = TRUE;
        isAddressSpec = TRUE;
    }
    else if (IsNumericAddressLiteralA(FunctionName))
    {
        isAddressSpec = TRUE;
    }

    if (!isAddressSpec)
        return STATUS_NOT_FOUND;

    if (!ParseUnsigned64A(valueText, forceHex, &value))
        return STATUS_INVALID_PARAMETER;

    if (!treatAsRva)
    {
        NTSTATUS imageStatus = IsWow64 ? ReadPreferredImageBase32(ModuleBase, &preferredImageBase)
                                       : ReadPreferredImageBase64(ModuleBase, &preferredImageBase);
        if (!NT_SUCCESS(imageStatus))
        {
            preferredImageBase = 0;
        }
    }

    return ResolveHookAddressValue(ModuleBase, ModuleSize, preferredImageBase, value, treatAsRva, ResolvedAddress);
}

// FIX #5: InstallUsermodeHook previously discarded the Process parameter
// via UNREFERENCED_PARAMETER and unconditionally called ZwCurrentProcess().
// When invoked from outside a KeStackAttachProcess context this resolves to
// the System process (PID 4), which does not map any user-mode address.
// ZwProtectVirtualMemory then rejects the request with STATUS_INVALID_PARAMETER.
//
// The fix replaces the PEPROCESS parameter with an explicit HANDLE that the
// caller must obtain while already attached to the target process (or pass
// ZwCurrentProcess() when calling from within KeStackAttachProcess).  This
// makes the calling convention self-documenting and prevents silent misuse.
//
// Callers that used PEPROCESS must now call this from within a
// KeStackAttachProcess / KeUnstackDetachProcess bracket and pass
// ZwCurrentProcess() as ProcessHandle.
NTSTATUS InstallUsermodeHook(_In_ HANDLE ProcessHandle, _In_ PVOID TargetAddress, _In_ PVOID DetourAddress,
                             _Out_writes_bytes_(USERMODE_HOOK_SIZE) PUCHAR OriginalBytes)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID baseAddress = TargetAddress;
    SIZE_T regionSize = USERMODE_HOOK_SIZE;
    ULONG oldProtect = 0;
    ULONG newProtect = PAGE_EXECUTE_READWRITE;

    if (!DetourAddress || !TargetAddress || !OriginalBytes)
        return STATUS_INVALID_PARAMETER;

    if (!fnZwProtectVirtualMemory)
        return STATUS_NOT_SUPPORTED;

    
#if IS_DEBUG_IRP
DbgPrint("!!! UserModeHook: Hooking %p -> Detour %p\n", TargetAddress, DetourAddress);
#endif


    __try
    {
        // 1. Change protection to RWX so we can write the JMP patch.
        //    Use the caller-supplied ProcessHandle (not ZwCurrentProcess()
        //    blindly) so the protection change targets the correct process.
        status = fnZwProtectVirtualMemory(ProcessHandle, &baseAddress, &regionSize, newProtect, &oldProtect);
        if (!NT_SUCCESS(status))
        {
            
#if IS_DEBUG_IRP
DbgPrint("!!! UserModeHook: Protect failed: 0x%X\n", status);
#endif

            __leave;
        }

        // 2. Save original bytes.
        ProbeForRead(TargetAddress, USERMODE_HOOK_SIZE, 1);
        RtlCopyMemory(OriginalBytes, TargetAddress, USERMODE_HOOK_SIZE);

        // 3. Build hook shellcode: FF 25 00 00 00 00 [8-byte absolute address]
        UCHAR hookShellcode[USERMODE_HOOK_SIZE];
        hookShellcode[0] = 0xFF;
        hookShellcode[1] = 0x25;
        *(PULONG)(&hookShellcode[2]) = 0x00000000;
        *(PVOID *)(&hookShellcode[6]) = DetourAddress;

        // 4. Write hook bytes.
        ProbeForWrite(TargetAddress, USERMODE_HOOK_SIZE, 1);
        RtlCopyMemory(TargetAddress, hookShellcode, USERMODE_HOOK_SIZE);

        // 5. Restore original protection.
        //    oldProtect may have been modified by the kernel (rounded page);
        //    baseAddress / regionSize likewise - that is intentional and
        //    correct for the restore call.
        fnZwProtectVirtualMemory(ProcessHandle, &baseAddress, &regionSize, oldProtect, &oldProtect);
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
NTSTATUS InjectSingleHook(_In_ PEPROCESS Process, _In_ ULONG ProcessId, _Inout_ PPROCESS_HOOK_ENTRY HookEntry,
                          _Inout_ PHOOK_DEF HookDef, _In_ ULONG EventId, _In_ PVOID TargetNtDeviceIo)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(Process);

    if (!HookDef->Address)
        return STATUS_INVALID_PARAMETER;
    if (HookDef->IsHooked)
        return STATUS_SUCCESS; // Already hooked

    // Do not build shellcode unless the per-process notify path is usable.
    // If this handle is NULL/stale, patching it into shellcode guarantees
    // NtDeviceIoControlFile will return STATUS_INVALID_HANDLE in the target.
    if (HookEntry == NULL || HookEntry->DriverDeviceHandle == NULL ||
        HookEntry->ShellcodeBase == NULL || HookEntry->ShellcodeSize == 0 ||
        TargetNtDeviceIo == NULL)
    {
#if IS_DEBUG_IRP
        DbgPrint("UserModeHook: PID %lu skipping hook at %p - notify infrastructure unavailable\n",
                 ProcessId, HookDef->Address);
#endif
        // This is a target-process hook support problem, not a failure of the
        // user-mode communication port that requested the hook.  Do not let it
        // escape as STATUS_INVALID_HANDLE or FilterSendMessage callers will
        // mistake it for a stale driver handle and reconnect needlessly.
        return STATUS_NOT_SUPPORTED;
    }

    // Determine the actual steal size: minimum number of complete x64
    // instructions that covers USERMODE_HOOK_SIZE (14) bytes.  A fixed
    // 14-byte steal cuts the Windows 10+ ntdll syscall stub mid-instruction
    // (the TEST byte ptr [0x7FFE0308],1 instruction is 8 bytes starting at
    // offset 8, so bytes 9-14 are a partial instruction).  Executing those
    // partial bytes from a different VA causes an access violation that kills
    // every hooked syscall: file closes fail, I/O stops, processes hang.
    SIZE_T stolenSize = 0;
    {
        UCHAR prologue[USERMODE_HOOK_STOLEN_MAX] = {0};
        __try
        {
            ProbeForRead(HookDef->Address, USERMODE_HOOK_STOLEN_MAX, 1);
            RtlCopyMemory(prologue, HookDef->Address, USERMODE_HOOK_STOLEN_MAX);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: ProbeForRead faulted at %p - skipping hook\n", HookDef->Address);
#endif

            return STATUS_ACCESS_VIOLATION;
        }

        stolenSize = ComputeStolenSize64(prologue);
        if (stolenSize == 0)
        {
            
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: Skipping %p - no instruction boundary within %u bytes\n", HookDef->Address,
                     (ULONG)USERMODE_HOOK_STOLEN_MAX);
#endif

            return STATUS_NOT_SUPPORTED;
        }

        BOOLEAN unrelocatable = ContainsUnrelocatableInstructions(prologue, stolenSize);
        if (unrelocatable)
        {
            
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: Skipping %p - stolen bytes contain relative branch\n", HookDef->Address);
#endif

            return STATUS_NOT_SUPPORTED;
        }
    }

    // Calculate Offset
    if (HookEntry->ShellcodeUsed + sizeof(g_ShellcodeTemplate) > HookEntry->ShellcodeSize)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PVOID myShellcodeAddress = (PVOID)((ULONG_PTR)HookEntry->ShellcodeBase + HookEntry->ShellcodeUsed);

    // 1. Prepare Shellcode (Copy and Patch by signature to avoid fragile hardcoded offsets)
    UCHAR shellcode[sizeof(g_ShellcodeTemplate)];
    RtlCopyMemory(shellcode, g_ShellcodeTemplate, sizeof(shellcode));

    {
        // Updated signatures matching the corrected shellcode template
        static const UCHAR kGuardMagicSig[] = {0x49, 0xBA, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88};
        static const UCHAR kJeSig64[] = {0x0F, 0x84, 0x00, 0x00, 0x00, 0x00};
        static const UCHAR kSkipLabelSig[] = {0x0F, 0x1F, 0x44, 0x00, 0x00};
        static const UCHAR kEventSig[] = {0xC7, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, 0x11, 0x11, 0x11, 0x11};
        static const UCHAR kPidSig[] = {0xC7, 0x84, 0x24, 0x94, 0x00, 0x00, 0x00, 0x22, 0x22, 0x22, 0x22};
        static const UCHAR kHandleSig[] = {0x48, 0xB9, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33};
        static const UCHAR kIoctlSig[] = {0x48, 0xB8, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
        static const UCHAR kSizeSig[] = {0x48, 0xB8, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77};
        static const UCHAR kNtIoSig[] = {0x48, 0xB8, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44};
        // Updated the signature to match the new 14-byte JMP pattern
        static const UCHAR kRetSig[] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};

        SIZE_T offGuardMagic = FindPatternOffset(shellcode, sizeof(shellcode), kGuardMagicSig, sizeof(kGuardMagicSig));
        SIZE_T offJe64 = FindPatternOffset(shellcode, sizeof(shellcode), kJeSig64, sizeof(kJeSig64));
        SIZE_T offSkipLabel = FindPatternOffset(shellcode, sizeof(shellcode), kSkipLabelSig, sizeof(kSkipLabelSig));
        SIZE_T offEvent = FindPatternOffset(shellcode, sizeof(shellcode), kEventSig, sizeof(kEventSig));
        SIZE_T offPid = FindPatternOffset(shellcode, sizeof(shellcode), kPidSig, sizeof(kPidSig));
        SIZE_T offHandle = FindPatternOffset(shellcode, sizeof(shellcode), kHandleSig, sizeof(kHandleSig));
        SIZE_T offIoctl = FindPatternOffset(shellcode, sizeof(shellcode), kIoctlSig, sizeof(kIoctlSig));
        SIZE_T offSize = FindPatternOffset(shellcode, sizeof(shellcode), kSizeSig, sizeof(kSizeSig));
        SIZE_T offNtIo = FindPatternOffset(shellcode, sizeof(shellcode), kNtIoSig, sizeof(kNtIoSig));
        SIZE_T offRet = FindPatternOffset(shellcode, sizeof(shellcode), kRetSig, sizeof(kRetSig));

        if (offGuardMagic == (SIZE_T)-1 || offJe64 == (SIZE_T)-1 || offSkipLabel == (SIZE_T)-1 ||
            offEvent == (SIZE_T)-1 || offPid == (SIZE_T)-1 || offHandle == (SIZE_T)-1 || offIoctl == (SIZE_T)-1 ||
            offSize == (SIZE_T)-1 || offNtIo == (SIZE_T)-1 || offRet == (SIZE_T)-1 || offRet < USERMODE_HOOK_STOLEN_MAX)
        {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        // Patch re-entrancy guard magic (imm64 starting at kGuardMagicSig+2)
        *(PULONG64)(shellcode + offGuardMagic + 2) = HOOK_REENTRANCY_MAGIC_64;

        // Patch JE rel32: target = kSkipLabelSig, source = kJeSig64+6
        // rel32 = offSkipLabel - (offJe64 + 6)
        *(PLONG)(shellcode + offJe64 + 2) = (LONG)(offSkipLabel - (offJe64 + 6));

        // Patch EventId - ULONG at instruction+7 (mov dword ptr [rsp+0x90], imm32)
        *(PULONG)(shellcode + offEvent + 7) = EventId;

        // Patch ProcessId - ULONG at instruction+7
        *(PULONG)(shellcode + offPid + 7) = ProcessId;

        // Patch FileHandle - HANDLE (8 bytes) at mov rcx, imm64 offset+2
        *(PHANDLE)(shellcode + offHandle + 2) = HookEntry->DriverDeviceHandle;

        // Patch IoControlCode - store as ULONG64 in the mov rax, imm64 slot
        *(PULONG64)(shellcode + offIoctl + 2) = (ULONG64)HOOK_NOTIFY_IOCTL_CODE;

        // Patch InputBufferLength - sizeof(HOOK_EVENT_DATA) as ULONG64
        *(PULONG64)(shellcode + offSize + 2) = (ULONG64)sizeof(HOOK_EVENT_DATA);

        // Patch NtDeviceIoControlFile address
        *(PVOID *)(shellcode + offNtIo + 2) = TargetNtDeviceIo;

        // Save first USERMODE_HOOK_SIZE bytes for unhook (the JMP patch area).
        // Embed stolenSize bytes in the shellcode trampoline.
        // Both use memory we already read into prologue[] above.
        // Re-read via ProbeForRead in case the page was remapped.

        // FIX Bug5: Defensive bounds check.  ComputeStolenSize64 guarantees
        // stolenSize <= USERMODE_HOOK_STOLEN_MAX, but assert here so that any
        // future regression (e.g. a caller that bypasses ComputeStolenSize64)
        // returns a clean error instead of silently overwriting the kRetSig
        // bytes that immediately follow the placeholder in the shellcode.
        if (stolenSize == 0 || stolenSize > USERMODE_HOOK_STOLEN_MAX)
        {
            
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: stolenSize %zu out of range [1,%u] at %p - refusing hook\n",
                     stolenSize, (ULONG)USERMODE_HOOK_STOLEN_MAX, HookDef->Address);
#endif

            return STATUS_INVALID_PARAMETER;
        }

        __try
        {
            ProbeForRead(HookDef->Address, stolenSize, 1);
            // OriginalBytes: only needs USERMODE_HOOK_SIZE bytes (unhook restores the JMP)
            RtlCopyMemory(HookDef->OriginalBytes, HookDef->Address, USERMODE_HOOK_SIZE);
            // Trampoline: embed stolenSize bytes in the placeholder
            //   placeholder starts at (offRet - USERMODE_HOOK_STOLEN_MAX)
            RtlCopyMemory(shellcode + (offRet - USERMODE_HOOK_STOLEN_MAX), HookDef->Address, stolenSize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return STATUS_ACCESS_VIOLATION;
        }

        // Patch return target to original function + actual stolen bytes
        // Notice the offset is now +6 because the 8-byte address sits 6 bytes into the signature
        *(PVOID *)(shellcode + offRet + 6) = (PVOID)((ULONG_PTR)HookDef->Address + stolenSize);
    }

    // Write Shellcode to Target at specific offset.
    // myShellcodeAddress is user-mode memory - must be guarded.
    __try
    {
        ProbeForWrite(myShellcodeAddress, sizeof(shellcode), 1);
        RtlCopyMemory(myShellcodeAddress, shellcode, sizeof(shellcode));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_ACCESS_VIOLATION;
    }

    // 2. Install Hook (JMP to Shellcode)
    {
        PVOID pageAddr = HookDef->Address;
        SIZE_T pageSize = 14;
        ULONG oldProt = 0;

        if (!fnZwProtectVirtualMemory)
            return STATUS_NOT_SUPPORTED;

        // FIX #2: Before calling ZwProtectVirtualMemory, verify that the
        // entire 14-byte patch region lies within a single committed VAD
        // region.  ZwProtectVirtualMemory returns STATUS_INVALID_PARAMETER
        // when the supplied range spans two VAD nodes with different types
        // or ownership (which is common for SEC_IMAGE .text / .rdata
        // boundaries).  Querying first lets us bail cleanly rather than
        // propagating an opaque INVALID_PARAMETER upward.
        {
            MEMORY_BASIC_INFORMATION mbi;
            RtlZeroMemory(&mbi, sizeof(mbi));
            SIZE_T retLen = 0;
            NTSTATUS qst = ZwQueryVirtualMemory(ZwCurrentProcess(), HookDef->Address, MemoryBasicInformation, &mbi,
                                                sizeof(mbi), &retLen);
            if (!NT_SUCCESS(qst))
            {
                
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: ZwQueryVirtualMemory failed 0x%X for %p\n", qst, HookDef->Address);
#endif

                return qst;
            }
            if (mbi.State != MEM_COMMIT)
            {
                
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: Target %p is not in a committed region\n", HookDef->Address);
#endif

                return STATUS_INVALID_ADDRESS;
            }
            // Ensure all 14 patch bytes fall within this single VAD region.
            if ((ULONG_PTR)HookDef->Address + 14 > (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize)
            {
                
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: 14-byte patch at %p straddles VAD boundary - skipping\n", HookDef->Address);
#endif

                return STATUS_CONFLICTING_ADDRESSES;
            }
        }

        status = fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, PAGE_EXECUTE_READWRITE, &oldProt);
        if (status == STATUS_INVALID_PARAMETER)
        {
            return STATUS_CONFLICTING_ADDRESSES;
        }
        if (NT_SUCCESS(status))
        {
            // Write JMP [RIP+0] -> Shellcode Address: FF 25 00 00 00 00 [Address]
            UCHAR jmp[14];
            RtlZeroMemory(jmp, 14);
            jmp[0] = 0xFF;
            jmp[1] = 0x25;
            *(PULONG)&jmp[2] = 0;
            *(PVOID *)&jmp[6] = myShellcodeAddress;

            // HookDef->Address is user-mode memory - must be guarded.
            __try
            {
                ProbeForWrite(HookDef->Address, 14, 1);
                RtlCopyMemory(HookDef->Address, jmp, 14);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                // Restore protection even on failure.
                fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, oldProt, &oldProt);
                return STATUS_ACCESS_VIOLATION;
            }

            fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, oldProt, &oldProt);

            HookEntry->ShellcodeUsed += sizeof(g_ShellcodeTemplate);
            HookDef->IsHooked = TRUE;
            HookDef->HookPatchSize = USERMODE_HOOK_SIZE; // 14 - FF 25 absolute JMP
        }
        else
        {
            return status;
        }
    }

    return STATUS_SUCCESS;
}

// -------------------------------------------------------------------------
// InjectSingleHook32
//
// 32-bit (WoW64) counterpart to InjectSingleHook.
//
// Differences from the 64-bit version:
//   * Stolen bytes: USERMODE_HOOK_SIZE_32 = 5 (one E9 rel32 JMP).
//   * Hook JMP: 5-byte E9 rel32.  All 32-bit targets fit in signed int32
//     because the WoW64 VA space is 0x00000000-0x7FFFFFFF (< 2 GB).
//   * Shellcode: g_ShellcodeTemplate32 (x86 stdcall, PUSHAD/POPAD).
//   * ZwQueryVirtualMemory VAD check: same principle, smaller patch size.
//   * HookDef->HookPatchSize is set to USERMODE_HOOK_SIZE_32 (5).
//     The HOOK_DEF structure must carry this field (see header note).
// -------------------------------------------------------------------------
NTSTATUS InjectSingleHook32(_In_ PEPROCESS Process, _In_ ULONG ProcessId, _Inout_ PPROCESS_HOOK_ENTRY HookEntry,
                            _Inout_ PHOOK_DEF HookDef, _In_ ULONG EventId,
                            _In_ PVOID TargetNtDeviceIo32 // 32-bit VA of NtDeviceIoControlFile
)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(Process);

    if (!HookDef->Address)
        return STATUS_INVALID_PARAMETER;
    if (HookDef->IsHooked)
        return STATUS_SUCCESS;

    // Do not build shellcode unless the per-process notify path is usable.
    // A NULL/stale 32-bit handle patched into the x86 shellcode guarantees
    // STATUS_INVALID_HANDLE from NtDeviceIoControlFile in the target.
    if (HookEntry == NULL || HookEntry->DriverDeviceHandle == NULL ||
        HookEntry->ShellcodeBase == NULL || HookEntry->ShellcodeSize == 0 ||
        TargetNtDeviceIo32 == NULL)
    {
#if IS_DEBUG_IRP
        DbgPrint("UserModeHook32: PID %lu skipping hook at %p - notify infrastructure unavailable\n",
                 ProcessId, HookDef->Address);
#endif
        // Same as the native path: the notify handle cannot be safely embedded
        // into this target, so skip the hook without poisoning caller IPC state.
        return STATUS_NOT_SUPPORTED;
    }

    // ------------------------------------------------------------------
    // 1. Reject hooks whose 5 stolen bytes contain relative branches.
    //    (No RIP-relative addressing in 32-bit mode, so only branches
    //     matter.)
    // ------------------------------------------------------------------
    {
        BOOLEAN unrelocatable = FALSE;
        __try
        {
            ProbeForRead(HookDef->Address, USERMODE_HOOK_SIZE_32, 1);
            unrelocatable = ContainsUnrelocatableInstructions32((const UCHAR *)HookDef->Address, USERMODE_HOOK_SIZE_32);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            
#if IS_DEBUG_IRP
DbgPrint("UserModeHook32: ProbeForRead faulted at %p - skipping\n", HookDef->Address);
#endif

            return STATUS_ACCESS_VIOLATION;
        }

        if (unrelocatable)
        {
            
#if IS_DEBUG_IRP
DbgPrint("UserModeHook32: Skipping %p - relative branch in prologue\n", HookDef->Address);
#endif

            return STATUS_NOT_SUPPORTED;
        }
    }

    // ------------------------------------------------------------------
    // 2. Capacity check.
    // ------------------------------------------------------------------
    if (HookEntry->ShellcodeUsed + sizeof(g_ShellcodeTemplate32) > HookEntry->ShellcodeSize)
        return STATUS_INSUFFICIENT_RESOURCES;

    PVOID myShellcodeAddress = (PVOID)((ULONG_PTR)HookEntry->ShellcodeBase + HookEntry->ShellcodeUsed);

    // ------------------------------------------------------------------
    // 3. Build and patch the 32-bit shellcode.
    // ------------------------------------------------------------------
    UCHAR shellcode[sizeof(g_ShellcodeTemplate32)];
    RtlCopyMemory(shellcode, g_ShellcodeTemplate32, sizeof(shellcode));

    {
        // Signature definitions (must be unique within the template).
        static const UCHAR kGuardMagicSig32[] = {0xBB, 0x88, 0x88, 0x88, 0x88};
        static const UCHAR kJeSig32[] = {0x0F, 0x84, 0x00, 0x00, 0x00, 0x00};
        static const UCHAR kSkipLabelSig32[] = {0x0F, 0x1F, 0x00};
        static const UCHAR kEventSig32[] = {0xC7, 0x44, 0x24, 0x08, 0x11, 0x11, 0x11, 0x11};
        static const UCHAR kPidSig32[] = {0xC7, 0x44, 0x24, 0x0C, 0x22, 0x22, 0x22, 0x22};
        static const UCHAR kSizeSig32[] = {0x68, 0x77, 0x77, 0x77, 0x77};
        static const UCHAR kIoctlSig32[] = {0x68, 0x66, 0x66, 0x66, 0x66};
        static const UCHAR kHandleSig32[] = {0x68, 0x33, 0x33, 0x33, 0x33};
        static const UCHAR kNtIoSig32[] = {0xB8, 0x44, 0x44, 0x44, 0x44};
        static const UCHAR kRetSig32[] = {0xE9, 0x55, 0x55, 0x55, 0x55};

        SIZE_T offGuardMagic32 =
            FindPatternOffset(shellcode, sizeof(shellcode), kGuardMagicSig32, sizeof(kGuardMagicSig32));
        SIZE_T offJe32 = FindPatternOffset(shellcode, sizeof(shellcode), kJeSig32, sizeof(kJeSig32));
        SIZE_T offSkipLabel32 =
            FindPatternOffset(shellcode, sizeof(shellcode), kSkipLabelSig32, sizeof(kSkipLabelSig32));
        SIZE_T offEvent = FindPatternOffset(shellcode, sizeof(shellcode), kEventSig32, sizeof(kEventSig32));
        SIZE_T offPid = FindPatternOffset(shellcode, sizeof(shellcode), kPidSig32, sizeof(kPidSig32));
        SIZE_T offSize = FindPatternOffset(shellcode, sizeof(shellcode), kSizeSig32, sizeof(kSizeSig32));
        SIZE_T offIoctl = FindPatternOffset(shellcode, sizeof(shellcode), kIoctlSig32, sizeof(kIoctlSig32));
        SIZE_T offHandle = FindPatternOffset(shellcode, sizeof(shellcode), kHandleSig32, sizeof(kHandleSig32));
        SIZE_T offNtIo = FindPatternOffset(shellcode, sizeof(shellcode), kNtIoSig32, sizeof(kNtIoSig32));
        SIZE_T offRet = FindPatternOffset(shellcode, sizeof(shellcode), kRetSig32, sizeof(kRetSig32));

        if (offGuardMagic32 == (SIZE_T)-1 || offJe32 == (SIZE_T)-1 || offSkipLabel32 == (SIZE_T)-1 ||
            offEvent == (SIZE_T)-1 || offPid == (SIZE_T)-1 || offSize == (SIZE_T)-1 || offIoctl == (SIZE_T)-1 ||
            offHandle == (SIZE_T)-1 || offNtIo == (SIZE_T)-1 || offRet == (SIZE_T)-1 || offRet < USERMODE_HOOK_SIZE_32)
        {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        // Patch re-entrancy guard magic (imm32 starting at kGuardMagicSig32+1)
        *(PULONG)(shellcode + offGuardMagic32 + 1) = HOOK_REENTRANCY_MAGIC_32;

        // Patch JE rel32: target = kSkipLabelSig32, source = kJeSig32+6
        *(PLONG)(shellcode + offJe32 + 2) = (LONG)(offSkipLabel32 - (offJe32 + 6));

        // Patch EventId (ULONG at kEventSig32 + 4)
        *(PULONG)(shellcode + offEvent + 4) = EventId;

        // Patch ProcessId (ULONG at kPidSig32 + 4)
        *(PULONG)(shellcode + offPid + 4) = ProcessId;

        // Patch InputBufferLength (ULONG at kSizeSig32 + 1)
        *(PULONG)(shellcode + offSize + 1) = (ULONG)sizeof(HOOK_EVENT_DATA);

        // Patch IoControlCode (ULONG at kIoctlSig32 + 1)
        *(PULONG)(shellcode + offIoctl + 1) = (ULONG)HOOK_NOTIFY_IOCTL_CODE;

        // Patch FileHandle (HANDLE -> ULONG in 32-bit process)
        // Handles are architecturally neutral integers; safe to truncate on
        // Windows where all kernel handles fit in 32 bits.
        *(PULONG)(shellcode + offHandle + 1) = (ULONG)(ULONG_PTR)HookEntry->DriverDeviceHandle;

        // Patch NtDeviceIoControlFile address (32-bit VA fits in ULONG)
        *(PULONG)(shellcode + offNtIo + 1) = (ULONG)(ULONG_PTR)TargetNtDeviceIo32;

        // Save original 5 bytes and copy them into the stolen-instruction slot.
        __try
        {
            ProbeForRead(HookDef->Address, USERMODE_HOOK_SIZE_32, 1);
            RtlCopyMemory(HookDef->OriginalBytes, HookDef->Address, USERMODE_HOOK_SIZE_32);
            RtlCopyMemory(shellcode + (offRet - USERMODE_HOOK_SIZE_32), HookDef->Address, USERMODE_HOOK_SIZE_32);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return STATUS_ACCESS_VIOLATION;
        }

        // Patch return JMP rel32:
        //   The E9 instruction at shellcode VA = (myShellcodeAddress + offRet).
        //   Target VA = (HookDef->Address + USERMODE_HOOK_SIZE_32).
        //   rel32 = target - (E9_VA + 5)
        //         = target - myShellcodeAddress - offRet - 5
        // All values are 32-bit VAs; arithmetic is safe.
        LONG retRel32 =
            (LONG)((ULONG_PTR)HookDef->Address + USERMODE_HOOK_SIZE_32 - ((ULONG_PTR)myShellcodeAddress + offRet + 5));
        *(PLONG)(shellcode + offRet + 1) = retRel32;
    }

    // ------------------------------------------------------------------
    // 4. Write shellcode to target process memory.
    // ------------------------------------------------------------------
    __try
    {
        ProbeForWrite(myShellcodeAddress, sizeof(shellcode), 1);
        RtlCopyMemory(myShellcodeAddress, shellcode, sizeof(shellcode));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_ACCESS_VIOLATION;
    }

    // ------------------------------------------------------------------
    // 5. VAD boundary check before ZwProtectVirtualMemory (BUG #2 fix).
    // ------------------------------------------------------------------
    {
        MEMORY_BASIC_INFORMATION mbi;
        RtlZeroMemory(&mbi, sizeof(mbi));
        SIZE_T retLen = 0;
        NTSTATUS qst = ZwQueryVirtualMemory(ZwCurrentProcess(), HookDef->Address, MemoryBasicInformation, &mbi,
                                            sizeof(mbi), &retLen);
        if (!NT_SUCCESS(qst))
            return qst;
        if (mbi.State != MEM_COMMIT)
            return STATUS_INVALID_ADDRESS;
        if ((ULONG_PTR)HookDef->Address + USERMODE_HOOK_SIZE_32 > (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize)
            return STATUS_CONFLICTING_ADDRESSES;
    }

    // ------------------------------------------------------------------
    // 6. Write 5-byte E9 rel32 JMP at target function.
    // ------------------------------------------------------------------
    if (!fnZwProtectVirtualMemory)
        return STATUS_NOT_SUPPORTED;

    {
        PVOID pageAddr = HookDef->Address;
        SIZE_T pageSize = USERMODE_HOOK_SIZE_32;
        ULONG oldProt = 0;

        status = fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, PAGE_EXECUTE_READWRITE, &oldProt);
        if (status == STATUS_INVALID_PARAMETER)
            return STATUS_CONFLICTING_ADDRESSES;
        if (!NT_SUCCESS(status))
            return status;

        // Build E9 rel32 JMP at target function:
        //   rel32 = myShellcodeAddress - (HookDef->Address + 5)
        UCHAR jmp32[USERMODE_HOOK_SIZE_32];
        jmp32[0] = 0xE9;
        *(PLONG)(&jmp32[1]) =
            (LONG)((ULONG_PTR)myShellcodeAddress - ((ULONG_PTR)HookDef->Address + USERMODE_HOOK_SIZE_32));

        __try
        {
            ProbeForWrite(HookDef->Address, USERMODE_HOOK_SIZE_32, 1);
            RtlCopyMemory(HookDef->Address, jmp32, USERMODE_HOOK_SIZE_32);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, oldProt, &oldProt);
            return STATUS_ACCESS_VIOLATION;
        }

        fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, oldProt, &oldProt);

        HookEntry->ShellcodeUsed += sizeof(g_ShellcodeTemplate32);
        HookDef->IsHooked = TRUE;
        HookDef->HookPatchSize = USERMODE_HOOK_SIZE_32; // 5 - used by UnhookSingleFunction
    }

    return STATUS_SUCCESS;
}

// -------------------------------------------------------------------------
// IsProcessAcgEnabled
//
// Detects Arbitrary Code Guard (ACG) by querying ProhibitDynamicCode via
// PsGetProcessMitigationOption.  The function is resolved at runtime with
// MmGetSystemRoutineAddress so the driver compiles on any WDK version and
// gracefully returns FALSE on systems that do not export it (pre-RS3).
//
// PS_MITIGATION_OPTION_PROHIBIT_DYNAMIC_CODE = 9  (ntddk.h constant).
// -------------------------------------------------------------------------

// Function pointer type — avoids depending on the WDK enum declaration.
typedef BOOLEAN (NTAPI *PFN_PS_GET_PROCESS_MITIGATION_OPTION)(
    _In_  PEPROCESS Process,
    _In_  ULONG     Option,      // PS_MITIGATION_OPTION ordinal
    _Out_ PULONG64  ReturnedState
);

static BOOLEAN IsProcessAcgEnabled(_In_ PEPROCESS Process)
{
    // Resolved once on first call; NULL if the export does not exist.
    static PFN_PS_GET_PROCESS_MITIGATION_OPTION s_pfn = NULL;
    static volatile LONG s_resolved = 0;

    if (InterlockedCompareExchange(&s_resolved, 1, 0) == 0)
    {
        UNICODE_STRING fnName;
        RtlInitUnicodeString(&fnName, L"PsGetProcessMitigationOption");
        s_pfn = (PFN_PS_GET_PROCESS_MITIGATION_OPTION)
                    MmGetSystemRoutineAddress(&fnName);
    }
    // Spin-wait for the first thread to finish resolving (extremely brief).
    while (s_resolved == 0) { /* no-op */ }

    if (s_pfn == NULL)
        return FALSE;   // OS too old or export missing — treat as no ACG

    ULONG64 mitigationState = 0;
    // Ordinal 9 = PS_MITIGATION_OPTION_PROHIBIT_DYNAMIC_CODE (ACG).
    // Returns TRUE when enforcement is active (not audit-only).
    return s_pfn(Process, 9, &mitigationState);
}



static BOOLEAN ShouldSkipHookFunctionForProcess(_In_ PEPROCESS Process, _In_ PCWSTR ModuleName, _In_z_ PCSTR FunctionName,
                                                _In_ BOOLEAN IsWow64)
{
    UNREFERENCED_PARAMETER(FunctionName);
    UNREFERENCED_PARAMETER(IsWow64);

    if (IsProcessAcgEnabled(Process))
    {
        // If ACG is enabled, we only skip hooking ntdll.dll.
        // We still want to hook other modules if possible.
        if (ModuleName != NULL)
        {
            UNICODE_STRING usModuleName;
            UNICODE_STRING usNtdll;
            RtlInitUnicodeString(&usModuleName, ModuleName);
            RtlInitUnicodeString(&usNtdll, L"ntdll.dll");
            if (RtlCompareUnicodeString(&usModuleName, &usNtdll, TRUE) == 0)
            {
                return TRUE;
            }
        }
    }

    return FALSE;
}

NTSTATUS ResolveAndHook32(_In_ PEPROCESS Process, _In_ PPROCESS_HOOK_ENTRY HookEntry, _In_ PCWSTR ModuleName,
                          _In_ PCSTR FunctionName, _Inout_ PHOOK_DEF HookDef, _In_ ULONG EventId,
                          _In_ PVOID TargetNtDeviceIo32)
{
    SIZE_T modSize = 0;
    PVOID modBase = IsMainExecutableHookModule(ModuleName)
                        ? FindMainImageBaseAddress32(Process, &modSize)
                        : FindModuleBaseAddress32(Process, ModuleName, &modSize);

    if (ShouldSkipHookFunctionForProcess(Process, ModuleName, FunctionName, TRUE))
        return STATUS_NOT_SUPPORTED;

    if (!modBase)
        return STATUS_NOT_FOUND;

    {
        NTSTATUS specStatus = ResolveHookAddressSpecifier(modBase, modSize, FunctionName, TRUE, &HookDef->Address);
        if (specStatus == STATUS_NOT_FOUND)
        {
            HookDef->Address = FindExportedFunction32Resolved(Process, modBase, FunctionName);
            if (!HookDef->Address)
                return STATUS_PROCEDURE_NOT_FOUND;
        }
        else if (!NT_SUCCESS(specStatus))
        {
            return specStatus;
        }
    }

    return InjectSingleHook32(Process, HookEntry->ProcessId, HookEntry, HookDef, EventId, TargetNtDeviceIo32);
}
//
// -------------------------------------------------------------------------
// FIX 1: Per-process independent FILE_OBJECT via ZwCreateFile.
//
// PREVIOUS DESIGN (root cause of freeze):
//   ObReferenceObjectByHandle(g_HookNotifyMasterHandle) retrieved the one
//   master FILE_OBJECT. ObOpenObjectByPointer then inserted a new handle into
//   the target process's handle table pointing at that SAME FILE_OBJECT.
//   Because the master was opened with FILE_SYNCHRONOUS_IO_NONALERT, the
//   kernel set FO_SYNCHRONOUS_IO on that FILE_OBJECT. Windows serializes ALL
//   I/O on a synchronous FILE_OBJECT via a single Event embedded in the object.
//   So every shellcode IOCTL call from every thread in every hooked process
//   queued behind a global lock — a single contention point that froze the
//   system under even moderate multi-process load.
//
// FIX:
//   Call ZwCreateFile WITHOUT OBJ_KERNEL_HANDLE while attached to the target
//   process. This allocates a brand-new FILE_OBJECT (with its own
//   FO_SYNCHRONOUS_IO serialization event) and inserts it directly into the
//   target process's handle table as a user-mode handle. Each hooked process
//   now has a fully independent FILE_OBJECT; concurrent IOCTLs from different
//   processes no longer contend at all.
//   g_HookNotifyMasterHandle is kept as an engine-initialized sentinel only.
// -------------------------------------------------------------------------
NTSTATUS InitializeShellcodeInfrastructure(_In_ PEPROCESS Process, _Inout_ PPROCESS_HOOK_ENTRY HookEntry)
{
    BOOLEAN isWow64 = HookEntry->IsWow64;
    NTSTATUS status;
    PVOID baseAddress = NULL;
    HANDLE targetDeviceHandle = NULL;
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

    // Sentinel: engine must be initialized before we can install hooks.
    if (g_HookNotifyMasterHandle == NULL)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    {
        KAPC_STATE apcState;
        KeStackAttachProcess((PRKPROCESS)Process, &apcState);
        __try // outer: guarantees detach
        {
            __try // inner: catches exceptions from ZwCreateFile / ZwAllocate
            {
                // FIX 1: Open a fresh handle to the hook device from within the
                // target process context. ZwCreateFile without OBJ_KERNEL_HANDLE
                // inserts the handle into the TARGET process's handle table and
                // creates an independent FILE_OBJECT. Each process therefore owns
                // its own FO_SYNCHRONOUS_IO event, eliminating cross-process lock
                // contention entirely.
                {
                    UNICODE_STRING devName;
                    OBJECT_ATTRIBUTES oa;
                    IO_STATUS_BLOCK ioSb;
                    RtlInitUnicodeString(&devName, L"\\Device\\OwlyshieldHook");
                    InitializeObjectAttributes(&oa, &devName,
                                               OBJ_CASE_INSENSITIVE, // no OBJ_KERNEL_HANDLE
                                               NULL, NULL);
                    RtlZeroMemory(&ioSb, sizeof(ioSb));
                    status = ZwCreateFile(&targetDeviceHandle,
                                          FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
                                          &oa, &ioSb, NULL,
                                          FILE_ATTRIBUTE_NORMAL,
                                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                                          FILE_OPEN,
                                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                                          NULL, 0);
                    if (!NT_SUCCESS(status))
                    {
                        
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: ZwCreateFile per-process notify handle failed 0x%X\n", status);
#endif

                        if (status == STATUS_INVALID_HANDLE)
                        {
                            status = STATUS_NOT_SUPPORTED;
                        }
                        __leave;
                    }

                    if (targetDeviceHandle == NULL)
                    {
                        
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: ZwCreateFile per-process notify handle returned NULL handle\n");
#endif

                        status = STATUS_NOT_SUPPORTED;
                        __leave;
                    }

                    status = ValidateHookNotifyUserHandle(targetDeviceHandle);
                    if (!NT_SUCCESS(status))
                    {
#if IS_DEBUG_IRP
                        DbgPrint("UserModeHook: per-process notify handle validation failed for PID %lu (0x%X)\n",
                                 HookEntry->ProcessId,
                                 status);
#endif
                        __leave;
                    }

                    if (fnZwSetInformationObject != NULL)
                    {
                        OWLY_OBJECT_HANDLE_FLAG_INFORMATION handleFlags = {0};
                        NTSTATUS handleProtectStatus;

                        //
                        // Do not mark this user handle as ProtectFromClose.
                        // Chromium/WebView2 sandbox code legitimately audits
                        // and closes handles during startup and renderer setup.
                        // A close-protected foreign handle turns that cleanup
                        // into visible handle errors in the target process.
                        //
                        // Notification is best-effort: if the sandbox closes
                        // this handle, shellcode restores the caller's registers
                        // and TEB error/status state, and the refresh path rebuilds
                        // the notify infrastructure later.
                        //
                        handleFlags.ProtectFromClose = FALSE;
                        handleFlags.Inherit = FALSE;
                        handleProtectStatus = fnZwSetInformationObject(targetDeviceHandle,
                                                                       OWLY_OBJECT_HANDLE_FLAG_INFORMATION_CLASS,
                                                                       &handleFlags,
                                                                       sizeof(handleFlags));
                        if (!NT_SUCCESS(handleProtectStatus))
                        {
                            
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: failed to clear per-process notify handle flags for PID %lu (0x%X); continuing\n",
                                     HookEntry->ProcessId,
                                     handleProtectStatus);
#endif
                        }

                        status = ValidateHookNotifyUserHandle(targetDeviceHandle);
                        if (!NT_SUCCESS(status))
                        {
#if IS_DEBUG_IRP
                            DbgPrint("UserModeHook: protected notify handle validation failed for PID %lu (0x%X)\n",
                                     HookEntry->ProcessId,
                                     status);
#endif
                            __leave;
                        }
                    }
                }

                if (!fnZwAllocateVirtualMemory)
                {
                    status = STATUS_NOT_IMPLEMENTED;
                    __leave;
                }

                if (!isWow64)
                {
                    // Native 64-bit: FF 25 absolute JMP, no range limit.
                    status = fnZwAllocateVirtualMemory(ZwCurrentProcess(), &baseAddress, 0, &regionSize,
                                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                }
                else
                {
                    // WoW64: do NOT use ZeroBits=33 here.
                    // Nt/ZwAllocateVirtualMemory interprets ZeroBits > 32 as a
                    // bitmask, not a count of high-order bits, so 33 does not
                    // reliably mean "below 0x80000000".  Search explicitly in
                    // the low address range so the 5-byte E9 rel32 trampoline
                    // remains reachable.
                    const ULONG_PTR lowBaseStart = 0x10000000UL;
                    const ULONG_PTR lowBaseEnd = 0x70000000UL;
                    const ULONG_PTR granularity = 0x00010000UL; // 64 KB
                    NTSTATUS lastAllocStatus = STATUS_CONFLICTING_ADDRESSES;
                    BOOLEAN allocated = FALSE;

                    for (ULONG_PTR hint = lowBaseStart; hint + regionSize < lowBaseEnd; hint += granularity)
                    {
                        PVOID candidate = (PVOID)hint;
                        SIZE_T candidateSize = regionSize;
                        NTSTATUS allocStatus =
                            fnZwAllocateVirtualMemory(ZwCurrentProcess(), &candidate, 0, &candidateSize,
                                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                        if (NT_SUCCESS(allocStatus))
                        {
                            baseAddress = candidate;
                            regionSize = candidateSize;
                            status = STATUS_SUCCESS;
                            allocated = TRUE;
                            break;
                        }
                        lastAllocStatus = allocStatus;
                    }

                    if (!allocated)
                    {
                        status = lastAllocStatus;
                    }
                }

                if (!NT_SUCCESS(status))
                {
                    __leave;
                }

                HookEntry->ShellcodeBase = baseAddress;
                HookEntry->ShellcodeSize = regionSize;
                HookEntry->ShellcodeUsed = 0;
                HookEntry->DriverDeviceHandle = targetDeviceHandle;
                targetDeviceHandle = NULL; // ownership moved to hook entry
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                status = GetExceptionCode();
            }

            if (!NT_SUCCESS(status))
            {
                if (targetDeviceHandle != NULL)
                {
                    CloseHookNotifyHandleSafe(&targetDeviceHandle);
                }
                if (baseAddress != NULL && fnZwFreeVirtualMemory != NULL)
                {
                    SIZE_T freeSize = 0;
                    fnZwFreeVirtualMemory(ZwCurrentProcess(), &baseAddress, &freeSize, MEM_RELEASE);
                }
                HookEntry->ShellcodeBase = NULL;
                HookEntry->ShellcodeSize = 0;
                HookEntry->ShellcodeUsed = 0;
                HookEntry->DriverDeviceHandle = NULL;
            }
        }
        __finally
        {
            KeUnstackDetachProcess(&apcState);
        }
    }

    return status;
}

//
// Helper: Resolve and Prepare Hook
//
// Per-function exclusions are intentionally narrow.  Chromium/WebView2 code
// treats STATUS_INVALID_HANDLE from NtQueryObject as normal sandbox probing, so
// that single API is skipped only when Chromium-family modules are loaded.
// The TEB re-entrancy sentinel still protects the NtDeviceIoControlFile
// transport hook path.
NTSTATUS ResolveAndHook(_In_ PEPROCESS Process, _In_ PPROCESS_HOOK_ENTRY HookEntry, _In_ PCWSTR ModuleName,
                        _In_ PCSTR FunctionName, _Inout_ PHOOK_DEF HookDef, _In_ ULONG EventId,
                        _In_ PVOID TargetNtDeviceIo)
{
    SIZE_T modSize = 0;
    PVOID modBase = IsMainExecutableHookModule(ModuleName)
                        ? FindMainImageBaseAddress(Process, &modSize)
                        : FindModuleBaseAddress(Process, ModuleName, &modSize);

    if (ShouldSkipHookFunctionForProcess(Process, ModuleName, FunctionName, FALSE))
        return STATUS_NOT_SUPPORTED;

    if (!modBase)
        return STATUS_NOT_FOUND;

    {
        NTSTATUS specStatus = ResolveHookAddressSpecifier(modBase, modSize, FunctionName, FALSE, &HookDef->Address);
        if (specStatus == STATUS_NOT_FOUND)
        {
            HookDef->Address = FindExportedFunctionResolved(Process, modBase, FunctionName);
            if (!HookDef->Address)
                return STATUS_PROCEDURE_NOT_FOUND;
        }
        else if (!NT_SUCCESS(specStatus))
        {
            return specStatus;
        }
    }

    return InjectSingleHook(Process, HookEntry->ProcessId, HookEntry, HookDef, EventId, TargetNtDeviceIo);
}

static VOID UnhookSingleFunction(_In_ PEPROCESS Process, _Inout_ PHOOK_DEF HookDef);

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
    ULONG appliedHookCount = 0;
    ULONG recoverableHookFailureCount = 0;
    ULONG hookConfigSnapshotCount = 0;
    PHOOK_CONFIG_DATA hookConfigSnapshot = NULL;
    PHOOK_CONFIG_DATA activeHookConfigSnapshot = NULL;
    SIZE_T hookConfigSnapshotBytes = 0;
    ULONG hookCountToInstall = 0;

    if (g_UserHookEngine == NULL || !g_UserHookEngine->IsInitialized)
        return STATUS_DEVICE_NOT_READY;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status))
        return status;

    // ShouldSkipHookingProcess must run at PASSIVE_LEVEL.  It can call
    // SeLocateProcessImageName and, on the first use of the exclusion-rule
    // engine, it can lazily load rules from disk via ZwCreateFile/ZwReadFile.
    // FAST_MUTEX acquisition raises execution to APC_LEVEL, so running the
    // skip-check under EngineMutex is invalid and can hang or trip verifier.
    if (ShouldSkipHookingProcess(process, ProcessId))
    {
        ObDereferenceObject(process);
        return STATUS_ACCESS_DENIED;
    }

    // ========================================================================
    // DEADLOCK FIX: Acquire ConfigMutex BEFORE EngineMutex to establish
    // a consistent lock ordering throughout the driver.
    //
    // LOCK ORDERING RULE: ConfigMutex must ALWAYS be acquired before EngineMutex.
    // Never nest these mutexes in the opposite order to prevent AB-BA deadlock.
    //
    // Original bug: EngineMutex was acquired first (line 3546), then ConfigMutex
    // was acquired inside (line 3609), causing system-wide deadlock when another
    // thread held ConfigMutex and tried to acquire EngineMutex.
    // ========================================================================
    
    // Snapshot the config count early, before taking EngineMutex
    ExAcquireFastMutex(&g_ConfigMutex);
    customHookCountSnapshot = g_CustomHookCount;
    ExReleaseFastMutex(&g_ConfigMutex);
    
    if (customHookCountSnapshot > MAX_CUSTOM_HOOKS)
    {
        customHookCountSnapshot = MAX_CUSTOM_HOOKS;
    }

    // Now serialize process-slot lookup/claim with EngineMutex
    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);

    // Re-use existing process slot to avoid duplicate infrastructure/handle creation.
    // Also check the stored EPROCESS pointer: if it differs from the current process
    // object the OS reused this PID for a new process.  Discard the stale slot so the
    // new process gets a fresh one (PID-reuse defence).
    for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++)
    {
        if (g_UserHookEngine->Processes[i].ProcessId == ProcessId)
        {
            if (g_UserHookEngine->Processes[i].ProcessObject != process)
            {
                // PID reused by a new process: release resources held for the old
                // one and zero the slot so the free-slot search below can claim it.
                if (g_UserHookEngine->Processes[i].ProcessObject != NULL)
                    ObDereferenceObject(g_UserHookEngine->Processes[i].ProcessObject);
                if (g_UserHookEngine->Processes[i].CustomHooks != NULL)
                {
                    ExFreePoolWithTag(g_UserHookEngine->Processes[i].CustomHooks, 'cHuM');
                }
                if (g_UserHookEngine->Processes[i].IsHooked &&
                    g_UserHookEngine->HookedProcessCount > 0)
                    g_UserHookEngine->HookedProcessCount--;
                RtlZeroMemory(&g_UserHookEngine->Processes[i], sizeof(PROCESS_HOOK_ENTRY));
                
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: PID %lu reuse detected; stale slot cleared\n", ProcessId);
#endif

                break; // stale slot cleared; fall through to free-slot search
            }
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

        // Use the config snapshot we took before acquiring EngineMutex
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
    // Initialize shellcode infrastructure before the resolve-and-hook pass.
    // InitializeShellcodeInfrastructure performs the required attach itself
    // because both ZwAllocateVirtualMemory(ZwCurrentProcess()) and the final
    // target-process device handle creation must occur in the target context.
    // -----------------------------------------------------------------------
    if (existingHookEntry)
    {
        BOOLEAN rebuildInfrastructure = FALSE;

        if (hookEntry->DriverDeviceHandle == NULL || hookEntry->ShellcodeBase == NULL ||
            hookEntry->ShellcodeSize == 0)
        {
            rebuildInfrastructure = TRUE;
        }
        else
        {
            KAPC_STATE validateApcState;
            KeStackAttachProcess((PRKPROCESS)process, &validateApcState);
            __try
            {
                status = ValidateHookNotifyUserHandle(hookEntry->DriverDeviceHandle);
                if (!NT_SUCCESS(status))
                {
#if IS_DEBUG_IRP
                    DbgPrint("UserModeHook: PID %lu stale notify handle detected during refresh (0x%X)\n",
                             ProcessId,
                             status);
#endif
                    rebuildInfrastructure = TRUE;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                rebuildInfrastructure = TRUE;
            }
            KeUnstackDetachProcess(&validateApcState);
        }

        if (rebuildInfrastructure)
        {
            if (process != NULL && PsGetProcessExitStatus(process) == STATUS_PENDING)
            {
                KAPC_STATE rebuildApcState;
                KeStackAttachProcess((PRKPROCESS)process, &rebuildApcState);
                __try
                {
                    for (ULONG i = 0; i < hookEntry->CustomHookCapacity; ++i)
                    {
                        if (hookEntry->CustomHooks != NULL && hookEntry->CustomHooks[i].IsHooked)
                        {
                            UnhookSingleFunction(process, &hookEntry->CustomHooks[i]);
                        }
                    }

                    if (hookEntry->DriverDeviceHandle != NULL)
                    {
                        CloseHookNotifyHandleSafe(&hookEntry->DriverDeviceHandle);
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                }
                KeUnstackDetachProcess(&rebuildApcState);
            }

            if (hookEntry->CustomHooks != NULL)
            {
                ExFreePoolWithTag(hookEntry->CustomHooks, 'cHuM');
                hookEntry->CustomHooks = NULL;
            }

            hookEntry->CustomHookCapacity = customHookCountSnapshot;
            hookEntry->DriverDeviceHandle = NULL;
            hookEntry->ShellcodeBase = NULL;
            hookEntry->ShellcodeSize = 0;
            hookEntry->ShellcodeUsed = 0;
            hookEntry->IsHooked = FALSE;
        }
    }

    if (!existingHookEntry || hookEntry->ShellcodeBase == NULL || hookEntry->DriverDeviceHandle == NULL)
    {
        // Detect WoW64 BEFORE allocating shellcode so the allocator can
        // constrain the region to the low 2 GB.  32-bit E9 rel32 JMPs
        // cannot reach a shellcode region above 0x7FFFFFFF - the JMP
        // silently overflows and jumps to garbage, causing crashes and
        // stopping all I/O events.  PsGetProcessWow64Process is safe to
        // call on any PEPROCESS at any IRQL without attaching.
        hookEntry->IsWow64 = (fnPsGetProcessWow64Process != NULL && fnPsGetProcessWow64Process(process) != NULL);

        status = InitializeShellcodeInfrastructure(process, hookEntry);
        if (!NT_SUCCESS(status))
        {
            goto HookProcessFailure;
        }

        // Detect if this is a Chromium-based process and store it in DriverData 
        // so that KERNEL_EVENT_INFO can be accurately populated during hooks.
        if (driverData != NULL)
        {
            BOOLEAN isAcgEnabled = IsProcessAcgEnabled(process);
            driverData->SetProcessIsAcgEnabled(ProcessId, isAcgEnabled);
            
#if IS_DEBUG_IRP
            if (isAcgEnabled)
            {
                DbgPrint("UserModeHook: PID %lu has ACG enabled\n", ProcessId);
            }
#endif
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

    // Snapshot the current hook configuration while holding g_ConfigMutex only
    // long enough to copy the rules. Holding a FAST_MUTEX during the actual
    // resolve/patch loop raises IRQL to APC_LEVEL, which is invalid for the
    // ZwQuery/Protect/AllocateVirtualMemory calls used by the hook installer.
    ExAcquireFastMutex(&g_ConfigMutex);
    customHookCountToApply = g_CustomHookCount;
    if (customHookCountToApply > hookEntry->CustomHookCapacity)
    {
        customHookCountToApply = hookEntry->CustomHookCapacity;
    }
    if (customHookCountToApply > 0)
    {
        hookConfigSnapshotCount = customHookCountToApply;
        hookConfigSnapshotBytes = (SIZE_T)customHookCountToApply * sizeof(HOOK_CONFIG_DATA);
    }
    ExReleaseFastMutex(&g_ConfigMutex);

    if (hookConfigSnapshotBytes > 0)
    {
        hookConfigSnapshot = (PHOOK_CONFIG_DATA)ExAllocatePool2(POOL_FLAG_NON_PAGED, hookConfigSnapshotBytes, 'gHuM');
        if (hookConfigSnapshot == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto HookProcessFailure;
        }

        ExAcquireFastMutex(&g_ConfigMutex);
        customHookCountToApply = g_CustomHookCount;
        if (customHookCountToApply > hookConfigSnapshotCount)
        {
            customHookCountToApply = hookConfigSnapshotCount;
        }
        if (customHookCountToApply > 0)
        {
            RtlCopyMemory(hookConfigSnapshot, g_GlobalCustomHooks,
                          (SIZE_T)customHookCountToApply * sizeof(HOOK_CONFIG_DATA));
        }
        ExReleaseFastMutex(&g_ConfigMutex);
    }

    hookCountToInstall = customHookCountToApply;
    activeHookConfigSnapshot = hookConfigSnapshot;
    if (hookCountToInstall > 0 && (activeHookConfigSnapshot == NULL || hookEntry->CustomHooks == NULL))
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto HookProcessFailure;
    }

    // Single attachment for resolving exports and writing hooks
    {
        KAPC_STATE apcState;
        KeStackAttachProcess((PRKPROCESS)process, &apcState);
        __try // outer: guarantees detach
        {
            __try // inner: catches exceptions from resolve/hook calls
            {
                ntdllBase = FindModuleBaseAddress(process, L"ntdll.dll", NULL);
                targetNtDeviceIo = FindExportedFunctionResolved(process, ntdllBase, "NtDeviceIoControlFile");
                if (!targetNtDeviceIo)
                {
                    status = STATUS_NOT_FOUND;
                    __leave;
                }

                // For WoW64 processes, also resolve the 32-bit NtDeviceIoControlFile
                // from the 32-bit ntdll.dll mapped in the WoW64 VA space.
                PVOID ntdllBase32 = NULL;
                PVOID targetNtDeviceIo32 = NULL;
                if (hookEntry->IsWow64)
                {
                    ntdllBase32 = FindModuleBaseAddress32(process, L"ntdll.dll", NULL);
                    if (ntdllBase32)
                        targetNtDeviceIo32 =
                            FindExportedFunction32Resolved(process, ntdllBase32, "NtDeviceIoControlFile");

                    if (!targetNtDeviceIo32)
                    {
                        
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: PID %lu WoW64 - could not resolve 32-bit NtDeviceIoControlFile\n",
                                 ProcessId);
#endif

                        status = STATUS_NOT_FOUND;
                        __leave;
                    }
                }

                if (hookCountToInstall > 0 && (activeHookConfigSnapshot == NULL || hookEntry->CustomHooks == NULL))
                {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                    __leave;
                }

                for (ULONG i = 0; i < hookCountToInstall; i++)
                {
                    NTSTATUS hookStatus = STATUS_UNSUCCESSFUL;
                    PHOOK_CONFIG_DATA currentHookConfig = &activeHookConfigSnapshot[i];
                    __try
                    {
                        // Route to the correct architecture's hook installer.
                        if (hookEntry->IsWow64)
                        {
                            // WoW64: resolve from 32-bit LDR, install 5-byte E9 JMP,
                            // use 32-bit shellcode template.
                            hookStatus = ResolveAndHook32(process, hookEntry, currentHookConfig->ModuleName,
                                                          currentHookConfig->FunctionName,
                                                          &hookEntry->CustomHooks[i], currentHookConfig->EventId,
                                                          targetNtDeviceIo32);
                        }
                        else
                        {
                            // Native 64-bit: resolve from 64-bit LDR, install 14-byte
                            // FF 25 JMP, use 64-bit shellcode template.
                            hookStatus = ResolveAndHook(process, hookEntry, currentHookConfig->ModuleName,
                                                        currentHookConfig->FunctionName, &hookEntry->CustomHooks[i],
                                                        currentHookConfig->EventId, targetNtDeviceIo);
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        hookStatus = GetExceptionCode();
                    }

                    if (NT_SUCCESS(hookStatus))
                    {
                        appliedHookCount++;
                        continue;
                    }

                    // FIX #1: The previous code had a second `if (!NT_SUCCESS(...))`
                    // that was logically dead - it was always reached and always
                    // true, so EVERY failure (including benign ones) aborted the
                    // entire hook operation and propagated STATUS_INVALID_PARAMETER
                    // or STATUS_NOT_FOUND to the caller.
                    // recoverableHookFailureCount was declared but never incremented.
                    //
                    // Fix: classify failures explicitly.
                    //
                    // Recoverable - the specific function is not available in this
                    // process (module absent, export absent, RIP-relative prologue,
                    // VAD boundary conflict, access fault).  Skip this target and
                    // continue installing the remaining hooks.
                    if (IsRecoverableHookInstallStatus(hookStatus))
                    {
                        
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: PID %lu skipping hook[%lu] '%s' - recoverable 0x%X\n", ProcessId, i,
                                 currentHookConfig->FunctionName, hookStatus);
#endif

                        recoverableHookFailureCount++;
                        continue;
                    }

                    // Fatal - abort (e.g. STATUS_INSUFFICIENT_RESOURCES,
                    //                  STATUS_INVALID_IMAGE_FORMAT,
                    //                  STATUS_DEVICE_DOES_NOT_EXIST).
                    
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: PID %lu fatal hook[%lu] '%ws!%s' failed 0x%X\n", ProcessId, i,
                             currentHookConfig->ModuleName, currentHookConfig->FunctionName, hookStatus);
#endif

                    status = hookStatus;
                    __leave;
                }

                if (recoverableHookFailureCount > 0)
                {
                    
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: PID %lu partial hook result: applied=%lu recoverable_failures=%lu\n",
                             ProcessId, appliedHookCount, recoverableHookFailureCount);
#endif

                }

                // If every requested hook was skipped, do not keep a live hook
                // entry with an embedded notify handle and no installed bytes.
                // Treat the process as unsupported and clean up the handle/VA
                // before returning. This is the safest behavior for protected,
                // dynamic-code-blocked, or WebView2 processes where the notify
                // handle cannot be guaranteed stable.
                if (!existingHookEntry && hookCountToInstall > 0 && appliedHookCount == 0)
                {
#if IS_DEBUG_IRP
                    DbgPrint("UserModeHook: PID %lu skipped - no hooks could be installed (recoverable failures=%lu)\n",
                             ProcessId, recoverableHookFailureCount);
#endif
                    status = STATUS_NOT_SUPPORTED;
                    __leave;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                status = GetExceptionCode();
            }
        }
        __finally
        {
            KeUnstackDetachProcess(&apcState);
        }

        if (hookConfigSnapshot != NULL)
        {
            ExFreePoolWithTag(hookConfigSnapshot, 'gHuM');
            hookConfigSnapshot = NULL;
        }

        // FIX: read NeedsCleanup atomically with IsInProgress clear.
        // UnhookProcess sets NeedsCleanup when it arrives while we are
        // in-flight so it can't do the cleanup itself.  We must do it.
        BOOLEAN needsCleanupNow = FALSE;
        ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);
        hookEntry->IsInProgress = FALSE;
        needsCleanupNow = hookEntry->NeedsCleanup;
        if (needsCleanupNow)
            hookEntry->NeedsCleanup = FALSE;
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
            
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: Shellcodes processed for PID %lu (%s)\n", ProcessId,
                     existingHookEntry ? "refresh" : "initial");
#endif

        }
        else
        {
            goto HookProcessFailure;
        }

        ObDereferenceObject(process);

        // Perform deferred unhook: the terminate callback fired while we
        // were in-flight and set NeedsCleanup instead of leaking the ref.
        if (needsCleanupNow)
            (VOID) UserModeUnhookProcess(ProcessId);

        return status;
    } // end attach scope block

HookProcessFailure:
    
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: PID %lu hook processing failed 0x%X (%s)\n", ProcessId, status,
             existingHookEntry ? "refresh" : "initial");
#endif

    const BOOLEAN recoverableProcessFailure = IsRecoverableHookProcessStatus(status);
    const NTSTATUS returnStatus = recoverableProcessFailure ? STATUS_SUCCESS : status;

    if (recoverableProcessFailure)
    {
#if IS_DEBUG_IRP
        DbgPrint("UserModeHook: PID %lu hook processing skipped as recoverable 0x%X (%s)\n",
                 ProcessId, status, existingHookEntry ? "refresh" : "initial");
#endif
    }

    if (hookConfigSnapshot != NULL)
    {
        ExFreePoolWithTag(hookConfigSnapshot, 'gHuM');
        hookConfigSnapshot = NULL;
    }

    // Ensure busy flag is cleared on failure
    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);
    hookEntry->IsInProgress = FALSE;
    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);

    if (existingHookEntry)
    {
        ObDereferenceObject(process);
        return returnStatus;
    }

    if (hookEntry != NULL)
    {
        // Initial hook failure cleanup has two very different cases:
        //
        //   1. No hook bytes were ever published (appliedHookCount == 0).
        //      Safe to close the per-process user handle and free the shellcode
        //      region immediately because nothing in user mode can jump there.
        //
        //   2. At least one hook was already installed before a later fatal
        //      error.  In that case we must first restore the original bytes.
        //      We intentionally DO NOT free ShellcodeBase or force-close the
        //      user handle afterwards because another thread may already be
        //      executing in the trampoline.  Unhooking prevents any NEW entry;
        //      normal process teardown reclaims the leaked VA + handle safely.
        //
        // Also avoid attaching to a dying process: the OS will reclaim its
        // handle table and VA space during rundown.
        if ((hookEntry->CustomHooks != NULL || hookEntry->DriverDeviceHandle != NULL || hookEntry->ShellcodeBase != NULL) &&
            process != NULL && PsGetProcessExitStatus(process) == STATUS_PENDING)
        {
            KAPC_STATE cleanupApcState;
            KeStackAttachProcess((PRKPROCESS)process, &cleanupApcState);
            __try // outer: guarantees detach
            {
                __try // inner: catches exceptions from unhook / close / free
                {
                    if (appliedHookCount > 0 && hookEntry->CustomHooks != NULL)
                    {
                        for (ULONG i = 0; i < hookEntry->CustomHookCapacity; ++i)
                        {
                            if (hookEntry->CustomHooks[i].IsHooked)
                            {
                                UnhookSingleFunction(process, &hookEntry->CustomHooks[i]);
                            }
                        }

                        hookEntry->DriverDeviceHandle = NULL;
                        hookEntry->ShellcodeBase = NULL;
                        hookEntry->ShellcodeSize = 0;
                        hookEntry->ShellcodeUsed = 0;
                    }
                    else
                    {
                        if (hookEntry->DriverDeviceHandle != NULL)
                        {
                            CloseHookNotifyHandleSafe(&hookEntry->DriverDeviceHandle);
                        }

                        if (hookEntry->ShellcodeBase != NULL && fnZwFreeVirtualMemory != NULL)
                        {
                            SIZE_T freeSize = 0;
                            fnZwFreeVirtualMemory(ZwCurrentProcess(), &hookEntry->ShellcodeBase, &freeSize,
                                                  MEM_RELEASE);
                            hookEntry->ShellcodeBase = NULL;
                        }

                        hookEntry->ShellcodeSize = 0;
                        hookEntry->ShellcodeUsed = 0;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    hookEntry->DriverDeviceHandle = NULL;
                    hookEntry->ShellcodeBase = NULL;
                    hookEntry->ShellcodeSize = 0;
                    hookEntry->ShellcodeUsed = 0;
                }
            }
            __finally
            {
                KeUnstackDetachProcess(&cleanupApcState);
            }
        }
        else
        {
            hookEntry->DriverDeviceHandle = NULL;
            hookEntry->ShellcodeBase = NULL;
            hookEntry->ShellcodeSize = 0;
            hookEntry->ShellcodeUsed = 0;
        }

        if (hookEntry->CustomHooks != NULL)
        {
            ExFreePoolWithTag(hookEntry->CustomHooks, 'cHuM');
            hookEntry->CustomHooks = NULL;
            hookEntry->CustomHookCapacity = 0;
        }

        // Drop the global array's reference before clearing the entry
        if (hookEntry->ProcessObject != NULL)
        {
            ObDereferenceObject(hookEntry->ProcessObject);
        }

        hookEntry->ProcessObject = NULL;
        RtlZeroMemory(hookEntry, sizeof(PROCESS_HOOK_ENTRY));
    }

    ObDereferenceObject(process);
    return returnStatus;
}
//
// Unhook
//

//
// Helper to Unhook Single Function
//
// -------------------------------------------------------------------------
// UnhookSingleFunction
//
// Restores the original bytes at the hooked function's entry point.
// Supports both 64-bit hooks (14-byte FF 25 patch) and WoW64 hooks
// (5-byte E9 rel32 patch) via HookDef->HookPatchSize.
//
// NOTE: HookDef->HookPatchSize must be set to USERMODE_HOOK_SIZE (14) for
// 64-bit hooks and USERMODE_HOOK_SIZE_32 (5) for WoW64 hooks at hook
// installation time (InjectSingleHook and InjectSingleHook32 do this).
// -------------------------------------------------------------------------
static VOID UnhookSingleFunction(_In_ PEPROCESS Process, _Inout_ PHOOK_DEF HookDef)
{
    UNREFERENCED_PARAMETER(Process);
    NTSTATUS status;

    if (!HookDef->IsHooked || !HookDef->Address)
        return;

    // Determine how many bytes to restore.  Default to USERMODE_HOOK_SIZE
    // (14) for backwards compatibility with hook entries that predate the
    // HookPatchSize field.
    ULONG patchSize = (HookDef->HookPatchSize == USERMODE_HOOK_SIZE_32)
                          ? USERMODE_HOOK_SIZE_32 // WoW64 5-byte E9 patch
                          : USERMODE_HOOK_SIZE;   // 64-bit 14-byte FF 25 patch

    if (!fnZwProtectVirtualMemory)
        return;

    PVOID pageAddr = HookDef->Address;
    SIZE_T pageSize = patchSize;
    ULONG oldProt = 0;

    status = fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, PAGE_EXECUTE_READWRITE, &oldProt);
    if (NT_SUCCESS(status))
    {
        __try
        {
            ProbeForWrite(HookDef->Address, patchSize, 1);
            RtlCopyMemory(HookDef->Address, HookDef->OriginalBytes, patchSize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, oldProt, &oldProt);
            return;
        }

        // Flush the CPU instruction pipeline for this address range.
        KeInvalidateAllCaches();

        fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, oldProt, &oldProt);
        HookDef->IsHooked = FALSE;
    }
}

NTSTATUS UserModeUnhookProcess(_In_ ULONG ProcessId)
{
    PEPROCESS process = NULL;
    PPROCESS_HOOK_ENTRY hookEntry = NULL;
    NTSTATUS status;
    KAPC_STATE apcState;

    if (g_UserHookEngine == NULL)
        return STATUS_DEVICE_NOT_READY;

    // 1. Lock the slot
    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);
    for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++)
    {
        // Match on PID for both fully-hooked and mid-hook (IsInProgress only) slots.
        // An IsInProgress-only slot can arise when the process exits before hooking
        // completes; without this check the slot stays live and blocks any new
        // process that receives the same PID from the OS (PID reuse).
        if (g_UserHookEngine->Processes[i].ProcessId == ProcessId &&
            (g_UserHookEngine->Processes[i].IsHooked || g_UserHookEngine->Processes[i].IsInProgress))
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

    if (hookEntry->IsInProgress)
    {
        // FIX: process terminated while HookProcess was still in-flight.
        // Returning STATUS_NOT_FOUND here leaves hookEntry->ProcessObject
        // with a live ObReference - the PEPROCESS object is never freed,
        // the process appears in the task list but can't be killed (zombie),
        // and the system can't restart because cleanup also misses the slot.
        hookEntry->NeedsCleanup = TRUE;
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
        return STATUS_SUCCESS;
    }

    hookEntry->IsInProgress = TRUE;
    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);

    // 2. Lookup and Zombie Check
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status))
        goto FinalCleanup;

    // Check if process is exiting/zombie - Attaching to a dying process causes hard resets.
    if (PsGetProcessExitStatus(process) != STATUS_PENDING)
    {
        // FIX: Even though we cannot attach (unsafe on dying process),
        // we must not leave a dangling handle reference tracked in hookEntry.
        // The Object Manager tears down the handle table for us as part of
        // process exit rundown, so the actual kernel handle is cleaned up.
        // We just clear our pointer so NeedsCleanup path does not double-close.
        hookEntry->DriverDeviceHandle = NULL;
        hookEntry->ShellcodeBase = NULL;
        hookEntry->ShellcodeSize = 0;
        ObDereferenceObject(process);
        goto FinalCleanup;
    }

    // 3. PHASE 1: RESTORE BYTES
    //
    // IMPORTANT: do NOT close DriverDeviceHandle before or immediately after
    // restoring the bytes.  WebView2/Edge is highly multi-threaded, and a
    // thread may already be executing inside our trampoline when this unhook
    // starts.  That in-flight trampoline can reach NtDeviceIoControlFile after
    // the original function bytes are restored.  If we close the embedded user
    // handle without a real shellcode in-flight/rundown counter, that thread
    // receives STATUS_INVALID_HANDLE.
    //
    // Safe ordering without a rundown counter:
    //   1. Restore all patched function entries first.
    //   2. Forget the per-process handle in our bookkeeping.
    //   3. Let process teardown reclaim the still-open protected user handle
    //      and shellcode VA region.
    //
    // This intentionally leaks one small handle/VA allocation until target
    // process exit, but prevents the msedgewebview2.exe STATUS_INVALID_HANDLE
    // race.  If you later add an in-flight counter in the shellcode, you can
    // wait for it to drain here and then call CloseHookNotifyHandleSafe.
    KeStackAttachProcess((PRKPROCESS)process, &apcState);
    __try // outer: guarantees detach
    {
        __try // inner: catches exceptions from UnhookSingleFunction
        {
            for (ULONG i = 0; i < hookEntry->CustomHookCapacity; ++i)
            {
                if (hookEntry->CustomHooks != NULL && hookEntry->CustomHooks[i].IsHooked)
                {
                    UnhookSingleFunction(process, &hookEntry->CustomHooks[i]);
                }
            }

            // Do not close this handle here.  It may already be embedded in an
            // in-flight trampoline on another thread.  Clearing our copy avoids
            // a later double-close; the target process will close the real user
            // handle during normal handle-table teardown.
            hookEntry->DriverDeviceHandle = NULL;
            hookEntry->ShellcodeBase = NULL;
            hookEntry->ShellcodeSize = 0;
            hookEntry->ShellcodeUsed = 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            
#if IS_DEBUG_IRP
DbgPrint("UserModeHook: Exception 0x%X during unhook of PID %lu\n", GetExceptionCode(), ProcessId);
#endif

        }
    }
    __finally
    {
        KeUnstackDetachProcess(&apcState);
    }

    // The shellcode VA region (shellcodeToFree) is intentionally NOT freed here.
    // When the process exits, the OS tears down its entire VA space and reclaims
    // all committed pages - including shellcode - automatically.  Trying to free
    // it ourselves requires a 500ms drain (to avoid freeing pages still executing
    // in another thread), and that drain WAS the zombie: the EPROCESS reference
    // was held through the delay, keeping the process alive and unkillable in
    // Task Manager.  The drain is gone; the OS handles it correctly.
    ObDereferenceObject(process);
    process = NULL;

FinalCleanup:
    // 6. INTERNAL CLEANUP
    if (hookEntry->CustomHooks != NULL)
    {
        ExFreePoolWithTag(hookEntry->CustomHooks, 'cHuM');
        hookEntry->CustomHooks = NULL;
    }

    // Release the array-held reference before wiping the entry.
    if (hookEntry->ProcessObject != NULL)
    {
        ObDereferenceObject(hookEntry->ProcessObject);
        hookEntry->ProcessObject = NULL;
    }

    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);
    RtlZeroMemory(hookEntry, sizeof(PROCESS_HOOK_ENTRY));
    if (g_UserHookEngine->HookedProcessCount > 0)
        g_UserHookEngine->HookedProcessCount--;
    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);

    return STATUS_SUCCESS;
}
