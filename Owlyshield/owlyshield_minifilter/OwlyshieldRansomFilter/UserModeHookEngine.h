/*++
Module Name:
    UserModeHookEngine.h
Abstract:
    User-mode ntdll.dll hooking engine.
    Fixed for redefinition errors and missing exports.
Environment:
    Kernel mode driver
--*/

#pragma once

// -------------------------------------------------------------------------
// HEADER FIX: Use ONLY ntifs.h.
// It contains PEPROCESS/PETHREAD definitions.
// Do not include ntddk.h or windef.h alongside it if they conflict.
// -------------------------------------------------------------------------
#include <ntifs.h>
#include "../SharedDefs/SharedDefs.h"

//
// -------------------------------------------------------------------------
// TYPE DEFINITIONS
// -------------------------------------------------------------------------
typedef unsigned char BYTE;
typedef BYTE *PBYTE;

//
// -------------------------------------------------------------------------
// UNDOCUMENTED STRUCTURE DEFINITIONS
// -------------------------------------------------------------------------
#pragma warning(push)
#pragma warning(disable : 4201) // Disable nameless struct/union warning

// PEB structures (Required because they are opaque in Kernel)
typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageDbGlobalFlag : 1;
            BOOLEAN SpareBool : 1;
            BOOLEAN BackGndLocallyVisible : 1;
            BOOLEAN SpareBool1 : 1;
            BOOLEAN TwoGlobalFlagBits : 2;
            BOOLEAN CriticalSectionDefaultTimeout : 1;
            BOOLEAN CriticalSectionRenderer : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    KSPIN_LOCK FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ReservedBits0 : 27;
        };
    };
    PVOID KernelCallbackTable;
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedMemoryBase;
    PVOID *ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG_PTR HeapSegmentReserve;
    ULONG_PTR HeapSegmentCommit;
    ULONG_PTR HeapDeCommitTotalFreeThreshold;
    ULONG_PTR HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID *ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    KSPIN_LOCK LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ImageProcessAffinityMask;
    ULONG GdiHandleBuffer[34];
    PVOID PostProcessInitRoutine;
    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;
    UNICODE_STRING CSDVersion;
    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;
    ULONG_PTR MinimumStackCommit;
} PEB, *PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

#pragma warning(pop)

//
// -------------------------------------------------------------------------
// EXPORT DEFINITIONS (Fixes VCR001/Linker Errors)
// -------------------------------------------------------------------------
//

// PsGetProcessPeb is exported by ntoskrnl but not always in standard headers
typedef PPEB(NTAPI *PPS_GET_PROCESS_PEB)(_In_ PEPROCESS Process);
extern PPS_GET_PROCESS_PEB fnPsGetProcessPeb;

// ZwProtectVirtualMemory is exported by ntoskrnl (Zw version)
typedef NTSTATUS(NTAPI *PZW_PROTECT_VIRTUAL_MEMORY)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect);
extern PZW_PROTECT_VIRTUAL_MEMORY fnZwProtectVirtualMemory;

// ZwAllocateVirtualMemory is exported by ntoskrnl (Zw version)
typedef NTSTATUS(NTAPI *PZW_ALLOCATE_VIRTUAL_MEMORY)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect);
extern PZW_ALLOCATE_VIRTUAL_MEMORY fnZwAllocateVirtualMemory;

// ZwDuplicateObject is exported by ntoskrnl (Zw version)
typedef NTSTATUS(NTAPI *PZW_DUPLICATE_OBJECT)(
    _In_ HANDLE SourceProcessHandle,
    _In_ HANDLE SourceHandle,
    _In_ HANDLE TargetProcessHandle,
    _Out_ PHANDLE TargetHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Options);
extern PZW_DUPLICATE_OBJECT fnZwDuplicateObject;

// FIX: Declare Free prototype
typedef NTSTATUS(NTAPI *PZW_FREE_VIRTUAL_MEMORY)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType);
extern PZW_FREE_VIRTUAL_MEMORY fnZwFreeVirtualMemory;

typedef NTSTATUS(NTAPI *PZW_FLUSH_INSTRUCTION_CACHE)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ SIZE_T Length);
extern PZW_FLUSH_INSTRUCTION_CACHE fnZwFlushInstructionCache;

//
// -------------------------------------------------------------------------
// ENGINE DEFINITIONS
// -------------------------------------------------------------------------

#define MAX_HOOKED_PROCESSES 256
#define USERMODE_HOOK_SIZE             14   // FF 25 JMP patch written at hooked function
#define USERMODE_HOOK_STOLEN_MAX       28   // shellcode trampoline placeholder;
                                            //   steal >= 14 bytes, rounded up to
                                            //   instruction boundary (max 28)
#define USERMODE_HOOK_SIZE_32 5   // 5-byte  E9 rel32 JMP    for WoW64 (32-bit) hooks
#define MAX_CUSTOM_HOOKS 65536

typedef struct _HOOK_DEF {
    PVOID Address;
    UCHAR OriginalBytes[USERMODE_HOOK_STOLEN_MAX]; // saved stolen bytes; first HookPatchSize bytes used for unhook
    ULONG HookPatchSize;                      // actual patch size: USERMODE_HOOK_SIZE (14) or USERMODE_HOOK_SIZE_32 (5)
    BOOLEAN IsHooked;
} HOOK_DEF, *PHOOK_DEF;

typedef struct _PROCESS_HOOK_ENTRY
{
    ULONG ProcessId;
    PEPROCESS ProcessObject;
    BOOLEAN IsHooked;
    BOOLEAN IsInProgress;
    BOOLEAN IsWow64;          // TRUE if process is WoW64 (32-bit on 64-bit Windows)
    // Set by UserModeUnhookProcess when IsInProgress=TRUE (process died mid-hook).
    // Checked and cleared by UserModeHookProcess when it exits - triggers deferred unhook.
    BOOLEAN NeedsCleanup;

    // Dynamic hooks configured from user mode (allocated per process).
    PHOOK_DEF CustomHooks;
    ULONG CustomHookCapacity;

    // Shellcode specific
    PVOID ShellcodeBase;
    SIZE_T ShellcodeSize;
    SIZE_T ShellcodeUsed;
    HANDLE DriverDeviceHandle;
} PROCESS_HOOK_ENTRY, *PPROCESS_HOOK_ENTRY;

typedef struct _USERMODE_HOOK_ENGINE
{
    BOOLEAN IsInitialized;
    FAST_MUTEX EngineMutex;
    ULONG HookedProcessCount;
    PROCESS_HOOK_ENTRY Processes[MAX_HOOKED_PROCESSES];
} USERMODE_HOOK_ENGINE, *PUSERMODE_HOOK_ENGINE;

//
// Public API
//

NTSTATUS UserModeHookEngineInitialize(VOID);
VOID UserModeHookEngineCleanup(VOID);

NTSTATUS UserModeHookProcess(_In_ ULONG ProcessId);
NTSTATUS UserModeUnhookProcess(_In_ ULONG ProcessId);
NTSTATUS InitializeShellcodeInfrastructure(_In_ PEPROCESS Process, _Inout_ PPROCESS_HOOK_ENTRY HookEntry);
NTSTATUS AddCustomHook(_In_ PHOOK_CONFIG_DATA Config);
_Success_(return != FALSE)
BOOLEAN ResolveHookNameByEventId(_In_ ULONG EventId, _Out_writes_(MAX_FILE_NAME_LENGTH) PWCHAR OutName, _In_ ULONG OutNameCch);

typedef NTSTATUS(NTAPI* PPS_SUSPEND_PROCESS)(_In_ PEPROCESS Process);
typedef NTSTATUS(NTAPI* PPS_RESUME_PROCESS)(_In_ PEPROCESS Process);
