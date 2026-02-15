/*++
Module Name:
    UserModeHookEngine.h
Abstract:
    User-mode ntdll.dll hooking engine.
    Fixed for complete NtDeviceIoControlFile parameter passing.
Environment:
    Kernel mode driver
--*/

#pragma once

// -------------------------------------------------------------------------
// HEADER FIX: Use ONLY ntifs.h.
// It contains PEPROCESS/PETHREAD definitions.
// Do not include ntddk.h or windef.h alongside it if they conflict.
// -------------------------------------------------------------------------
#include "..\SharedDefs\SharedDefs.h"
#include <ntifs.h>

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
typedef NTSTATUS(NTAPI *PZW_PROTECT_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                    _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtect,
                                                    _Out_ PULONG OldProtect);
extern PZW_PROTECT_VIRTUAL_MEMORY fnZwProtectVirtualMemory;

// ZwAllocateVirtualMemory is exported by ntoskrnl (Zw version)
typedef NTSTATUS(NTAPI *PZW_ALLOCATE_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                     _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize,
                                                     _In_ ULONG AllocationType, _In_ ULONG Protect);
extern PZW_ALLOCATE_VIRTUAL_MEMORY fnZwAllocateVirtualMemory;

// ZwDuplicateObject is exported by ntoskrnl (Zw version)
typedef NTSTATUS(NTAPI *PZW_DUPLICATE_OBJECT)(_In_ HANDLE SourceProcessHandle, _In_ HANDLE SourceHandle,
                                              _In_ HANDLE TargetProcessHandle, _Out_ PHANDLE TargetHandle,
                                              _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes,
                                              _In_ ULONG Options);
extern PZW_DUPLICATE_OBJECT fnZwDuplicateObject;

// FIX: Declare Free prototype
typedef NTSTATUS(NTAPI *PZW_FREE_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                 _Inout_ PSIZE_T RegionSize, _In_ ULONG FreeType);
extern PZW_FREE_VIRTUAL_MEMORY fnZwFreeVirtualMemory;

//
// -------------------------------------------------------------------------
// ENGINE DEFINITIONS
// -------------------------------------------------------------------------

#define MAX_HOOKED_PROCESSES 512
#define USERMODE_HOOK_SIZE 14
#define MAX_CUSTOM_HOOKS 8192 // Increased to 8k for comprehensive API monitoring

extern HOOK_CONFIG_DATA g_GlobalCustomHooks[MAX_CUSTOM_HOOKS];
extern ULONG g_CustomHookCount;
extern FAST_MUTEX g_ConfigMutex;

typedef struct _HOOK_DEF
{
    PVOID Address;
    UCHAR OriginalBytes[USERMODE_HOOK_SIZE];
    BOOLEAN IsHooked;
} HOOK_DEF, *PHOOK_DEF;

typedef struct _PROCESS_HOOK_ENTRY
{
    ULONG ProcessId;
    PEPROCESS ProcessObject;
    BOOLEAN IsHooked;
    // Generic: No single base. We find base per hook if needed.
    // PVOID NtdllBase;
    // SIZE_T NtdllSize;

    // Hooked Functions
    HOOK_DEF NtWriteVirtualMemory;
    HOOK_DEF NtAllocateVirtualMemory;
    HOOK_DEF NtProtectVirtualMemory;
    HOOK_DEF NtCreateThreadEx;
    HOOK_DEF NtMapViewOfSection;

    // Dynamic Hooks (Dynamically Allocated - sized to MAX_CUSTOM_HOOKS)
    PHOOK_DEF CustomHooks;

    // Shellcode specific
    PVOID ShellcodeBase;
    SIZE_T ShellcodeSize;
    SIZE_T ShellcodeUsed;
    HANDLE DriverDeviceHandle;
    PVOID NtDeviceIoControlFileAddr; // Cached for re-hooking
} PROCESS_HOOK_ENTRY, *PPROCESS_HOOK_ENTRY;

typedef struct _USERMODE_HOOK_ENGINE
{
    BOOLEAN IsInitialized;
    FAST_MUTEX EngineMutex;
    ULONG HookedProcessCount;
    PROCESS_HOOK_ENTRY Processes[MAX_HOOKED_PROCESSES];
} USERMODE_HOOK_ENGINE, *PUSERMODE_HOOK_ENGINE;

// Public API
//

NTSTATUS UserModeHookEngineInitialize(VOID);
VOID UserModeHookEngineCleanup(VOID);

NTSTATUS UserModeHookProcess(_In_ ULONG ProcessId, _In_opt_ PVOID ImageBase);
NTSTATUS UserModeUnhookProcess(_In_ ULONG ProcessId);
NTSTATUS UserModeUnhookProcessInternal(_Inout_ PPROCESS_HOOK_ENTRY HookEntry);

// Expose these if needed or keep static in cpp
NTSTATUS InitializeShellcodeInfrastructure(_In_ PEPROCESS Process, _Inout_ PPROCESS_HOOK_ENTRY HookEntry);

// Generic Config
NTSTATUS AddCustomHook(_In_ PHOOK_CONFIG_DATA Config);
