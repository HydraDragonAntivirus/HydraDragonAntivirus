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
extern "C" NTKERNELAPI PPEB PsGetProcessPeb(_In_ PEPROCESS Process);

// ZwProtectVirtualMemory is exported by ntoskrnl (Zw version)
extern "C" NTKERNELAPI NTSTATUS ZwProtectVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                       _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtect,
                                                       _Out_ PULONG OldProtect);

//
// -------------------------------------------------------------------------
// ENGINE DEFINITIONS
// -------------------------------------------------------------------------

#define MAX_HOOKED_PROCESSES 256
#define USERMODE_HOOK_SIZE 14

typedef struct _PROCESS_HOOK_ENTRY
{
    ULONG ProcessId;
    PEPROCESS ProcessObject;
    BOOLEAN IsHooked;
    PVOID NtdllBase;
    SIZE_T NtdllSize;
    UCHAR NtWriteVirtualMemory_Original[USERMODE_HOOK_SIZE];
    UCHAR NtAllocateVirtualMemory_Original[USERMODE_HOOK_SIZE];
    PVOID NtWriteVirtualMemory_Addr;
    PVOID NtAllocateVirtualMemory_Addr;
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

// Updated Prototype
NTSTATUS UserModeHookProcess(_In_ ULONG ProcessId, _In_opt_ PVOID DetourAddress_NtWrite,
                             _In_opt_ PVOID DetourAddress_NtAlloc);
NTSTATUS UserModeUnhookProcess(_In_ ULONG ProcessId);
