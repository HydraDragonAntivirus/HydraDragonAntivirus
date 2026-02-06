/*++

Module Name:

    UserModeHookEngine.h

Abstract:

    User-mode ntdll.dll hooking engine for modern Windows.
    
    Instead of hooking kernel functions (blocked by PatchGuard),
    this hooks the user-mode syscall stubs in ntdll.dll of each
    monitored process.
    
    This approach:
    - Bypasses PatchGuard (user-mode code modification is allowed)
    - Catches ALL syscalls from user-mode
    - Can block operations before they reach kernel
    - Used by commercial AV/EDR solutions

Environment:

    Kernel mode driver, operates on user-mode memory

--*/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>

//
// Maximum number of processes to hook simultaneously
//

#define MAX_HOOKED_PROCESSES 256

//
// Hook shellcode size (JMP instruction + address)
//

#define USERMODE_HOOK_SIZE 14  // FF 25 00 00 00 00 [8 byte address]

//
// Function signatures for ntdll exports
//

typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);

typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS (NTAPI *pNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

typedef NTSTATUS (NTAPI *pNtSetContextThread)(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
);

//
// Per-process hook information
//

typedef struct _PROCESS_HOOK_ENTRY {
    ULONG ProcessId;
    PEPROCESS ProcessObject;
    BOOLEAN IsHooked;
    
    // Base address of ntdll.dll in target process
    PVOID NtdllBase;
    SIZE_T NtdllSize;
    
    // Original bytes for each hooked function
    UCHAR NtWriteVirtualMemory_Original[USERMODE_HOOK_SIZE];
    UCHAR NtAllocateVirtualMemory_Original[USERMODE_HOOK_SIZE];
    UCHAR NtProtectVirtualMemory_Original[USERMODE_HOOK_SIZE];
    UCHAR NtCreateThreadEx_Original[USERMODE_HOOK_SIZE];
    UCHAR NtQueueApcThread_Original[USERMODE_HOOK_SIZE];
    UCHAR NtSetContextThread_Original[USERMODE_HOOK_SIZE];
    
    // Addresses of functions in target process's ntdll
    PVOID NtWriteVirtualMemory_Addr;
    PVOID NtAllocateVirtualMemory_Addr;
    PVOID NtProtectVirtualMemory_Addr;
    PVOID NtCreateThreadEx_Addr;
    PVOID NtQueueApcThread_Addr;
    PVOID NtSetContextThread_Addr;
    
} PROCESS_HOOK_ENTRY, *PPROCESS_HOOK_ENTRY;

//
// Global hook engine state
//

typedef struct _USERMODE_HOOK_ENGINE {
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

//
// Internal functions
//

PVOID FindModuleBaseAddress(
    _In_ PEPROCESS Process,
    _In_ PCWSTR ModuleName,
    _Out_opt_ PSIZE_T ModuleSize
);

PVOID FindExportedFunction(
    _In_ PVOID ModuleBase,
    _In_ PCSTR FunctionName
);

NTSTATUS InstallUsermodeHook(
    _In_ PEPROCESS Process,
    _In_ PVOID TargetAddress,
    _In_ PVOID HookRoutine,
    _Out_writes_bytes_(USERMODE_HOOK_SIZE) PUCHAR OriginalBytes
);
