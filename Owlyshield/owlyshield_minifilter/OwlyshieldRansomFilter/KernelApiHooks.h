#pragma once

/*++

Module Name:

    KernelApiHooks.h

Abstract:

    Kernel API hooking implementations for critical system calls.
    Hooks kernel-mode APIs to detect malicious behavior.

Environment:

    Kernel mode only

--*/

#include <ntifs.h>
#include <ntddk.h>
#include "KernelHookEngine.h"
#include "SharedDefs.h"

//
// Forward declarations of kernel APIs we'll hook
//

// NtTerminateProcess - detect process termination attempts
typedef NTSTATUS (NTAPI *pNtTerminateProcess)(
    _In_opt_ HANDLE ProcessHandle,
    _In_ NTSTATUS ExitStatus
);

// NtOpenProcess - detect process access attempts
typedef NTSTATUS (NTAPI *pNtOpenProcess)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
);

// NtWriteVirtualMemory - detect code injection
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);

// NtCreateThreadEx - detect remote thread creation
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags,
    _In_opt_ SIZE_T ZeroBits,
    _In_opt_ SIZE_T StackSize,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ PVOID AttributeList
);

// NtSetInformationFile - detect file operations
typedef NTSTATUS (NTAPI *pNtSetInformationFile)(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass
);

// NtDeleteFile - detect file deletion
typedef NTSTATUS (NTAPI *pNtDeleteFile)(
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
);

// NtAllocateVirtualMemory - detect memory allocation for code injection
typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);

// NtProtectVirtualMemory - detect DEP bypass attempts
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);

// NtQueueApcThread - detect APC injection
typedef NTSTATUS (NTAPI *pNtQueueApcThread)(
    _In_ HANDLE ThreadHandle,
    _In_ PVOID ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
);

// NtSetContextThread - detect thread context manipulation
typedef NTSTATUS (NTAPI *pNtSetContextThread)(
    _In_ HANDLE ThreadHandle,
    _In_ PCONTEXT ThreadContext
);

// NtLoadDriver - detect driver loading
typedef NTSTATUS (NTAPI *pNtLoadDriver)(
    _In_ PUNICODE_STRING DriverServiceName
);

// ZwCreateSection - detect section creation for code injection
typedef NTSTATUS (NTAPI *pZwCreateSection)(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
);

// ZwMapViewOfSection - detect section mapping for code injection
typedef NTSTATUS (NTAPI *pZwMapViewOfSection)(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ ULONG InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect
);

//
// Trampoline function pointers (for calling original functions)
//

extern pNtTerminateProcess g_OriginalNtTerminateProcess;
extern pNtOpenProcess g_OriginalNtOpenProcess;
extern pNtWriteVirtualMemory g_OriginalNtWriteVirtualMemory;
extern pNtCreateThreadEx g_OriginalNtCreateThreadEx;
extern pNtSetInformationFile g_OriginalNtSetInformationFile;
extern pNtDeleteFile g_OriginalNtDeleteFile;
extern pNtAllocateVirtualMemory g_OriginalNtAllocateVirtualMemory;
extern pNtProtectVirtualMemory g_OriginalNtProtectVirtualMemory;
extern pNtQueueApcThread g_OriginalNtQueueApcThread;
extern pNtSetContextThread g_OriginalNtSetContextThread;
extern pNtLoadDriver g_OriginalNtLoadDriver;
extern pZwCreateSection g_OriginalZwCreateSection;
extern pZwMapViewOfSection g_OriginalZwMapViewOfSection;

//
// Hook function declarations
//

NTSTATUS NTAPI HookedNtTerminateProcess(
    _In_opt_ HANDLE ProcessHandle,
    _In_ NTSTATUS ExitStatus
);

NTSTATUS NTAPI HookedNtOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
);

NTSTATUS NTAPI HookedNtWriteVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);

NTSTATUS NTAPI HookedNtCreateThreadEx(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags,
    _In_opt_ SIZE_T ZeroBits,
    _In_opt_ SIZE_T StackSize,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ PVOID AttributeList
);

NTSTATUS NTAPI HookedNtSetInformationFile(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass
);

NTSTATUS NTAPI HookedNtDeleteFile(
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS NTAPI HookedNtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);

NTSTATUS NTAPI HookedNtProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);

NTSTATUS NTAPI HookedNtQueueApcThread(
    _In_ HANDLE ThreadHandle,
    _In_ PVOID ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
);

NTSTATUS NTAPI HookedNtSetContextThread(
    _In_ HANDLE ThreadHandle,
    _In_ PCONTEXT ThreadContext
);

NTSTATUS NTAPI HookedNtLoadDriver(
    _In_ PUNICODE_STRING DriverServiceName
);

NTSTATUS NTAPI HookedZwCreateSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
);

NTSTATUS NTAPI HookedZwMapViewOfSection(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ ULONG InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect
);

//
// Hook installation/removal
//

NTSTATUS InstallKernelApiHooks(VOID);
VOID RemoveKernelApiHooks(VOID);

//
// Helper functions
//

BOOLEAN IsProtectedProcess(ULONG Pid);
BOOLEAN IsExecutableProtection(ULONG Protect);
VOID LogSuspiciousActivity(
    _In_ LPCSTR ActivityType,
    _In_ ULONG SourcePid,
    _In_ ULONG TargetPid,
    _In_opt_ LPCWSTR AdditionalInfo
);

#endif // KERNEL_API_HOOKS_H
