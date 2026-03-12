#pragma once

/*++

Module Name:

    FsFilter.h

Abstract:

    Header file for the kernel FS driver

Environment:

    Kernel mode

--*/

#include <dontuse.h>
#include <fltKernel.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <suppress.h>
#include <wdm.h>

#include "../SharedDefs/SharedDefs.h"
#include "Communication.h"
#include "DriverData.h"
#include "KernelString.h"
#include "ShanonEntropy.h"

extern "C" UCHAR* PsGetProcessImageFileName(PEPROCESS Process);

NTSTATUS
FSUnloadDriver(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

FLT_POSTOP_CALLBACK_STATUS
FSPostOperation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS
FSPreOperation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
               _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

NTSTATUS
FSInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

NTSTATUS
FSInstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

VOID FSInstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

VOID FSInstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

// handles pre operation for read, write, set info and close files
NTSTATUS
FSProcessPreOperation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                       _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

NTSTATUS
FSEntrySetFileName(const PFLT_VOLUME volume, PFLT_FILE_NAME_INFORMATION nameInfo, PUNICODE_STRING uString);

FLT_POSTOP_CALLBACK_STATUS
FSProcessPostReadIrp(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                     _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_POSTOP_CALLBACK_STATUS
FSProcessPostReadSafe(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                      _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

// handles IRP_MJ_CREATE irps on post op
FLT_POSTOP_CALLBACK_STATUS
FSProcessCreateIrp(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects);

// compares unicode string file name to the directories in protected areas in driverData object
// return true if the file is in one of the dirs
BOOLEAN
FSIsFileNameInScanDirs(CONST PUNICODE_STRING path);

// NEW: Enumerate all existing processes on driver load
VOID EnumerateExistingProcesses(VOID);

// ZwQueryInformationProcess - dynamic loaded function which query info data about already opened processes
typedef NTSTATUS (*QUERY_INFO_PROCESS)(__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass,
                                       __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
                                       __in ULONG ProcessInformationLength, __out_opt PULONG ReturnLength);

// FIX: Declare as extern volatile to match the definition in the .c file
// This ensures the compiler knows this is shared across compilation units and prevents optimization issues
extern volatile QUERY_INFO_PROCESS ZwQueryInformationProcess;

// copy the file id info from the data argument (FLT_CALLBACK_DATA) to DRIVER_MESSAGE class allocated
NTSTATUS
CopyFileIdInfo(_Inout_ PFLT_CALLBACK_DATA Data, PDRIVER_MESSAGE newItem);

// recieves a pointer to allocated unicode string, FLT_RELATED_OBJECTS and FILE_NAME_INFORMATION class.
// function gets the file name from the name info and flt objects and fill the unicode string with it
NTSTATUS GetFileNameInfo(_In_ PCFLT_RELATED_OBJECTS FltObjects, PUNICODE_STRING FilePath,
                         PFLT_FILE_NAME_INFORMATION nameInfo);

// copy extension info from FILE_NAME_INFORMATION class to null terminated wchar string
VOID CopyExtension(PWCHAR dest, PFLT_FILE_NAME_INFORMATION nameInfo);

// Process creation/termination callback with extended process-create metadata (command line, image path, etc.).
VOID AddRemProcessRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

VOID AddRemProcessRoutineLegacy(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
);

// Process and quarantine functions
NTSTATUS GetProcessNameByHandle(_In_ HANDLE ProcessHandle, _Out_ PUNICODE_STRING *Name);
NTSTATUS GetProcessCommandLineByHandle(_In_ HANDLE ProcessHandle, _Out_ PUNICODE_STRING *CommandLine);
NTSTATUS DeleteFileByPath(PUNICODE_STRING FilePath);
NTSTATUS QuarantineFileByPath(PUNICODE_STRING FilePath);
VOID FSReloadPyasWhitelistRules(VOID);

// FIX: This global variable should be removed or properly managed
// Global variables in drivers should be avoided when possible
// If needed, it should be properly initialized and synchronized
extern UNICODE_STRING GvolumeData;

// -------------------------------------------------------------------------
// Manual declarations for ZwQuerySystemInformation + SYSTEM_PROCESS_INFORMATION
//
// These are NOT reliably exposed by any standard WDK kernel-mode header
// (<ntddk.h>, <ntifs.h>, <wdm.h>) across all WDK versions. Declaring them
// manually here is the standard approach used in all production kernel drivers
// that need process enumeration, matching how ZwQueryInformationProcess is
// already handled in this codebase.
// -------------------------------------------------------------------------

typedef enum _SYSTEM_INFORMATION_CLASS_LOCAL {
    SystemProcessInformationLocal = 5
} SYSTEM_INFORMATION_CLASS_LOCAL;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG           NextEntryOffset;
    ULONG           NumberOfThreads;
    LARGE_INTEGER   WorkingSetPrivateSize;
    ULONG           HardFaultCount;
    ULONG           NumberOfThreadsHighWatermark;
    ULONGLONG       CycleTime;
    LARGE_INTEGER   CreateTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   KernelTime;
    UNICODE_STRING  ImageName;
    LONG            BasePriority;
    HANDLE          UniqueProcessId;
    HANDLE          InheritedFromUniqueProcessId;
    ULONG           HandleCount;
    ULONG           SessionId;
    ULONG_PTR       UniqueProcessKey;
    SIZE_T          PeakVirtualSize;
    SIZE_T          VirtualSize;
    ULONG           PageFaultCount;
    SIZE_T          PeakWorkingSetSize;
    SIZE_T          WorkingSetSize;
    SIZE_T          QuotaPeakPagedPoolUsage;
    SIZE_T          QuotaPagedPoolUsage;
    SIZE_T          QuotaPeakNonPagedPoolUsage;
    SIZE_T          QuotaNonPagedPoolUsage;
    SIZE_T          PagefileUsage;
    SIZE_T          PeakPagefileUsage;
    SIZE_T          PrivatePageCount;
    LARGE_INTEGER   ReadOperationCount;
    LARGE_INTEGER   WriteOperationCount;
    LARGE_INTEGER   OtherOperationCount;
    LARGE_INTEGER   ReadTransferCount;
    LARGE_INTEGER   WriteTransferCount;
    LARGE_INTEGER   OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS (NTAPI *PZW_QUERY_SYSTEM_INFORMATION)(
    _In_      ULONG SystemInformationClass,
    _Inout_   PVOID SystemInformation,
    _In_      ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

static PZW_QUERY_SYSTEM_INFORMATION g_fnZwQuerySystemInformation = NULL;
