#pragma once

#include <ntstrsafe.h>

//
// --- Process & Thread Access Rights Definitions ---
//

// From winnt.h, for Process Access Rights
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE             (0x0001)
#define PROCESS_CREATE_THREAD         (0x0002)
#define PROCESS_SET_SESSIONID         (0x0004)
#define PROCESS_VM_OPERATION          (0x0008)
#define PROCESS_VM_READ               (0x0010)
#define PROCESS_VM_WRITE              (0x0020)
#define PROCESS_DUP_HANDLE            (0x0040)
#define PROCESS_CREATE_PROCESS        (0x0080)
#define PROCESS_SET_QUOTA             (0x0100)
#define PROCESS_SET_INFORMATION       (0x0200)
#define PROCESS_QUERY_INFORMATION     (0x0400)
#define PROCESS_SUSPEND_RESUME        (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
#define PROCESS_SET_LIMITED_INFORMATION   (0x2000)
#endif

#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE             0x0001
#define THREAD_SUSPEND_RESUME        0x0002
#define THREAD_GET_CONTEXT           0x0008
#define THREAD_SET_CONTEXT           0x0010
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#define THREAD_SET_INFORMATION       0x0020
#define THREAD_QUERY_INFORMATION     0x0040
#define THREAD_SET_THREAD_TOKEN      0x0080
#define THREAD_IMPERSONATE           0x0100
#define THREAD_DIRECT_IMPERSONATION  0x0200
#endif

//
// --- Constants ---
//

#define PID_LIST_TAG 'diPP' // Pool tag for our PID list allocations

// Safe access rights for blocked processes/threads
#define SAFE_PROCESS_ACCESS (PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)
#define SAFE_THREAD_ACCESS (THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)

// Process access rights considered dangerous (for reference only - not used in code)
#define PROCESS_DANGEROUS_MASK (PROCESS_TERMINATE | PROCESS_CREATE_THREAD | \
                                PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION | \
                                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | \
                                PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION | \
                                PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION | PROCESS_SET_LIMITED_INFORMATION)

// Thread access rights considered dangerous (for reference only - not used in code)
#define THREAD_DANGEROUS_MASK (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | \
                               THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN | THREAD_IMPERSONATE | \
                               THREAD_DIRECT_IMPERSONATION)

//
// --- Structures ---
//

// Structure for our linked list entries to track protected PIDs
typedef struct _PROTECTED_PID_ENTRY {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
} PROTECTED_PID_ENTRY, * PPROTECTED_PID_ENTRY;

// Structure for work items used to send alerts to user-mode
typedef struct _PROCESS_ALERT_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    UNICODE_STRING TargetPath;
    UNICODE_STRING AttackerPath;
    HANDLE TargetPid;
    HANDLE AttackerPid;
    WCHAR AttackType[64];
} PROCESS_ALERT_WORK_ITEM, * PPROCESS_ALERT_WORK_ITEM;

//
// --- NT API Definitions ---
//

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenProcessToken(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE TokenHandle
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationToken(
    _In_ HANDLE TokenHandle,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _Out_writes_bytes_to_opt_(TokenInformationLength, *ReturnLength) PVOID TokenInformation,
    _In_ ULONG TokenInformationLength,
    _Out_ PULONG ReturnLength
);

// Define PsGetProcessImageFileName as it is not always in standard WDK headers
NTKERNELAPI
UCHAR*
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
);


//
// --- Function Prototypes ---
//

// Main driver functions
NTSTATUS ProcessDriverEntry();
NTSTATUS ProcessDriverUnload();
NTSTATUS ProtectProcess();

// Kernel callbacks
VOID CreateProcessNotifyRoutine(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

OB_PREOP_CALLBACK_STATUS preCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
);

OB_PREOP_CALLBACK_STATUS threadPreCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
);

// Worker thread for user-mode alerting
VOID ProcessAlertWorker(
    PVOID Context
);

// Helper functions
BOOLEAN IsProtectedProcessByPath(
    _In_ PEPROCESS Process
);

BOOLEAN IsProtectedProcessByPid(
    _In_ HANDLE ProcessId
);

BOOLEAN IsSystemProcess(
    _In_ PEPROCESS Process
);

BOOLEAN UnicodeStringEndsWithInsensitive(
    _In_ PUNICODE_STRING Source,
    _In_ PCWSTR Pattern
);

NTSTATUS QueueProcessAlertToUserMode(
    _In_ PEPROCESS TargetProcess,
    _In_ PEPROCESS AttackerProcess,
    _In_ PCWSTR AttackType
);
