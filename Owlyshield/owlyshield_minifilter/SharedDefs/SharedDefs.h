#pragma once

/*++

Abstract :

Header file which contains the structures, type definitions,
constants, global variables and function prototypes that are
shared between kernel and user mode.

Environment :

    Kernel & user mode

--*/

//
// Note: This header is included after fltKernel.h in kernel mode
// and after windows.h in user mode, so types are already defined
//

//
//  Name of port used to communicate
//

const WCHAR *const ComPortName = L"\\RWFilter";

// Fix C4005: Macro redefinition warning
#ifndef MAX_FILE_NAME_LENGTH
#define MAX_FILE_NAME_LENGTH 520
#endif

// Define IOCTL for Shellcode -> Driver communication
#define FILE_DEVICE_OWLYSHIELD 0x8000
#define IOCTL_REPORT_HOOK_EVENT CTL_CODE(FILE_DEVICE_OWLYSHIELD, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _HOOK_EVENT_DATA {
    ULONG EventType;
    ULONG ProcessId;
    WCHAR FunctionName[64];
    // Generic arguments storage (up to 4 arguments for now to keep it simple)
    ULONG_PTR Arg1;
    ULONG_PTR Arg2;
    ULONG_PTR Arg3;
    ULONG_PTR Arg4;
} HOOK_EVENT_DATA, *PHOOK_EVENT_DATA;

#define MAX_FILE_NAME_SIZE (MAX_FILE_NAME_LENGTH * sizeof(WCHAR))
#define FILE_OBJECT_ID_SIZE 16
#define FILE_OBJEC_MAX_EXTENSION_SIZE 11

#define MAX_COMM_BUFFER_SIZE 0x10000
#define MAX_OPS_SAVE 0x1000

enum COM_MESSAGE_TYPE
{
    MESSAGE_ADD_SCAN_DIRECTORY,
    MESSAGE_REM_SCAN_DIRECTORY,
    MESSAGE_GET_OPS,
    MESSAGE_SET_PID,
    MESSAGE_KILL_GID,
    MESSAGE_KILL_AND_QUARANTINE_GID, // Kill process and quarantine files
    MESSAGE_KILL_ONLY_GID,           // Kill process without quarantine
    MESSAGE_KILL_AND_REMOVE_GID,     // Kill process and delete file
    MESSAGE_REVERT_REGISTRY_CHANGES,
    MESSAGE_ADD_HOOK,                 // Dynamic Hook Config
    MESSAGE_HOOK_PROCESS              // Force hook a specific PID
};

#define IOCTL_HOOK_PROCESS CTL_CODE(FILE_DEVICE_OWLYSHIELD, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

// msgs struct that the application send when sending msg to the driver, type member should be one of the
// COM_MESSAGE_TYPE
typedef struct _COM_MESSAGE
{
    ULONG type;
    ULONG pid;
    ULONGLONG gid;
    WCHAR path[MAX_FILE_NAME_LENGTH];
    WCHAR quarantine_path[MAX_FILE_NAME_LENGTH];

} COM_MESSAGE, *PCOM_MESSAGE;

enum FILE_CHANGE_INFO
{
    FILE_CHANGE_NOT_SET,
    FILE_OPEN_DIRECTORY,
    FILE_CHANGE_WRITE,
    FILE_CHANGE_NEW_FILE,
    FILE_CHANGE_RENAME_FILE,
    FILE_CHANGE_EXTENSION_CHANGED,
    FILE_CHANGE_DELETE_FILE,
    FILE_CHANGE_DELETE_NEW_FILE,
    FILE_CHANGE_OVERWRITE_FILE,
    REG_CREATE_KEY,
    REG_SET_VALUE,
    REG_DELETE_VALUE,
    REG_RENAME_KEY
};

enum FILE_LOCATION_INFO
{
    FILE_NOT_PROTECTED, // nothing to set, not protected
    FILE_PROTECTED,     // if not read remember change in file
    FILE_MOVED_IN,      // new file to remove from protected
    FILE_MOVED_OUT      // keep filename if not already exist
};

enum IRP_MAJOR_OP
{
    IRP_NONE,
    IRP_READ,
    IRP_WRITE,
    IRP_SETINFO,
    IRP_CREATE,
    IRP_CLEANUP,
    IRP_REGISTRY,

    IRP_PROCESS_CREATE,
    IRP_PROCESS_TERMINATE,
    IRP_PROCESS_TERMINATE_ATTEMPT,
    IRP_PROCESS_EXIT,
    IRP_PROCESS_HANDLE_OPEN,

    IRP_NT_WRITE_VIRTUAL_MEMORY,
    IRP_NT_ALLOCATE_VIRTUAL_MEMORY,
    IRP_NT_PROTECT_VIRTUAL_MEMORY,
    IRP_NT_CREATE_THREAD,
    IRP_NT_QUEUE_APC,
    IRP_NT_SET_CONTEXT,

    IRP_NT_CREATE_SECTION,
    IRP_NT_MAP_SECTION,
    IRP_NT_DELETE_FILE,

    IRP_NT_LOAD_DRIVER,
    IRP_NT_OPEN_PROCESS,
    IRP_NT_GENERIC_API_CALL, // 23
};

// Aliases to resolve E0020 (Undefined identifier) in ProcessProtection.cpp
#define IRP_KERNEL_WRITE_MEMORY IRP_NT_WRITE_VIRTUAL_MEMORY
#define IRP_KERNEL_PROTECT_MEMORY IRP_NT_PROTECT_VIRTUAL_MEMORY
#define IRP_KERNEL_CREATE_THREAD IRP_NT_CREATE_THREAD
#define IRP_KERNEL_QUEUE_APC IRP_NT_QUEUE_APC
#define IRP_KERNEL_CREATE_SECTION IRP_NT_CREATE_SECTION
// Define IOCTL for Dynamic Hook Configuration
#define IOCTL_ADD_HOOK_TARGET CTL_CODE(FILE_DEVICE_OWLYSHIELD, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _HOOK_CONFIG_DATA {
    WCHAR ModuleName[64];
    CHAR FunctionName[64];
    ULONG EventId;
} HOOK_CONFIG_DATA, *PHOOK_CONFIG_DATA;

// ... (Existing Macros) ...

// Add Generic Event ID
#define IRP_KERNEL_MAP_SECTION IRP_NT_MAP_SECTION
// IRP_GENERIC_API_CALL will be 23


enum THREAT_ACTION_TYPE
{
    THREAT_ACTION_KILL_AND_QUARANTINE = 0,
    THREAT_ACTION_KILL_ONLY = 1
};

typedef struct _NTDLL_EVENT_INFO
{
    ULONG EventType;
    ULONGLONG Timestamp;
    ULONG SourceProcessId;
    ULONG TargetProcessId;

    PVOID MemoryAddress;
    SIZE_T MemorySize;
    ULONG MemoryProtection;
    BOOLEAN IsExecutableMemory;

    HANDLE ThreadHandle;
    PVOID ThreadStartRoutine;

    WCHAR ObjectName[MAX_FILE_NAME_LENGTH];

    ACCESS_MASK AccessMask;
    NTSTATUS OperationStatus;
} NTDLL_EVENT_INFO, *PNTDLL_EVENT_INFO;

// Alias to satisfy KERNEL_EVENT_INFO usage
typedef NTDLL_EVENT_INFO KERNEL_EVENT_INFO;

typedef struct _DRIVER_MESSAGE
{
    WCHAR Extension[FILE_OBJEC_MAX_EXTENSION_SIZE + 1];

#ifdef _KERNEL_MODE
    FILE_ID_INFORMATION FileID;
#else
    FILE_ID_INFO FileID;
#endif

    ULONGLONG MemSizeUsed;
    DOUBLE Entropy;
    ULONG PID;
    UCHAR IRP_OP;
    BOOLEAN isEntropyCalc;
    UCHAR FileChange;
    UCHAR FileLocationInfo;
    UNICODE_STRING filePath;
    ULONGLONG Gid;
    ULONG ParentPid;
    ULONG AttackerPID;
    ULONGLONG AttackerGid;

    // Union to resolve E0135 (No member KernelEventInfo)
    union {
        NTDLL_EVENT_INFO NtdllEventInfo;
        NTDLL_EVENT_INFO KernelEventInfo;
    };

    PVOID next;

} DRIVER_MESSAGE, *PDRIVER_MESSAGE;

typedef struct _RWD_REPLY_IRPS
{
    size_t dataSize;
    PDRIVER_MESSAGE data;
    ULONGLONG num_ops;

    size_t size()
    {
        return dataSize + sizeof(_RWD_REPLY_IRPS);
    }
    size_t addSize(size_t size)
    {
        dataSize += size;
        return dataSize;
    }
    ULONGLONG addOp()
    {
        num_ops++;
        return num_ops;
    }
    ULONGLONG numOps()
    {
        return num_ops;
    }
    _RWD_REPLY_IRPS() : dataSize(sizeof(_RWD_REPLY_IRPS)), data(nullptr), num_ops(0)
    {
    }
} RWD_REPLY_IRPS, *PRWD_REPLY_IRPS;
