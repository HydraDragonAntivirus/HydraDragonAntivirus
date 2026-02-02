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

const WCHAR * const ComPortName = L"\\RWFilter";

#define MAX_FILE_NAME_LENGTH 520
#define MAX_FILE_NAME_SIZE (MAX_FILE_NAME_LENGTH * sizeof(WCHAR)) // max length in bytes of files sizes and dir paths
#define FILE_OBJECT_ID_SIZE 16
#define FILE_OBJEC_MAX_EXTENSION_SIZE 11
// #define MAX_COMM_BUFFER_SIZE 0x100000 // size of the buffer we allocate to recieve irp ops from the driver
// #define MAX_OPS_SAVE 0x10000 // max ops to save, we limit this to prevent driver from filling the non paged memory
// and crashing the os

#define MAX_COMM_BUFFER_SIZE 0x10000 // size of the buffer we allocate to recieve irp ops from the driver
#define MAX_OPS_SAVE                                                                                                   \
    0x1000 // max ops to save, we limit this to prevent driver from filling the non paged memory and crashing the os

// msgs types that the application may send to the driver
enum COM_MESSAGE_TYPE
{
    MESSAGE_ADD_SCAN_DIRECTORY,
    MESSAGE_REM_SCAN_DIRECTORY,
    MESSAGE_GET_OPS,
    MESSAGE_SET_PID,
    MESSAGE_KILL_GID,
    MESSAGE_KILL_AND_QUARANTINE_GID, // NEW: Kill process and quarantine files
    MESSAGE_KILL_ONLY_GID,           // NEW: Kill process without quarantine
    MESSAGE_KILL_AND_REMOVE_GID,     // NEW: Kill process and delete file
    MESSAGE_REVERT_REGISTRY_CHANGES
};

// msgs struct that the application send when sending msg to the driver, type member should be one of the
// COM_MESSAGE_TYPE
typedef struct _COM_MESSAGE
{
    ULONG type;
    ULONG pid;
    ULONGLONG gid;
    WCHAR path[MAX_FILE_NAME_LENGTH];
    WCHAR quarantine_path[MAX_FILE_NAME_LENGTH]; // Added to match usermode

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
    
    // Process-related operations
    IRP_PROCESS_CREATE,                 // Process creation
    IRP_PROCESS_TERMINATE,              // Process termination
    IRP_PROCESS_TERMINATE_ATTEMPT,      // External process attempting to terminate another
    IRP_PROCESS_EXIT,                   // Process exit/cleanup
    IRP_PROCESS_HANDLE_OPEN,            // Process handle opened for access
    
    // Kernel-level API hooks - Injection/Code manipulation
    IRP_KERNEL_WRITE_MEMORY,            // NtWriteVirtualMemory - code injection attempt
    IRP_KERNEL_ALLOCATE_MEMORY,         // NtAllocateVirtualMemory - memory allocation
    IRP_KERNEL_PROTECT_MEMORY,          // NtProtectVirtualMemory - DEP bypass attempt
    IRP_KERNEL_CREATE_THREAD,           // NtCreateThreadEx - remote thread creation
    IRP_KERNEL_QUEUE_APC,               // NtQueueApcThread - APC injection
    IRP_KERNEL_SET_CONTEXT,             // NtSetContextThread - thread context manipulation
    
    // Kernel-level API hooks - File/Section manipulation
    IRP_KERNEL_CREATE_SECTION,          // ZwCreateSection - section creation
    IRP_KERNEL_MAP_SECTION,             // ZwMapViewOfSection - section mapping
    IRP_KERNEL_DELETE_FILE,             // NtDeleteFile - file deletion
    
    // Kernel-level API hooks - Driver/System operations
    IRP_KERNEL_LOAD_DRIVER,             // NtLoadDriver - driver loading
    IRP_KERNEL_OPEN_PROCESS,            // NtOpenProcess - process access
};

// NEW: Action types for threat response
enum THREAT_ACTION_TYPE
{
    THREAT_ACTION_KILL_AND_QUARANTINE = 0,
    THREAT_ACTION_KILL_ONLY = 1
};

// NEW: Kernel event details structure for capturing detailed kernel-level activity
typedef struct _KERNEL_EVENT_INFO
{
    ULONG EventType;                    // IRP_MAJOR_OP type for this event
    ULONGLONG Timestamp;                // Event timestamp
    ULONG SourceProcessId;              // Process initiating the operation
    ULONG TargetProcessId;              // Target process (if applicable)
    
    // Memory operation details
    PVOID MemoryAddress;                // Address involved in operation
    SIZE_T MemorySize;                  // Size of memory operation
    ULONG MemoryProtection;             // Protection flags (for protect/allocate ops)
    BOOLEAN IsExecutableMemory;         // Whether operation targets executable memory
    
    // Thread operation details
    HANDLE ThreadHandle;                // Thread handle (for thread operations)
    PVOID ThreadStartRoutine;           // Start routine (for thread creation)
    
    // File/Section operation details
    WCHAR ObjectName[MAX_FILE_NAME_LENGTH]; // File/section name
    
    // Access control details
    ACCESS_MASK AccessMask;             // Requested access rights
    
    // Operation result
    NTSTATUS OperationStatus;           // Status of the operation
    
} KERNEL_EVENT_INFO, *PKERNEL_EVENT_INFO;

// -64- bytes structure, fixed to -96- bytes, fixed to 104 bytes
typedef struct _DRIVER_MESSAGE
{
    WCHAR Extension[FILE_OBJEC_MAX_EXTENSION_SIZE + 1]; // null terminated 24 bytes

#ifdef _KERNEL_MODE
    FILE_ID_INFORMATION
    FileID; // 24 bytes - file id 128 bits and its volume serial number
#else
    FILE_ID_INFO
    FileID; // 24 bytes - file id 128 bits and its volume serial number
#endif

    ULONGLONG
    MemSizeUsed;            // for read and write, we follow buffer sizes 8 bytes
    DOUBLE Entropy;         // 8 bytes
    ULONG PID;              // 4 bytes
    UCHAR IRP_OP;           // 1 byte
    BOOLEAN isEntropyCalc;  // 1 byte
    UCHAR FileChange;       // 1 byte
    UCHAR FileLocationInfo; // 1 byte align
    UNICODE_STRING
    filePath;      // 16 bytes unicode string - filename, also contains size and max size, buffer is outside the struct
    ULONGLONG Gid; // 8 bytes process ransomwatch gid
    
    // Parent PID of the process
    ULONG ParentPid;        // 4 bytes
    
    // For IRP_PROCESS_TERMINATE_ATTEMPT: Info about the attacker process
    ULONG AttackerPID;      // 4 bytes - PID of process attempting termination (0 if not applicable)
    ULONGLONG AttackerGid;  // 8 bytes - GID of attacker process (0 if not tracked)
    
    // Kernel-level API hooking extended fields
    KERNEL_EVENT_INFO KernelEventInfo;  // Detailed kernel event information
    
    PVOID
    next; // 8 bytes - next PDRIVER_MESSAGE, we use it to allow adding the fileName to the same buffer, this pointer
          // should point to the next PDRIVER_MESSAGE in buffer (kernel handled)

} DRIVER_MESSAGE, *PDRIVER_MESSAGE;

// header for return buffer from driver on irp ops, has pointer to the first driver message, num ops in the buffer and
// readable data size in the buffer
typedef struct _RWD_REPLY_IRPS
{
    size_t dataSize; // 8 bytes
    PDRIVER_MESSAGE
    data; // 8 bytes points to the first IRP driver message, the next DRIVER_MESSAGE is a pointer inside DRIVER_MESSAGE
    ULONGLONG num_ops; // 8 bytes

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
