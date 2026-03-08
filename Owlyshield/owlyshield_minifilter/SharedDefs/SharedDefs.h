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
// IMPORTANT:
// This shared header assumes core Windows/WDK types are already available
// through the including translation unit (for example via <fltKernel.h>).
// Do not include <Windows.h>/<ntifs.h> here: doing so under non-default pack
// pragmas can trigger ntdef packing assertions and cascading parse errors.
//

//
//  Name of port used to communicate
//

const WCHAR *const ComPortName = L"\\RWFilter";

// Shared dynamic-hook exclusion rule file path (kernel/user-mode deployment target).
#define OWLY_DYNAMIC_HOOK_RULE_FILE_KERNEL L"\\??\\C:\\Program Files\\HydraDragonAntivirus\\hydradragon\\PYAS_Protection\\PYAS_Protection_Rules\\Process\\Owlyshield\\DynamicHook\\default_rules.txt"
// Shared ProcessProtection rule file path (kernel-side exclude list).
#define OWLY_PROCESS_PROTECTION_RULE_FILE_KERNEL L"\\??\\C:\\Program Files\\HydraDragonAntivirus\\hydradragon\\PYAS_Protection\\PYAS_Protection_Rules\\Process\\Owlyshield\\ProcessProtection\\default_rules.txt"
// Shared FsFilter rule file path (kernel-side ignore list).
#define OWLY_FSFILTER_RULE_FILE_KERNEL L"\\??\\C:\\Program Files\\HydraDragonAntivirus\\hydradragon\\PYAS_Protection\\PYAS_Protection_Rules\\Process\\Owlyshield\\FSFilter\\default_rules.txt"

// Fix C4005: Macro redefinition warning
#ifndef MAX_FILE_NAME_LENGTH
#define MAX_FILE_NAME_LENGTH 520
#endif

// Global path normalization helper (shared by kernel components).
// - lowercases
// - '/' -> '\'
// - strips leading "\??\" / "\\?\"
// - maps "\Device\HarddiskVolumeX\..." to "c:\..."
static __forceinline BOOLEAN OwlyNormalizePathForMatch(_In_ PCUNICODE_STRING InputPath,
                                                        _Out_writes_(MAX_FILE_NAME_LENGTH) PWCHAR OutputBuffer,
                                                        _Out_ PUNICODE_STRING NormalizedPath)
{
    static const WCHAR kDevicePrefix[] = L"\\device\\harddiskvolume";
    const USHORT kDevicePrefixLen = (USHORT)(RTL_NUMBER_OF(kDevicePrefix) - 1);
    USHORT charsToCopy;

    if (InputPath == NULL ||
        OutputBuffer == NULL ||
        NormalizedPath == NULL ||
        InputPath->Buffer == NULL ||
        InputPath->Length == 0)
    {
        return FALSE;
    }

    charsToCopy = InputPath->Length / sizeof(WCHAR);
    if (charsToCopy >= MAX_FILE_NAME_LENGTH)
    {
        charsToCopy = MAX_FILE_NAME_LENGTH - 1;
    }

    for (USHORT i = 0; i < charsToCopy; ++i)
    {
        WCHAR ch = InputPath->Buffer[i];
        if (ch == L'/')
        {
            ch = L'\\';
        }
        OutputBuffer[i] = RtlDowncaseUnicodeChar(ch);
    }
    OutputBuffer[charsToCopy] = L'\0';

    if (charsToCopy >= 4 &&
        OutputBuffer[0] == L'\\' &&
        OutputBuffer[1] == L'?' &&
        OutputBuffer[2] == L'?' &&
        OutputBuffer[3] == L'\\')
    {
        RtlMoveMemory(OutputBuffer, OutputBuffer + 4, (charsToCopy - 4 + 1) * sizeof(WCHAR));
        charsToCopy -= 4;
    }
    else if (charsToCopy >= 4 &&
             OutputBuffer[0] == L'\\' &&
             OutputBuffer[1] == L'\\' &&
             OutputBuffer[2] == L'?' &&
             OutputBuffer[3] == L'\\')
    {
        RtlMoveMemory(OutputBuffer, OutputBuffer + 4, (charsToCopy - 4 + 1) * sizeof(WCHAR));
        charsToCopy -= 4;
    }

    if (charsToCopy > kDevicePrefixLen &&
        RtlCompareMemory(OutputBuffer, kDevicePrefix, kDevicePrefixLen * sizeof(WCHAR)) == (kDevicePrefixLen * sizeof(WCHAR)))
    {
        USHORT i = kDevicePrefixLen;
        while (i < charsToCopy && OutputBuffer[i] >= L'0' && OutputBuffer[i] <= L'9')
        {
            ++i;
        }

        if (i < charsToCopy && OutputBuffer[i] == L'\\')
        {
            USHORT tailStart = i + 1;
            USHORT tailLen = (tailStart <= charsToCopy) ? (charsToCopy - tailStart) : 0;
            if (tailLen + 3 >= MAX_FILE_NAME_LENGTH)
            {
                tailLen = MAX_FILE_NAME_LENGTH - 4;
            }

            if (tailLen > 0)
            {
                RtlMoveMemory(OutputBuffer + 3, OutputBuffer + tailStart, tailLen * sizeof(WCHAR));
            }

            OutputBuffer[0] = L'c';
            OutputBuffer[1] = L':';
            OutputBuffer[2] = L'\\';
            charsToCopy = (USHORT)(3 + tailLen);
            OutputBuffer[charsToCopy] = L'\0';
        }
    }

    NormalizedPath->Buffer = OutputBuffer;
    NormalizedPath->Length = charsToCopy * sizeof(WCHAR);
    NormalizedPath->MaximumLength = (charsToCopy + 1) * sizeof(WCHAR);
    return TRUE;
}

// Define IOCTL for Shellcode -> Driver communication
#define FILE_DEVICE_OWLYSHIELD 0x8000
#define IOCTL_REPORT_HOOK_EVENT CTL_CODE(FILE_DEVICE_OWLYSHIELD, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _HOOK_EVENT_DATA {
    ULONG EventType;
    ULONG ProcessId;
    CHAR FunctionName[64];
    // Generic argument storage copied by the hook shellcode (up to 4 arguments).
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

    // Single normalized opcode for all hypervisor-origin events
    IRP_HYPERVISOR_EVENT,
};

// Distinct raw kernel/hypervisor event ids (kept in 13..19 range).
// User-mode keeps these opcodes distinct from IRP_HYPERVISOR_EVENT.
#define IRP_KERNEL_REMOTE_THREAD 13
#define IRP_KERNEL_WRITE_MEMORY 14
#define IRP_KERNEL_PROTECT_MEMORY 15
#define IRP_KERNEL_CREATE_THREAD 16
#define IRP_KERNEL_QUEUE_APC 17
#define IRP_KERNEL_CREATE_SECTION 18
#define IRP_KERNEL_MAP_SECTION 19
// Define IOCTL for Dynamic Hook Configuration
#define IOCTL_ADD_HOOK_TARGET CTL_CODE(FILE_DEVICE_OWLYSHIELD, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _HOOK_CONFIG_DATA {
    WCHAR ModuleName[64];
    CHAR FunctionName[256];
    ULONG EventId;
} HOOK_CONFIG_DATA, *PHOOK_CONFIG_DATA;

// ... (Existing Macros) ...

// Generic hypervisor event id is represented by IRP_HYPERVISOR_EVENT.


enum THREAT_ACTION_TYPE
{
    THREAT_ACTION_KILL_AND_QUARANTINE = 0,
    THREAT_ACTION_KILL_ONLY = 1
};

typedef struct _KERNEL_EVENT_INFO
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

    // Raw HIM/API-hook arguments for lossless forwarding to user-mode.
    ULONG_PTR RawArgument1;
    ULONG_PTR RawArgument2;
    ULONG_PTR RawArgument3;
    ULONG_PTR RawArgument4;

    WCHAR ObjectName[MAX_FILE_NAME_LENGTH];

    ACCESS_MASK AccessMask;
    NTSTATUS OperationStatus;
} KERNEL_EVENT_INFO, *PKERNEL_EVENT_INFO;

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
    WCHAR CommandLine[MAX_FILE_NAME_LENGTH];
    ULONG AttackerPID;
    ULONGLONG AttackerGid;

    KERNEL_EVENT_INFO KernelEventInfo;

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
