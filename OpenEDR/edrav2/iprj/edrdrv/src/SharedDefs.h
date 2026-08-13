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
// Hypervisor (VMM/HyperDbg) bridge support switch.
// The standalone hypervisor is no longer part of the product; this compiles
// to 0 so the VMM registration and hypervisor-event queue code is disabled.
// Set to 1 only if an external hypervisor is reintroduced.
//
#ifndef OWLY_HYPERVISOR_SUPPORT
#define OWLY_HYPERVISOR_SUPPORT 0
#endif

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

// Quarantine directory path (shared across all components)
const WCHAR *const QuarantinePath = L"\\??\\C:\\ProgramData\\HydraDragonQuarantine";

// Rule file paths removed for security (mitigates path-based vulnerabilities).
// Rules are now pushed via Comms from a PPL process.

// Fix C4005: Macro redefinition warning
#ifndef MAX_FILE_NAME_LENGTH
#define MAX_FILE_NAME_LENGTH 520
#endif

static __forceinline SIZE_T OwlyBoundedWideLength(_In_reads_(MaxChars) PCWSTR Value, _In_ SIZE_T MaxChars)
{
    SIZE_T length = 0;

    if (Value == NULL || MaxChars == 0)
    {
        return 0;
    }

    while (length < MaxChars && Value[length] != L'\0')
    {
        ++length;
    }

    return length;
}

static __forceinline BOOLEAN OwlyWideEqualsInsensitiveBounded(_In_reads_(LeftMaxChars) PCWSTR Left,
                                                              _In_ SIZE_T LeftMaxChars,
                                                              _In_reads_(RightMaxChars) PCWSTR Right,
                                                              _In_ SIZE_T RightMaxChars)
{
    SIZE_T leftLen;
    SIZE_T rightLen;

    if (Left == NULL || Right == NULL || LeftMaxChars == 0 || RightMaxChars == 0)
    {
        return FALSE;
    }

    leftLen = OwlyBoundedWideLength(Left, LeftMaxChars);
    rightLen = OwlyBoundedWideLength(Right, RightMaxChars);
    if (leftLen != rightLen)
    {
        return FALSE;
    }

    for (SIZE_T i = 0; i < leftLen; ++i)
    {
        if (RtlDowncaseUnicodeChar(Left[i]) != RtlDowncaseUnicodeChar(Right[i]))
        {
            return FALSE;
        }
    }

    return TRUE;
}

// Global path normalization helper (shared by kernel components).
// - lowercases
// - '/' -> '\'
// - strips leading "\??\" / "\\?\"
// - collapses both "c:\foo\bar" and "\Device\HarddiskVolumeX\foo\bar"
//   to the same root-relative form: "\foo\bar"
static __forceinline VOID OwlyCollapsePathRootForMatch(_Inout_updates_z_(MAX_FILE_NAME_LENGTH) PWCHAR Buffer,
                                                       _Inout_ SIZE_T *PathChars)
{
    static const WCHAR kDevicePrefix[] = L"\\device\\harddiskvolume";
    const SIZE_T kDevicePrefixLen = RTL_NUMBER_OF(kDevicePrefix) - 1;
    SIZE_T charsToCopy;

    if (Buffer == NULL || PathChars == NULL)
    {
        return;
    }

    charsToCopy = *PathChars;
    if (charsToCopy >= 3 &&
        ((Buffer[0] >= L'a' && Buffer[0] <= L'z') || (Buffer[0] >= L'A' && Buffer[0] <= L'Z')) &&
        Buffer[1] == L':' &&
        Buffer[2] == L'\\')
    {
        RtlMoveMemory(Buffer, Buffer + 2, (charsToCopy - 2 + 1) * sizeof(WCHAR));
        *PathChars = charsToCopy - 2;
        return;
    }

    if (charsToCopy > kDevicePrefixLen &&
        RtlCompareMemory(Buffer, kDevicePrefix, kDevicePrefixLen * sizeof(WCHAR)) == (kDevicePrefixLen * sizeof(WCHAR)))
    {
        SIZE_T i = kDevicePrefixLen;
        while (i < charsToCopy && Buffer[i] >= L'0' && Buffer[i] <= L'9')
        {
            ++i;
        }

        if (i < charsToCopy && Buffer[i] == L'\\')
        {
            SIZE_T tailLen = charsToCopy - i;
            RtlMoveMemory(Buffer, Buffer + i, (tailLen + 1) * sizeof(WCHAR));
            *PathChars = tailLen;
        }
    }
}

_Success_(return != FALSE)
static __forceinline BOOLEAN OwlyNormalizePathForMatch(_In_ PCUNICODE_STRING InputPath,
                                                         _Out_writes_(MAX_FILE_NAME_LENGTH) PWCHAR OutputBuffer,
                                                         _Out_ PUNICODE_STRING NormalizedPath)
{
    SIZE_T charsToCopy;

    if (InputPath == NULL ||
        OutputBuffer == NULL ||
        NormalizedPath == NULL ||
        InputPath->Buffer == NULL ||
        InputPath->Length == 0)
    {
        return FALSE;
    }

    charsToCopy = (SIZE_T)InputPath->Length / sizeof(WCHAR);
    if (charsToCopy >= MAX_FILE_NAME_LENGTH)
    {
        charsToCopy = MAX_FILE_NAME_LENGTH - 1;
    }

    for (SIZE_T i = 0; i < charsToCopy; ++i)
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

    OwlyCollapsePathRootForMatch(OutputBuffer, &charsToCopy);

    NormalizedPath->Buffer = OutputBuffer;
    NormalizedPath->Length = (USHORT)(charsToCopy * sizeof(WCHAR));
    NormalizedPath->MaximumLength = (USHORT)((charsToCopy + 1) * sizeof(WCHAR));
    return TRUE;
}

_Success_(return != FALSE)
static __forceinline BOOLEAN OwlyNormalizeRuleLineForMatch(_In_reads_(RuleChars) PCWSTR RuleText,
                                                           _In_ SIZE_T RuleChars,
                                                           _Out_writes_(OutputCch) PWCHAR OutputBuffer,
                                                           _In_ SIZE_T OutputCch,
                                                           _In_ BOOLEAN TrimTrailingBackslashes,
                                                           _Out_opt_ PSIZE_T NormalizedChars)
{
    SIZE_T lineLen = 0;
    SIZE_T start = 0;
    SIZE_T end = RuleChars;
    SIZE_T commentPos = (SIZE_T)-1;

    if (NormalizedChars != NULL)
    {
        *NormalizedChars = 0;
    }

    if (RuleText == NULL || OutputBuffer == NULL || OutputCch < MAX_FILE_NAME_LENGTH)
    {
        return FALSE;
    }

    OutputBuffer[0] = L'\0';
    if (RuleChars == 0)
    {
        return TRUE;
    }

    while (start < end && (RuleText[start] == L' ' || RuleText[start] == L'\t'))
    {
        start++;
    }

    for (SIZE_T i = start; i < end; ++i)
    {
        if (RuleText[i] == L'#')
        {
            commentPos = i;
            break;
        }

        if ((i + 1) < end && RuleText[i] == L'/' && RuleText[i + 1] == L'/')
        {
            commentPos = i;
            break;
        }
    }

    if (commentPos != (SIZE_T)-1)
    {
        end = commentPos;
    }

    while (end > start &&
           (RuleText[end - 1] == L' ' ||
            RuleText[end - 1] == L'\t' ||
            RuleText[end - 1] == L'\r' ||
            RuleText[end - 1] == L'"'))
    {
        end--;
    }

    if (end <= start)
    {
        return TRUE;
    }

    for (SIZE_T i = start; i < end && (lineLen + 1) < OutputCch; ++i)
    {
        WCHAR ch = RuleText[i];
        if (ch == L'/')
        {
            ch = L'\\';
        }

        OutputBuffer[lineLen++] = RtlDowncaseUnicodeChar(ch);
    }
    OutputBuffer[lineLen] = L'\0';

    if (lineLen >= 4 &&
        OutputBuffer[0] == L'\\' &&
        OutputBuffer[1] == L'?' &&
        OutputBuffer[2] == L'?' &&
        OutputBuffer[3] == L'\\')
    {
        RtlMoveMemory(OutputBuffer, OutputBuffer + 4, (lineLen - 4 + 1) * sizeof(WCHAR));
        lineLen -= 4;
    }
    else if (lineLen >= 4 &&
             OutputBuffer[0] == L'\\' &&
             OutputBuffer[1] == L'\\' &&
             OutputBuffer[2] == L'?' &&
             OutputBuffer[3] == L'\\')
    {
        RtlMoveMemory(OutputBuffer, OutputBuffer + 4, (lineLen - 4 + 1) * sizeof(WCHAR));
        lineLen -= 4;
    }

    OwlyCollapsePathRootForMatch(OutputBuffer, &lineLen);

    if (TrimTrailingBackslashes)
    {
        while (lineLen > 3 && OutputBuffer[lineLen - 1] == L'\\')
        {
            OutputBuffer[--lineLen] = L'\0';
        }
    }

    if (NormalizedChars != NULL)
    {
        *NormalizedChars = lineLen;
    }

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
    
    BOOLEAN IsAmsiEvent;
    WCHAR AmsiContentSample[256];
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
    MESSAGE_ADD_HOOK,                 // Register a user-mode API hook target
    MESSAGE_HOOK_PROCESS,             // Force hook a specific PID
    MESSAGE_ADD_BLOCK_PATH            // Add path to kernel block list
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
    REG_RENAME_KEY,
    REG_QUERY_VALUE,
    // FIX (Bug #2): These were missing, causing every open/query/enum/delete-key
    // operation to be misreported as REG_QUERY_VALUE in the kernel callback.
    REG_DELETE_KEY,   // 14
    REG_OPEN_KEY,     // 15
    REG_QUERY_KEY,    // 16
    REG_ENUM_KEY,     // 17
    REG_ENUM_VALUE    // 18
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

    // Single normalized opcode reserved for real VMM/HyperDbg-origin events.
    // Do not use this for ProcessProtection/FSfilter kernel API signals.
    IRP_HYPERVISOR_EVENT,

    // Named Pipe Operations (Kernel + Usermode)
    IRP_NAMED_PIPE_CREATE = 28,
    IRP_NAMED_PIPE_WRITE = 29,
};

// Distinct raw kernel/process-protection event ids (kept in 13..19 range).
// These are still emitted directly by kernel producers and must remain real
// integral constants for switch labels and static initialization sites.
// They are not hypervisor events.
#define IRP_KERNEL_REMOTE_THREAD   13U
#define IRP_KERNEL_WRITE_MEMORY    14U
#define IRP_KERNEL_PROTECT_MEMORY  15U
#define IRP_KERNEL_CREATE_THREAD   16U
#define IRP_KERNEL_QUEUE_APC       17U
#define IRP_KERNEL_CREATE_SECTION  18U
#define IRP_KERNEL_MAP_SECTION     19U

// User-mode API hook event (shellcode via UserModeHookEngine -> IOCTL_REPORT_HOOK_EVENT).
// Distinct from IRP_HYPERVISOR_EVENT which is reserved for VMM/HyperDbg-origin events.
#define IRP_USERMODE_HOOK_EVENT 20U

#define IRP_ROOTKIT_SSDT_HOOK       21U
#define IRP_ROOTKIT_HIDDEN_PROCESS  22U
#define IRP_ROOTKIT_HIDDEN_DRIVER   23U
#define IRP_ROOTKIT_KERNEL_HOOK     24U
#define IRP_ROOTKIT_TERMINATE_PROCESS 25U
#define IRP_ROOTKIT_FILE_MOVE       26U
#define IRP_ROOTKIT_GENERIC         27U


// Define IOCTL for Dynamic Hook Configuration
#define IOCTL_ADD_HOOK_TARGET CTL_CODE(FILE_DEVICE_OWLYSHIELD, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _HOOK_CONFIG_DATA {
    WCHAR ModuleName[64];
    CHAR FunctionName[256];
    ULONG EventId;
} HOOK_CONFIG_DATA, *PHOOK_CONFIG_DATA;

// ... (Existing Macros) ...

// Generic VMM/HyperDbg-origin event id is represented by IRP_HYPERVISOR_EVENT.
// ProcessProtection/FSfilter kernel API signals keep using IRP_KERNEL_* above.


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

    ULONG CoreId;
    ULONG ThreadId;
    ULONGLONG Context;

    // DLL Load Detection - Tracks both API-based and direct DLL loading
    // Kernel sets IsDllLoad=TRUE when detecting any DLL load operation
    // (via LoadLibrary API or direct module load without API)
    BOOLEAN IsDllLoad;
    WCHAR LoadedDllPath[MAX_FILE_NAME_LENGTH];
    BOOLEAN IsApiBasedLoad; // TRUE if loaded via API (LoadLibrary), FALSE if direct load
    
    // ACG Detection - Dynamic Code Policy at kernel level
    BOOLEAN IsAcgEnabled;

    // AMSI Detection
    BOOLEAN IsAmsiEvent;
    WCHAR AmsiContentSample[256];
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
