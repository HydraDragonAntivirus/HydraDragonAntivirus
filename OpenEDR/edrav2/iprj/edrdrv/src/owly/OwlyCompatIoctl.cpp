#include "OwlyCompatIoctl.h"

#include "DriverData.h"
#include "KernelCommon.h"
#include "UserModeHookEngine.h"
#include <ntstrsafe.h>

// Implemented in Communication.cpp.
NTSTATUS KillProcessesInGid(ULONGLONG GID, PLONG OutputStatus, ULONG removalMode);

namespace cmd {
namespace owly {

static NTSTATUS WriteBoolResult(_Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
                                _In_ ULONG OutputBufferLength,
                                _Out_ PULONG ReturnOutputBufferLength,
                                _In_ BOOLEAN Value)
{
    if (ReturnOutputBufferLength == nullptr)
        return STATUS_INVALID_PARAMETER;
    *ReturnOutputBufferLength = 0;
    if (OutputBuffer == nullptr || OutputBufferLength < sizeof(BOOLEAN))
        return STATUS_BUFFER_TOO_SMALL;
    *((PBOOLEAN)OutputBuffer) = Value;
    *ReturnOutputBufferLength = sizeof(BOOLEAN);
    return STATUS_SUCCESS;
}

static NTSTATUS CopyWideToAnsi(_Out_writes_z_(DestinationCch) PCHAR Destination,
                               _In_ SIZE_T DestinationCch,
                               _In_reads_or_z_(MAX_FILE_NAME_LENGTH) PCWSTR Source)
{
    if (Destination == nullptr || DestinationCch == 0 || Source == nullptr)
        return STATUS_INVALID_PARAMETER;

    Destination[0] = '\0';

    UNICODE_STRING sourceString;
    ANSI_STRING destinationString;
    SIZE_T sourceLen = wcsnlen(Source, MAX_FILE_NAME_LENGTH);

    sourceString.Buffer = (PWCH)Source;
    sourceString.Length = (USHORT)(sourceLen * sizeof(WCHAR));
    sourceString.MaximumLength = (USHORT)((sourceLen + 1) * sizeof(WCHAR));

    destinationString.Buffer = Destination;
    destinationString.Length = 0;
    destinationString.MaximumLength = (USHORT)DestinationCch;

    NTSTATUS status = RtlUnicodeStringToAnsiString(&destinationString, &sourceString, FALSE);
    if (!NT_SUCCESS(status))
        return status;

    if (destinationString.Length >= DestinationCch)
    {
        Destination[DestinationCch - 1] = '\0';
        return STATUS_BUFFER_TOO_SMALL;
    }

    Destination[destinationString.Length] = '\0';
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS ProcessCompatMessage(
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength)
{
    if (ReturnOutputBufferLength == nullptr)
        return STATUS_INVALID_PARAMETER;
    *ReturnOutputBufferLength = 0;

    if (InputBuffer == nullptr || InputBufferLength < sizeof(COM_MESSAGE))
        return STATUS_INVALID_PARAMETER;
    if (driverData == nullptr)
        return STATUS_DEVICE_NOT_READY;

    COM_MESSAGE* message = static_cast<COM_MESSAGE*>(InputBuffer);
    message->path[MAX_FILE_NAME_LENGTH - 1] = L'\0';
    message->quarantine_path[MAX_FILE_NAME_LENGTH - 1] = L'\0';

    switch (message->type)
    {
    case MESSAGE_SET_PID:
        if (message->pid == 0)
            return STATUS_INVALID_PARAMETER;
        driverData->setPID(message->pid);
        if (message->path[0] != L'\0')
            driverData->setSystemRootPath(message->path);
        return STATUS_SUCCESS;

    case MESSAGE_ADD_SCAN_DIRECTORY:
    {
        PDIRECTORY_ENTRY entry = new DIRECTORY_ENTRY();
        if (entry == nullptr)
            return STATUS_INSUFFICIENT_RESOURCES;
        NTSTATUS status = CopyWString(entry->path, message->path, MAX_FILE_NAME_LENGTH);
        if (!NT_SUCCESS(status))
        {
            delete entry;
            return status;
        }
        BOOLEAN ok = driverData->AddDirectoryEntry(entry);
        if (!ok)
            delete entry;
        return WriteBoolResult(OutputBuffer, OutputBufferLength, ReturnOutputBufferLength, ok);
    }

    case MESSAGE_ADD_BLOCK_PATH:
    {
        PDIRECTORY_ENTRY entry = new DIRECTORY_ENTRY();
        if (entry == nullptr)
            return STATUS_INSUFFICIENT_RESOURCES;
        NTSTATUS status = CopyWString(entry->path, message->path, MAX_FILE_NAME_LENGTH);
        if (!NT_SUCCESS(status))
        {
            delete entry;
            return status;
        }
        BOOLEAN ok = driverData->AddBlockedPath(entry);
        if (!ok)
            delete entry;
        return WriteBoolResult(OutputBuffer, OutputBufferLength, ReturnOutputBufferLength, ok);
    }

    case MESSAGE_REM_SCAN_DIRECTORY:
    {
        PDIRECTORY_ENTRY removed = driverData->RemDirectoryEntry(message->path);
        BOOLEAN ok = removed != nullptr;
        if (removed != nullptr)
            delete removed;
        return WriteBoolResult(OutputBuffer, OutputBufferLength, ReturnOutputBufferLength, ok);
    }

    case MESSAGE_KILL_GID:
    case MESSAGE_KILL_ONLY_GID:
    case MESSAGE_KILL_AND_QUARANTINE_GID:
    case MESSAGE_KILL_AND_REMOVE_GID:
    {
        if (OutputBuffer == nullptr || OutputBufferLength < sizeof(LONG))
            return STATUS_BUFFER_TOO_SMALL;
        ULONG mode = 0;
        if (message->type == MESSAGE_KILL_AND_QUARANTINE_GID)
            mode = 1;
        else if (message->type == MESSAGE_KILL_AND_REMOVE_GID)
            mode = 2;

        *ReturnOutputBufferLength = sizeof(LONG);
        return KillProcessesInGid(message->gid, (PLONG)OutputBuffer, mode);
    }

    case MESSAGE_REVERT_REGISTRY_CHANGES:
        if (message->gid == 0)
            return STATUS_INVALID_PARAMETER;
        driverData->RevertRegistryChangesForGid(message->gid);
        return STATUS_SUCCESS;

    case MESSAGE_ADD_HOOK:
    {
        HOOK_CONFIG_DATA hookConfig = {};
        NTSTATUS status = RtlStringCchCopyW(hookConfig.ModuleName,
                                            RTL_NUMBER_OF(hookConfig.ModuleName),
                                            message->path);
        if (!NT_SUCCESS(status))
            return status;

        status = CopyWideToAnsi(hookConfig.FunctionName,
                                RTL_NUMBER_OF(hookConfig.FunctionName),
                                message->quarantine_path);
        if (!NT_SUCCESS(status))
            return status;

        hookConfig.EventId = (ULONG)message->gid;
        return AddCustomHook(&hookConfig);
    }

    case MESSAGE_HOOK_PROCESS:
        if (message->pid == 0)
            return STATUS_INVALID_PARAMETER;
        return UserModeHookProcess(message->pid);

    case MESSAGE_GET_OPS:
        // Removed in integrated mode. Events are delivered through OpenEDR fltport.
        return STATUS_NOT_SUPPORTED;

    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

} // namespace owly
} // namespace cmd
