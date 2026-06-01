#include "OwlyOpenEdrBridge.h"

#include "common.h"
#include "fltport.h"
#include "lbvsext.h"
#include "osutils.h"
#include <ntstrsafe.h>

namespace cmd {
namespace owly {

static bool WriteUnicodeStringField(
    _Inout_ NonPagedLbvsSerializer<edrdrv::EventField>& Serializer,
    _In_ edrdrv::EventField Field,
    _In_opt_ PCUNICODE_STRING Value)
{
    if (Value == nullptr || Value->Buffer == nullptr || Value->Length == 0)
        return true;
    return write(Serializer, Field, Value);
}

static bool WriteWideZField(
    _Inout_ NonPagedLbvsSerializer<edrdrv::EventField>& Serializer,
    _In_ edrdrv::EventField Field,
    _In_reads_or_z_(MAX_FILE_NAME_LENGTH) PCWSTR Value)
{
    if (Value == nullptr || Value[0] == L'\0')
        return true;
    SIZE_T len = 0;
    while (len < MAX_FILE_NAME_LENGTH && Value[len] != L'\0') ++len;
    return Serializer.write(Field, Value, len);
}

static bool WriteKernelEventDetails(
    _Inout_ NonPagedLbvsSerializer<edrdrv::EventField>& Serializer,
    _In_ const DRIVER_MESSAGE* Message)
{
    if (Message == nullptr)
        return true;

    const KERNEL_EVENT_INFO& k = Message->KernelEventInfo;

    // OpenEDR's stock schema has no dedicated fields for Owlyshield's complete
    // kernel-event payload. Preserve it losslessly as a compact UTF-8 JSON stream
    // in RegistryRawData. The Rust OpenEDR adapter included in this package reads
    // this field and reconstructs KernelEventInfo for the existing behavior engine.
    CHAR json[1536] = { 0 };
    NTSTATUS status = RtlStringCbPrintfA(
        json,
        sizeof(json),
        "{"
        "\"owly_schema\":1,"
        "\"irp_op\":%u,"
        "\"file_change\":%u,"
        "\"gid\":%llu,"
        "\"attacker_pid\":%lu,"
        "\"attacker_gid\":%llu,"
        "\"event_type\":%lu,"
        "\"timestamp\":%llu,"
        "\"source_pid\":%lu,"
        "\"target_pid\":%lu,"
        "\"memory_address\":%llu,"
        "\"memory_size\":%llu,"
        "\"memory_protection\":%lu,"
        "\"is_executable_memory\":%u,"
        "\"thread_handle\":%llu,"
        "\"thread_start_routine\":%llu,"
        "\"raw_argument1\":%llu,"
        "\"raw_argument2\":%llu,"
        "\"raw_argument3\":%llu,"
        "\"raw_argument4\":%llu,"
        "\"access_mask\":%lu,"
        "\"operation_status\":%ld,"
        "\"core_id\":%lu,"
        "\"thread_id\":%lu,"
        "\"context\":%llu,"
        "\"is_dll_load\":%u,"
        "\"is_api_based_load\":%u,"
        "\"is_acg_enabled\":%u,"
        "\"is_amsi_event\":%u"
        "}",
        (ULONG)Message->IRP_OP,
        (ULONG)Message->FileChange,
        (ULONGLONG)Message->Gid,
        Message->AttackerPID,
        (ULONGLONG)Message->AttackerGid,
        k.EventType,
        (ULONGLONG)k.Timestamp,
        k.SourceProcessId,
        k.TargetProcessId,
        (ULONGLONG)(ULONG_PTR)k.MemoryAddress,
        (ULONGLONG)k.MemorySize,
        k.MemoryProtection,
        k.IsExecutableMemory ? 1 : 0,
        (ULONGLONG)(ULONG_PTR)k.ThreadHandle,
        (ULONGLONG)(ULONG_PTR)k.ThreadStartRoutine,
        (ULONGLONG)k.RawArgument1,
        (ULONGLONG)k.RawArgument2,
        (ULONGLONG)k.RawArgument3,
        (ULONGLONG)k.RawArgument4,
        (ULONG)k.AccessMask,
        (LONG)k.OperationStatus,
        k.CoreId,
        k.ThreadId,
        (ULONGLONG)k.Context,
        k.IsDllLoad ? 1 : 0,
        k.IsApiBasedLoad ? 1 : 0,
        k.IsAcgEnabled ? 1 : 0,
        k.IsAmsiEvent ? 1 : 0);

    if (!NT_SUCCESS(status))
        return false;

    SIZE_T jsonLen = 0;
    while (jsonLen < sizeof(json) && json[jsonLen] != '\0') ++jsonLen;
    return Serializer.write(EvFld::RegistryRawData, json, jsonLen);
}

USHORT MapOwlyMessageToOpenEdrEventId(_In_ UCHAR IrpOp, _In_ UCHAR FileChange)
{
    switch (IrpOp)
    {
    case IRP_CREATE:
        return (USHORT)edrdrv::SysmonEvent::FileCreate;
    case IRP_CLEANUP:
        return (USHORT)edrdrv::SysmonEvent::FileClose;
    case IRP_READ:
        return (USHORT)edrdrv::SysmonEvent::FileDataReadFull;
    case IRP_WRITE:
        return (USHORT)edrdrv::SysmonEvent::FileDataWriteFull;
    case IRP_SETINFO:
        switch (FileChange)
        {
        case FILE_CHANGE_DELETE_FILE:
        case FILE_CHANGE_DELETE_NEW_FILE:
            return (USHORT)edrdrv::SysmonEvent::FileDelete;
        default:
            return (USHORT)edrdrv::SysmonEvent::FileDataChange;
        }
    case IRP_PROCESS_CREATE:
        return (USHORT)edrdrv::SysmonEvent::ProcessCreate;
    case IRP_PROCESS_TERMINATE:
    case IRP_PROCESS_EXIT:
        return (USHORT)edrdrv::SysmonEvent::ProcessDelete;
    case IRP_PROCESS_HANDLE_OPEN:
    case IRP_PROCESS_TERMINATE_ATTEMPT:
        return (USHORT)edrdrv::SysmonEvent::ProcessOpen;
    case IRP_REGISTRY:
        switch (FileChange)
        {
        case REG_CREATE_KEY:
            return (USHORT)edrdrv::SysmonEvent::RegistryKeyCreate;
        case REG_DELETE_KEY:
            return (USHORT)edrdrv::SysmonEvent::RegistryKeyDelete;
        case REG_SET_VALUE:
            return (USHORT)edrdrv::SysmonEvent::RegistryValueSet;
        case REG_DELETE_VALUE:
            return (USHORT)edrdrv::SysmonEvent::RegistryValueDelete;
        case REG_RENAME_KEY:
            return (USHORT)edrdrv::SysmonEvent::RegistryKeyNameChange;
        default:
            return (USHORT)edrdrv::SysmonEvent::RegistryValueSet;
        }
    case IRP_NAMED_PIPE_CREATE:
        return (USHORT)edrdrv::SysmonEvent::NamedPipeCreate;
    case IRP_NAMED_PIPE_WRITE:
        return (USHORT)edrdrv::SysmonEvent::FileDataWriteFull;
    case IRP_HYPERVISOR_EVENT:
        return (USHORT)edrdrv::SysmonEvent::DeviceIoControl;
    case IRP_KERNEL_REMOTE_THREAD:
    case IRP_KERNEL_WRITE_MEMORY:
    case IRP_KERNEL_PROTECT_MEMORY:
    case IRP_KERNEL_CREATE_THREAD:
    case IRP_KERNEL_QUEUE_APC:
    case IRP_KERNEL_CREATE_SECTION:
    case IRP_KERNEL_MAP_SECTION:
    case IRP_USERMODE_HOOK_EVENT:
    case IRP_ROOTKIT_SSDT_HOOK:
    case IRP_ROOTKIT_HIDDEN_PROCESS:
    case IRP_ROOTKIT_HIDDEN_DRIVER:
    case IRP_ROOTKIT_KERNEL_HOOK:
    case IRP_ROOTKIT_TERMINATE_PROCESS:
    case IRP_ROOTKIT_FILE_MOVE:
    case IRP_ROOTKIT_GENERIC:
        return (USHORT)edrdrv::SysmonEvent::SelfDefense;
    default:
        return (USHORT)edrdrv::SysmonEvent::SelfDefense;
    }
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS MirrorDriverMessageToOpenEdr(_In_ const DRIVER_MESSAGE* Message)
{
    if (Message == nullptr)
        return STATUS_INVALID_PARAMETER;

    if (KeGetCurrentIrql() > APC_LEVEL)
        return STATUS_UNSUCCESSFUL;

    // If no OpenEDR client is connected, fltport::sendRawEvent queues the event
    // when async queueing is enabled; if the queue is disabled or full, this is
    // still best-effort and must not block the Owly producer path.
    NonPagedLbvsSerializer<edrdrv::EventField> serializer;

    const USHORT rawEventId = MapOwlyMessageToOpenEdrEventId(Message->IRP_OP, Message->FileChange);

    if (!serializer.write(EvFld::RawEventId, uint16_t(rawEventId))) return STATUS_NO_MEMORY;
    if (!serializer.write(EvFld::TickTime, uint64_t(getTickCount64()))) return STATUS_NO_MEMORY;
    if (!serializer.write(EvFld::ProcessPid, (uint32_t)Message->PID)) return STATUS_NO_MEMORY;

    if (Message->ParentPid != 0)
        if (!serializer.write(EvFld::ProcessParentPid, (uint32_t)Message->ParentPid)) return STATUS_NO_MEMORY;

    if (Message->KernelEventInfo.TargetProcessId != 0)
        if (!serializer.write(EvFld::TargetProcessPid, (uint32_t)Message->KernelEventInfo.TargetProcessId)) return STATUS_NO_MEMORY;

    if (Message->KernelEventInfo.AccessMask != 0)
        if (!serializer.write(EvFld::AccessMask, (uint32_t)Message->KernelEventInfo.AccessMask)) return STATUS_NO_MEMORY;

    if (Message->CommandLine[0] != L'\0')
        if (!serializer.write(EvFld::ProcessCmdLine, Message->CommandLine,
            [&]() -> SIZE_T { SIZE_T n = 0; while (n < MAX_FILE_NAME_LENGTH && Message->CommandLine[n] != L'\0') ++n; return n; }())) return STATUS_NO_MEMORY;

    // For ordinary file events this is file.rawPath. For kernel/user-mode hook
    // and rootkit telemetry, ObjectName carries the API/finding label and is
    // also useful to the Rust behavior engine as a fallback path/name.
    if (Message->filePath.Buffer != nullptr && Message->filePath.Length != 0)
    {
        if (!WriteUnicodeStringField(serializer, EvFld::FilePath, &Message->filePath))
            return STATUS_NO_MEMORY;
    }
    else if (Message->KernelEventInfo.ObjectName[0] != L'\0')
    {
        if (!WriteWideZField(serializer, EvFld::FilePath, Message->KernelEventInfo.ObjectName))
            return STATUS_NO_MEMORY;
    }

    // Preserve API/function/finding name in an additional string field too.
    if (!WriteWideZField(serializer, EvFld::FileRawHash, Message->KernelEventInfo.ObjectName))
        return STATUS_NO_MEMORY;

    if (!WriteWideZField(serializer, EvFld::RegistryPath, Message->KernelEventInfo.LoadedDllPath))
        return STATUS_NO_MEMORY;

    if (!WriteKernelEventDetails(serializer, Message))
        return STATUS_NO_MEMORY;

    return fltport::sendRawEvent(serializer);
}

} // namespace owly
} // namespace cmd
