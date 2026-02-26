#include "Communication.h"
#include "FsFilter.h"
#include <ntstrsafe.h>

#define OWLY_HV_EVENT_QUEUE_TAG 'vHwO'

typedef struct _OWLY_HV_EVENT_ENTRY
{
    LIST_ENTRY     Entry;
    DRIVER_MESSAGE Message;
} OWLY_HV_EVENT_ENTRY, *POWLY_HV_EVENT_ENTRY;

static LIST_ENTRY g_OwlyHvEventQueue;
static KSPIN_LOCK g_OwlyHvEventQueueLock;
static BOOLEAN    g_OwlyHvEventQueueInitialized = FALSE;
static ULONG      g_OwlyHvEventQueueSize        = 0;

static VOID
EnsureQueuedHypervisorEventsInitialized(VOID)
{
    if (!g_OwlyHvEventQueueInitialized)
    {
        InitializeListHead(&g_OwlyHvEventQueue);
        KeInitializeSpinLock(&g_OwlyHvEventQueueLock);
        g_OwlyHvEventQueueSize        = 0;
        g_OwlyHvEventQueueInitialized = TRUE;
    }
}

BOOLEAN
QueueHypervisorEvent(_In_ ULONG RawEventType,
                     _In_opt_z_ PCWSTR EventName,
                     _In_ ULONG_PTR EventArg1,
                     _In_ ULONG_PTR EventArg2)
{
    KIRQL oldIrql;
    ULONG currentPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    POWLY_HV_EVENT_ENTRY newEntry;
    LARGE_INTEGER timestamp;

    EnsureQueuedHypervisorEventsInitialized();

    newEntry = (POWLY_HV_EVENT_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                      sizeof(OWLY_HV_EVENT_ENTRY),
                                                      OWLY_HV_EVENT_QUEUE_TAG);
    if (newEntry == NULL)
    {
        return FALSE;
    }

    RtlZeroMemory(newEntry, sizeof(OWLY_HV_EVENT_ENTRY));

    newEntry->Message.PID         = currentPid;
    newEntry->Message.AttackerPID = currentPid;
    newEntry->Message.IRP_OP      = IRP_HYPERVISOR_EVENT;

    KeQuerySystemTime(&timestamp);
    newEntry->Message.KernelEventInfo.EventType       = RawEventType;
    newEntry->Message.KernelEventInfo.Timestamp       = (ULONGLONG)timestamp.QuadPart;
    newEntry->Message.KernelEventInfo.SourceProcessId = currentPid;
    newEntry->Message.KernelEventInfo.TargetProcessId = currentPid;
    newEntry->Message.KernelEventInfo.RawArgument1    = EventArg1;
    newEntry->Message.KernelEventInfo.RawArgument2    = EventArg2;
    newEntry->Message.KernelEventInfo.MemoryAddress   = (PVOID)EventArg2;
    newEntry->Message.KernelEventInfo.ThreadHandle    = (HANDLE)EventArg1;
    newEntry->Message.KernelEventInfo.AccessMask      = (ACCESS_MASK)EventArg1;
    newEntry->Message.KernelEventInfo.OperationStatus = STATUS_SUCCESS;

    if (EventName != NULL && EventName[0] != L'\0')
    {
        size_t eventNameLength = wcsnlen(EventName, MAX_FILE_NAME_LENGTH - 1);
        if (eventNameLength > 0)
        {
            RtlCopyMemory(newEntry->Message.KernelEventInfo.ObjectName,
                          EventName,
                          eventNameLength * sizeof(WCHAR));
        }
    }

    KeAcquireSpinLock(&g_OwlyHvEventQueueLock, &oldIrql);
    if (g_OwlyHvEventQueueSize >= MAX_OPS_SAVE)
    {
        KeReleaseSpinLock(&g_OwlyHvEventQueueLock, oldIrql);
        ExFreePoolWithTag(newEntry, OWLY_HV_EVENT_QUEUE_TAG);
        return FALSE;
    }

    InsertTailList(&g_OwlyHvEventQueue, &newEntry->Entry);
    g_OwlyHvEventQueueSize++;
    KeReleaseSpinLock(&g_OwlyHvEventQueueLock, oldIrql);
    return TRUE;
}

VOID
ResetQueuedHypervisorEvents(VOID)
{
    KIRQL oldIrql;
    LIST_ENTRY localList;

    if (!g_OwlyHvEventQueueInitialized)
    {
        return;
    }

    InitializeListHead(&localList);

    KeAcquireSpinLock(&g_OwlyHvEventQueueLock, &oldIrql);
    while (!IsListEmpty(&g_OwlyHvEventQueue))
    {
        PLIST_ENTRY entry = RemoveHeadList(&g_OwlyHvEventQueue);
        InsertTailList(&localList, entry);
    }
    g_OwlyHvEventQueueSize = 0;
    KeReleaseSpinLock(&g_OwlyHvEventQueueLock, oldIrql);

    while (!IsListEmpty(&localList))
    {
        PLIST_ENTRY          entry = RemoveHeadList(&localList);
        POWLY_HV_EVENT_ENTRY item  = CONTAINING_RECORD(entry, OWLY_HV_EVENT_ENTRY, Entry);
        ExFreePoolWithTag(item, OWLY_HV_EVENT_QUEUE_TAG);
    }
}

VOID
DrainQueuedHypervisorEvents(_Inout_updates_bytes_(OutputBufferLength) PVOID OutputBuffer,
                            _In_ ULONG OutputBufferLength,
                            _Inout_ PULONG ReturnOutputBufferLength)
{
    PRWD_REPLY_IRPS outHeader;

    if (OutputBuffer == NULL || ReturnOutputBufferLength == NULL || OutputBufferLength < sizeof(RWD_REPLY_IRPS))
    {
        return;
    }

    if (!g_OwlyHvEventQueueInitialized)
    {
        return;
    }

    outHeader = (PRWD_REPLY_IRPS)OutputBuffer;
    if (*ReturnOutputBufferLength < sizeof(RWD_REPLY_IRPS))
    {
        RtlZeroMemory(outHeader, sizeof(RWD_REPLY_IRPS));
        outHeader->dataSize = sizeof(RWD_REPLY_IRPS);
        outHeader->data     = nullptr;
        outHeader->num_ops  = 0;
        *ReturnOutputBufferLength = sizeof(RWD_REPLY_IRPS);
    }

    while (*ReturnOutputBufferLength + sizeof(DRIVER_MESSAGE) <= OutputBufferLength)
    {
        KIRQL                oldIrql;
        POWLY_HV_EVENT_ENTRY item = NULL;
        PDRIVER_MESSAGE      outMsg;
        PCHAR                writePtr;

        KeAcquireSpinLock(&g_OwlyHvEventQueueLock, &oldIrql);
        if (!IsListEmpty(&g_OwlyHvEventQueue))
        {
            PLIST_ENTRY entry = RemoveHeadList(&g_OwlyHvEventQueue);
            item = CONTAINING_RECORD(entry, OWLY_HV_EVENT_ENTRY, Entry);
            g_OwlyHvEventQueueSize--;
        }
        KeReleaseSpinLock(&g_OwlyHvEventQueueLock, oldIrql);

        if (item == NULL)
        {
            break;
        }

        writePtr = (PCHAR)OutputBuffer + *ReturnOutputBufferLength;
        outMsg   = (PDRIVER_MESSAGE)writePtr;

        item->Message.filePath.Buffer        = nullptr;
        item->Message.filePath.Length        = 0;
        item->Message.filePath.MaximumLength = 0;
        item->Message.next                   = nullptr;

        RtlCopyMemory(outMsg, &item->Message, sizeof(DRIVER_MESSAGE));
        ExFreePoolWithTag(item, OWLY_HV_EVENT_QUEUE_TAG);

        *ReturnOutputBufferLength += sizeof(DRIVER_MESSAGE);
        outHeader->addSize(sizeof(DRIVER_MESSAGE));
        outHeader->addOp();
    }

    if (outHeader->numOps())
    {
        outHeader->data = (PDRIVER_MESSAGE)((PCHAR)OutputBuffer + sizeof(RWD_REPLY_IRPS));
    }
}

NTSTATUS InitCommData(

)
{
    HRESULT status;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;
    PSECURITY_DESCRIPTOR sd;
    EnsureQueuedHypervisorEventsInitialized();
    //
    //  Create a communication port.
    //
    RtlInitUnicodeString(&uniString, ComPortName);

    status = FltBuildDefaultSecurityDescriptor(
        &sd,
        FLT_PORT_ALL_ACCESS); //  We secure the port so only ADMINs & SYSTEM can acecss it.
    status = RtlSetDaclSecurityDescriptor(sd, TRUE, NULL,
                                          FALSE); // allow user application without admin to enter

    if (NT_SUCCESS(status))
    {
        InitializeObjectAttributes(&oa, &uniString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);

        status = FltCreateCommunicationPort(commHandle->Filter, &commHandle->ServerPort, &oa, NULL, RWFConnect,
                                            RWFDissconnect, RWFNewMessage, 1);
        //
        //  Free the security descriptor in all cases. It is not needed once
        //  the call to FltCreateCommunicationPort() is made.
        //

        FltFreeSecurityDescriptor(sd);
    }

    return status;
}

BOOLEAN IsCommClosed()
{
    return commHandle->CommClosed;
}

void CommClose()
{
    // FLT_ASSERT(IsCommClosed());

    if (commHandle->ClientPort)
    {
        FltCloseClientPort(commHandle->Filter, &commHandle->ClientPort);
        commHandle->ClientPort = NULL;
    }

    if (commHandle->ServerPort)
    {
        FltCloseCommunicationPort(commHandle->ServerPort);
        commHandle->ServerPort = NULL;
    }
    commHandle->UserProcess = NULL;
    commHandle->CommClosed = TRUE;
    ResetQueuedHypervisorEvents();
}

NTSTATUS
RWFConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie,
           _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext, _In_ ULONG SizeOfContext,
           _Outptr_result_maybenull_ PVOID

               *ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie = NULL);

    FLT_ASSERT(commHandle->ClientPort == NULL);

    //
    //  Set the user process and port. In a production filter it may
    //  be necessary to synchronize access to such fields with port
    //  lifetime. For instance, while filter manager will synchronize
    //  FltCloseClientPort with FltSendMessage's reading of the port
    //  handle, synchronizing access to the UserProcess would be up to
    //  the filter.
    //

    commHandle->ClientPort = ClientPort;
    DbgPrint("!!! user connected, port=0x%p\n", ClientPort);

    return STATUS_SUCCESS;
}

VOID RWFDissconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    DbgPrint("!!! user disconnected, port=0x%p\n", commHandle->ClientPort);

    //
    //  Close our handle to the connection: note, since we limited max connections to 1,
    //  another connect will not be allowed until we return from the disconnect routine.
    //

    FltCloseClientPort(commHandle->Filter, &commHandle->ClientPort);

    //
    //  Reset the user-process field.
    //
    DbgPrint("Disconnent\n");
    commHandle->CommClosed = TRUE;
}

// NEW: Helper function to kill all processes in a GID
// removalMode: 0 = Kill Only, 1 = Kill & Quarantine, 2 = Kill & Remove
NTSTATUS KillProcessesInGid(ULONGLONG GID, PLONG OutputStatus, ULONG removalMode)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE processHandle;
    BOOLEAN isGidExist = FALSE;
    ULONGLONG gidSize = driverData->GetGidSize(GID, &isGidExist);

    driverData->SetGidMalicious(GID);

    if (gidSize == 0 || isGidExist == FALSE)
    {
        DbgPrint("!!! FS : Gid already ended or no such gid %llu\n", GID);
        *OutputStatus = STATUS_NO_SUCH_GROUP;
        return STATUS_SUCCESS;
    }

    // Allocate buffer for PIDs
    PULONG Buffer = (PULONG)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ULONG) * gidSize, 'RW');
    if (Buffer == nullptr)
    {
        DbgPrint("!!! FS : memory allocation error on non paged pool\n");
        *OutputStatus = STATUS_MEMORY_NOT_ALLOCATED;
        return STATUS_SUCCESS;
    }

    ULONGLONG pidsReturned = 0;
    isGidExist = driverData->GetGidPids(GID, Buffer, gidSize, &pidsReturned);

    if (isGidExist)
    {
        // Log the action type
        if (removalMode == 1)
        {
            DbgPrint("!!! FS : Kill and Quarantine action for GID: %llu\n", GID);
        }
        else if (removalMode == 2)
        {
             DbgPrint("!!! FS : Kill and REMOVE action for GID: %llu\n", GID);
        }
        else
        {
            DbgPrint("!!! FS : Kill Only action for GID: %llu\n", GID);
        }

        // Kill each process
        for (ULONGLONG i = 0; i < gidSize; i++)
        {
            CLIENT_ID clientId;
            clientId.UniqueProcess = (HANDLE)Buffer[i];
            clientId.UniqueThread = 0;

            OBJECT_ATTRIBUTES objAttribs;
            NTSTATUS exitStatus = STATUS_FAIL_CHECK;
            PUNICODE_STRING exePath = NULL;

            DbgPrint("!!! FS : Attempt to terminate pid: %lu from gid: %llu (mode: %lu)\n", Buffer[i], GID,
                     removalMode);

            InitializeObjectAttributes(&objAttribs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

            status = ZwOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objAttribs, &clientId);

            if (!NT_SUCCESS(status))
            {
                *OutputStatus = STATUS_FAIL_CHECK;
                DbgPrint("!!! FS : Failed to open process %lu, reason: %d\n", Buffer[i], status);
                continue;
            }

            // Get the executable path BEFORE killing (important!)
            if (removalMode > 0)
            {
                NTSTATUS pathStatus = GetProcessNameByHandle(processHandle, &exePath);
                if (NT_SUCCESS(pathStatus) && exePath != NULL && exePath->Length > 0)
                {
                    DbgPrint("!!! FS : Quarantine target: %wZ\n", exePath);
                }
                else
                {
                    DbgPrint("!!! FS : Warning: Could not get exe path for PID %lu (Status: 0x%X)\n", Buffer[i], pathStatus);
                }
            }

            status = ZwTerminateProcess(processHandle, exitStatus);
            if (!NT_SUCCESS(status))
            {
                *OutputStatus = STATUS_FAIL_CHECK;
                DbgPrint("!!! FS : Failed to kill process %lu, reason: %d\n", Buffer[i], status);
                NtClose(processHandle);
                if (exePath != NULL)
                    ExFreePoolWithTag(exePath, 'RW');
                continue;
            }

            NtClose(processHandle);
            DbgPrint("!!! FS : Termination of pid: %lu from gid: %llu succeeded\n", Buffer[i], GID);

            // Now quarantine or remove the file if requested
            if (removalMode > 0 && exePath != NULL)
            {
                if (removalMode == 1) // Quarantine
                {
                    NTSTATUS quarantineStatus = QuarantineFileByPath(exePath);
                    if (NT_SUCCESS(quarantineStatus))
                    {
                        DbgPrint("!!! FS : Successfully quarantined file: %wZ\n", exePath);
                    }
                    else
                    {
                        DbgPrint("!!! FS : Failed to quarantine file %wZ. Status: 0x%X\n", exePath, quarantineStatus);
                    }
                }
                else if (removalMode == 2) // Remove (Delete)
                {
                    NTSTATUS deleteStatus = DeleteFileByPath(exePath);
                    if (NT_SUCCESS(deleteStatus))
                    {
                        DbgPrint("!!! FS : Successfully DELETED file: %wZ\n", exePath);
                    }
                    else
                    {
                        DbgPrint("!!! FS : Failed to delete file %wZ. Status: 0x%X\n", exePath, deleteStatus);
                    }
                }
                ExFreePoolWithTag(exePath, 'RW');
            }
        }
    }

    ExFreePoolWithTag(Buffer, 'RW');
    return STATUS_SUCCESS;
}

NTSTATUS
RWFNewMessage(IN PVOID PortCookie, IN PVOID InputBuffer, IN ULONG InputBufferLength, OUT PVOID OutputBuffer,
              IN ULONG OutputBufferLength, OUT PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBufferLength);

    *ReturnOutputBufferLength = 0;

    COM_MESSAGE *message = static_cast<COM_MESSAGE *>(InputBuffer);
    if (message == NULL)
        return STATUS_INTERNAL_ERROR; // failed message type

    if (message->type == MESSAGE_ADD_SCAN_DIRECTORY)
    {
        DbgPrint("Recived add directory message\n");
        PDIRECTORY_ENTRY newEntry = new DIRECTORY_ENTRY();
        if (newEntry == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        NTSTATUS hr = CopyWString(newEntry->path, message->path, MAX_FILE_NAME_LENGTH);
        if (!NT_SUCCESS(hr))
        {
            delete newEntry;
            return STATUS_INTERNAL_ERROR;
        }
        *ReturnOutputBufferLength = 1;
        if (driverData->AddDirectoryEntry(newEntry))
        {
            *((PBOOLEAN)OutputBuffer) = TRUE;
            DbgPrint("Added scan directory successfully\n");
            return STATUS_SUCCESS;
        }
        else
        {
            delete newEntry;
            *((PBOOLEAN)OutputBuffer) = FALSE;
            DbgPrint("Failed to addscan directory\n");
            return STATUS_SUCCESS;
        }
    }
    else if (message->type == MESSAGE_REM_SCAN_DIRECTORY)
    {
        PDIRECTORY_ENTRY ptr = driverData->RemDirectoryEntry(message->path);
        *ReturnOutputBufferLength = 1;
        if (ptr == NULL)
        {
            *((PBOOLEAN)OutputBuffer) = FALSE;
            DbgPrint("Failed to remove directory\n");
            return STATUS_SUCCESS;
        }
        else
        {
            delete ptr;
        }
        *((PBOOLEAN)OutputBuffer) = TRUE;
        DbgPrint("Removed scan directory successfully\n");
        return STATUS_SUCCESS;
    }
    else if (message->type == MESSAGE_GET_OPS)
    {
        if (OutputBuffer == NULL || OutputBufferLength != MAX_COMM_BUFFER_SIZE)
        {
            return STATUS_INVALID_PARAMETER;
        }
        driverData->DriverGetIrps(OutputBuffer, OutputBufferLength, ReturnOutputBufferLength);
        DrainQueuedHypervisorEvents(OutputBuffer, OutputBufferLength, ReturnOutputBufferLength);
        return STATUS_SUCCESS;
    }
    else if (message->type == MESSAGE_SET_PID)
    {
        if (message->pid != 0)
        {
            driverData->setPID(message->pid);
            driverData->setSystemRootPath(message->path);
            commHandle->CommClosed = FALSE;
            return STATUS_SUCCESS;
        }
        return STATUS_INVALID_PARAMETER;
    }
    // ORIGINAL: Legacy kill message (kept for backward compatibility)
    else if (message->type == MESSAGE_KILL_GID)
    {
        if (OutputBuffer == NULL || OutputBufferLength != sizeof(LONG))
        {
            return STATUS_INVALID_PARAMETER;
        }
        *ReturnOutputBufferLength = sizeof(LONG);
        DbgPrint("!!! FS : Legacy MESSAGE_KILL_GID received for GID: %llu\n", message->gid);
        return KillProcessesInGid(message->gid, (PLONG)OutputBuffer, 0); // Default to Kill Only
    }
    // NEW: Kill and Quarantine message
    else if (message->type == MESSAGE_KILL_AND_QUARANTINE_GID)
    {
        if (OutputBuffer == NULL || OutputBufferLength != sizeof(LONG))
        {
            return STATUS_INVALID_PARAMETER;
        }
        *ReturnOutputBufferLength = sizeof(LONG);
        DbgPrint("!!! FS : MESSAGE_KILL_AND_QUARANTINE_GID received for GID: %llu\n", message->gid);
        return KillProcessesInGid(message->gid, (PLONG)OutputBuffer, 1); // Mode 1: Quarantine
    }
    // NEW: Kill Only message
    else if (message->type == MESSAGE_KILL_ONLY_GID)
    {
        if (OutputBuffer == NULL || OutputBufferLength != sizeof(LONG))
        {
            return STATUS_INVALID_PARAMETER;
        }
        *ReturnOutputBufferLength = sizeof(LONG);
        DbgPrint("!!! FS : MESSAGE_KILL_ONLY_GID received for GID: %llu\n", message->gid);
        return KillProcessesInGid(message->gid, (PLONG)OutputBuffer, 0); // Mode 0: Kill Only
    }
    // NEW: Kill and Remove (Delete) message
    else if (message->type == MESSAGE_KILL_AND_REMOVE_GID)
    {
        if (OutputBuffer == NULL || OutputBufferLength != sizeof(LONG))
        {
            return STATUS_INVALID_PARAMETER;
        }
        *ReturnOutputBufferLength = sizeof(LONG);
        DbgPrint("!!! FS : MESSAGE_KILL_AND_REMOVE_GID received for GID: %llu\n", message->gid);
        return KillProcessesInGid(message->gid, (PLONG)OutputBuffer, 2); // Mode 2: Remove
    }
    else if (message->type == MESSAGE_REVERT_REGISTRY_CHANGES)
    {
        DbgPrint("!!! FS : MESSAGE_REVERT_REGISTRY_CHANGES received for GID: %llu\n", message->gid);
        if (message->gid != 0)
        {
            driverData->RevertRegistryChangesForGid(message->gid);
            return STATUS_SUCCESS;
        }
        return STATUS_INVALID_PARAMETER;
    }
    // NEW: Add Generic Hook Config
    else if (message->type == MESSAGE_ADD_HOOK)
    {
        DbgPrint("!!! FS : MESSAGE_ADD_HOOK received but user-mode hook engine is removed; unsupported\n");
        return STATUS_NOT_SUPPORTED;
    }

    return STATUS_INTERNAL_ERROR;
}

CommHandler *commHandle;
