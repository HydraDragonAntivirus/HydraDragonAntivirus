#include "Communication.h"
#include "FsFilter.h"

NTSTATUS InitCommData(

)
{
    HRESULT status;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;
    PSECURITY_DESCRIPTOR sd;
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
NTSTATUS KillProcessesInGid(ULONGLONG GID, PLONG OutputStatus, BOOLEAN enableQuarantine)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE processHandle;
    BOOLEAN isGidExist = FALSE;
    ULONGLONG gidSize = driverData->GetGidSize(GID, &isGidExist);

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
        if (enableQuarantine)
        {
            DbgPrint("!!! FS : Kill and Quarantine action for GID: %llu\n", GID);
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

            DbgPrint("!!! FS : Attempt to terminate pid: %lu from gid: %llu (quarantine: %s)\n", Buffer[i], GID,
                     enableQuarantine ? "YES" : "NO");

            InitializeObjectAttributes(&objAttribs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

            status = ZwOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objAttribs, &clientId);

            if (!NT_SUCCESS(status))
            {
                *OutputStatus = STATUS_FAIL_CHECK;
                DbgPrint("!!! FS : Failed to open process %lu, reason: %d\n", Buffer[i], status);
                continue;
            }

            // Get the executable path BEFORE killing (important!)
            if (enableQuarantine)
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

            // Now quarantine the file if requested (move to isolated folder)
            if (enableQuarantine && exePath != NULL)
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
        return KillProcessesInGid(message->gid, (PLONG)OutputBuffer, FALSE);
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
        return KillProcessesInGid(message->gid, (PLONG)OutputBuffer, TRUE);
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
        return KillProcessesInGid(message->gid, (PLONG)OutputBuffer, FALSE);
    }

    return STATUS_INTERNAL_ERROR;
}

CommHandler *commHandle;
