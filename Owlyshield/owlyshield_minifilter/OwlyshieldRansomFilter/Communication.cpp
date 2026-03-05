#include "Communication.h"
#include "FsFilter.h"
#include "UserModeHookEngine.h"
#include <ntstrsafe.h>

// =========================================================================
// HOOK NOTIFICATION DEVICE  (\Device\OwlyshieldHook)
//
// PURPOSE
// -------
// UserModeHookEngine.cpp installs a shellcode trampoline into each hooked
// user-mode process.  When a hooked function fires, the shellcode calls
// NtDeviceIoControlFile(DriverDeviceHandle, NULL, NULL, NULL,
//   &IoStatusBlock, IOCTL_REPORT_HOOK_EVENT, &HOOK_EVENT_DATA,
//   sizeof(HOOK_EVENT_DATA), NULL, 0)
// to deliver the event to the driver.  DriverDeviceHandle is a handle to
// THIS device, inserted into the target process's handle table by
// InitializeShellcodeInfrastructure via ObInsertObject.
//
// Without this device, ZwCreateFile("\Device\OwlyshieldHook") in
// InitializeShellcodeInfrastructure returns STATUS_OBJECT_NAME_NOT_FOUND.
// ObInsertObject is never called.  The shellcode gets a null or invalid
// handle, the IOCTL goes nowhere, and all hook events are silently dropped.
//
// ASYNC CONTRACT
// --------------
// The device is opened WITHOUT FILE_SYNCHRONOUS_IO_NONALERT (see
// UserModeHookEngine.cpp).  NtDeviceIoControlFile is therefore asynchronous
// — it returns STATUS_PENDING immediately.  The IRP arrives here in the
// context of the calling thread (the hooked user-mode thread) via a normal
// kernel I/O path.  This dispatch routine MUST call IoCompleteRequest
// BEFORE returning (synchronous inline completion).  This makes
// NtDeviceIoControlFile return STATUS_SUCCESS with IoStatusBlock written
// while the shellcode's stack frame is still alive.  Pending the IRP would
// cause the I/O manager to write IoStatusBlock after the stack unwinds —
// a use-after-return bug.  For a fire-and-forget notify IOCTL (no output
// data, no deferred work), synchronous completion is correct and sufficient.
//
// METHOD_BUFFERED
// ---------------
// IOCTL_REPORT_HOOK_EVENT uses METHOD_BUFFERED.  The I/O manager copies
// the caller's InputBuffer (HOOK_EVENT_DATA on the shellcode's stack) into
// a kernel-mode system buffer BEFORE calling this dispatch routine.  The
// system buffer is accessed via Irp->AssociatedIrp.SystemBuffer.  No
// ProbeForRead is needed — the data is already in kernel address space.
//
// DISPATCH CHAINING
// -----------------
// This module installs its own IRP_MJ_CREATE, IRP_MJ_CLOSE, and
// IRP_MJ_DEVICE_CONTROL handlers on the DriverObject, saving whatever was
// previously registered (e.g. FltMgr's default handlers from
// FltRegisterFilter).  For IRPs not targeting g_HookNotifyDevice, the
// saved original handlers are called unchanged.
//
// CALL ORDER REQUIREMENT
// ----------------------
// InitHookNotifyDevice MUST be called AFTER FltRegisterFilter (which may
// have installed its own MajorFunction handlers).  If called before,
// FltRegisterFilter could overwrite the wrapper functions, breaking the
// chain.  In practice: call InitHookNotifyDevice at the end of DriverEntry,
// after FltStartFiltering.  Call CleanupHookNotifyDevice at the start of
// DriverUnload, before FltUnregisterFilter.
// =========================================================================

#define OWLY_HOOK_DEVICE_NAME   L"\\Device\\OwlyshieldHook"
#define OWLY_HOOK_SYMLINK_NAME  L"\\DosDevices\\OwlyshieldHook"

static PDEVICE_OBJECT  g_HookNotifyDevice = NULL;

// Saved original dispatch routines (installed by FltMgr or FSFilter.cpp).
// We wrap these so FltMgr's own IRPs continue to work unaffected.
static PDRIVER_DISPATCH g_OrigDispatchCreate    = NULL;
static PDRIVER_DISPATCH g_OrigDispatchClose     = NULL;
static PDRIVER_DISPATCH g_OrigDispatchDevCtrl   = NULL;

// ----------------------------------------------------------------------------
// CompleteIrpInline — complete an IRP synchronously without raising IRQL.
// Call this BEFORE returning from the dispatch routine.
// ----------------------------------------------------------------------------
static NTSTATUS CompleteIrpInline(
    _In_ PIRP    Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Info)
{
    Irp->IoStatus.Status      = Status;
    Irp->IoStatus.Information = Info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

// ----------------------------------------------------------------------------
// HookDeviceCreateClose — IRP_MJ_CREATE / IRP_MJ_CLOSE for our device.
// Allows ZwCreateFile / ObInsertObject handle duplication to succeed.
// ----------------------------------------------------------------------------
static NTSTATUS HookDeviceCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return CompleteIrpInline(Irp, STATUS_SUCCESS, 0);
}

// ----------------------------------------------------------------------------
// HookDeviceControl — IRP_MJ_DEVICE_CONTROL for our device.
//
// Receives HOOK_EVENT_DATA from the shellcode thread, resolves the function
// name by EventId, and enqueues the event for delivery to user-mode via
// MESSAGE_GET_OPS / DrainQueuedHypervisorEvents.
// ----------------------------------------------------------------------------
static NTSTATUS HookDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION  stack    = IoGetCurrentIrpStackLocation(Irp);
    ULONG               code     = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG               inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    // METHOD_BUFFERED: I/O manager already copied caller's buffer here.
    PVOID               sysBuf   = Irp->AssociatedIrp.SystemBuffer;

    if (code != IOCTL_REPORT_HOOK_EVENT)
    {
        // Not our IOCTL — complete with error rather than pend or forward.
        // This device only serves the hook-notification purpose.
        return CompleteIrpInline(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }

    if (sysBuf == NULL || inputLen < sizeof(HOOK_EVENT_DATA))
    {
        return CompleteIrpInline(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    PHOOK_EVENT_DATA hookEvent = (PHOOK_EVENT_DATA)sysBuf;

    // Resolve function name from EventId.
    // The shellcode sets FunctionName[0] = L'\0' deliberately — name
    // resolution happens here on the driver side using the EventId.
    WCHAR funcName[MAX_FILE_NAME_LENGTH];
    funcName[0] = L'\0';
    ResolveHookNameByEventId(hookEvent->EventType, funcName, MAX_FILE_NAME_LENGTH);

    // Enqueue the event.  This call is at PASSIVE_LEVEL in the context of
    // the hooked thread, so ExAllocatePool2 and KeAcquireSpinLock are safe.
    // PsGetCurrentProcessId() (called inside QueueHypervisorEvent) returns
    // the PID of the hooked process because this IRP arrived in that
    // thread's context — matching hookEvent->ProcessId.
    QueueHypervisorEvent(
        hookEvent->EventType,
        (funcName[0] != L'\0') ? funcName : NULL,
        (ULONG_PTR)hookEvent->Arg1,
        (ULONG_PTR)hookEvent->Arg2);

    // Complete synchronously (see ASYNC CONTRACT in the header comment above).
    return CompleteIrpInline(Irp, STATUS_SUCCESS, 0);
}

// ----------------------------------------------------------------------------
// HookDeviceDispatch — unified wrapper registered on DriverObject.
//
// Routes IRPs targeting g_HookNotifyDevice to our handlers; all other IRPs
// (targeting FltMgr's volume/filter devices) are forwarded to the original
// dispatch routines saved during InitHookNotifyDevice.
// ----------------------------------------------------------------------------
static NTSTATUS HookDeviceDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp)
{
    if (DeviceObject == g_HookNotifyDevice)
    {
        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
        switch (stack->MajorFunction)
        {
        case IRP_MJ_CREATE:
        case IRP_MJ_CLOSE:
            return HookDeviceCreateClose(DeviceObject, Irp);
        case IRP_MJ_DEVICE_CONTROL:
            return HookDeviceControl(DeviceObject, Irp);
        default:
            return CompleteIrpInline(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
        }
    }

    // Not our device — forward to the original handler.
    PIO_STACK_LOCATION  stack = IoGetCurrentIrpStackLocation(Irp);
    PDRIVER_DISPATCH    orig  = NULL;
    switch (stack->MajorFunction)
    {
    case IRP_MJ_CREATE:         orig = g_OrigDispatchCreate;  break;
    case IRP_MJ_CLOSE:          orig = g_OrigDispatchClose;   break;
    case IRP_MJ_DEVICE_CONTROL: orig = g_OrigDispatchDevCtrl; break;
    default: break;
    }

    if (orig != NULL)
        return orig(DeviceObject, Irp);

    // No original handler registered — return a safe default.
    return CompleteIrpInline(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

// ----------------------------------------------------------------------------
// InitHookNotifyDevice — create the device and install dispatch wrappers.
//
// Must be called AFTER FltRegisterFilter / FltStartFiltering so that any
// MajorFunction entries set by FltMgr are captured in the g_Orig* pointers
// and correctly forwarded.
// ----------------------------------------------------------------------------
NTSTATUS InitHookNotifyDevice(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING devName, symName;
    NTSTATUS       status;

    RtlInitUnicodeString(&devName, OWLY_HOOK_DEVICE_NAME);
    RtlInitUnicodeString(&symName, OWLY_HOOK_SYMLINK_NAME);

    // Create the device object.
    // DO_BUFFERED_IO is required: IOCTL_REPORT_HOOK_EVENT uses METHOD_BUFFERED
    // and the I/O manager only copies buffers when this flag is set.
    // FILE_DEVICE_SECURE_OPEN restricts access to objects opened by name.
    status = IoCreateDevice(
        DriverObject,
        0,                          // no device extension
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,                      // non-exclusive
        &g_HookNotifyDevice);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("!!! HookDevice: IoCreateDevice failed 0x%X\n", status);
        return status;
    }

    g_HookNotifyDevice->Flags |=  DO_BUFFERED_IO;
    g_HookNotifyDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    // Create the symbolic link so ZwCreateFile("\DosDevices\OwlyshieldHook")
    // and "\??\OwlyshieldHook" both resolve to our device.
    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("!!! HookDevice: IoCreateSymbolicLink failed 0x%X\n", status);
        IoDeleteDevice(g_HookNotifyDevice);
        g_HookNotifyDevice = NULL;
        return status;
    }

    // Install dispatch wrappers, chaining through whatever was previously
    // registered (FltMgr defaults, or FSFilter.cpp's own dispatch).
    g_OrigDispatchCreate  = DriverObject->MajorFunction[IRP_MJ_CREATE];
    g_OrigDispatchClose   = DriverObject->MajorFunction[IRP_MJ_CLOSE];
    g_OrigDispatchDevCtrl = DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = HookDeviceDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = HookDeviceDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HookDeviceDispatch;

    DbgPrint("!!! HookDevice: Ready at %S\n", OWLY_HOOK_DEVICE_NAME);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
// CleanupHookNotifyDevice — remove the device before driver unload.
//
// Must be called BEFORE FltUnregisterFilter so that the saved g_Orig*
// pointers are still valid if FltMgr's unload path sends final IRPs.
// ----------------------------------------------------------------------------
VOID CleanupHookNotifyDevice(VOID)
{
    if (g_HookNotifyDevice == NULL)
        return;

    // Restore the original dispatch routines so FltMgr's cleanup path works.
    // We do this by simply removing our device — once it's gone, no new IRPs
    // can reach HookDeviceDispatch for it, but the DriverObject still has the
    // wrapper installed for the FltMgr devices.  Those will chain to g_Orig*
    // which now means FltMgr's original handlers, which is correct.
    UNICODE_STRING symName;
    RtlInitUnicodeString(&symName, OWLY_HOOK_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symName);
    IoDeleteDevice(g_HookNotifyDevice);
    g_HookNotifyDevice = NULL;

    DbgPrint("!!! HookDevice: Cleaned up\n");
}

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
        HOOK_CONFIG_DATA config;
        ANSI_STRING asFunc;
        UNICODE_STRING usFunc;
        NTSTATUS status;

        RtlZeroMemory(&config, sizeof(config));
        RtlCopyMemory(config.ModuleName,
                      message->path,
                      min(sizeof(config.ModuleName), sizeof(message->path)));
        config.ModuleName[RTL_NUMBER_OF(config.ModuleName) - 1] = L'\0';

        RtlInitUnicodeString(&usFunc, message->quarantine_path);
        asFunc.Buffer = config.FunctionName;
        asFunc.Length = 0;
        asFunc.MaximumLength = (USHORT)sizeof(config.FunctionName);
        status = RtlUnicodeStringToAnsiString(&asFunc, &usFunc, FALSE);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("!!! FS : MESSAGE_ADD_HOOK function conversion failed: 0x%X\n", status);
            return status;
        }
        if (asFunc.Length < asFunc.MaximumLength)
        {
            asFunc.Buffer[asFunc.Length] = '\0';
        }
        else
        {
            config.FunctionName[RTL_NUMBER_OF(config.FunctionName) - 1] = '\0';
        }

        config.EventId = (ULONG)message->gid;
        if (config.EventId == 0)
        {
            config.EventId = 0x6000u;
        }

        status = AddCustomHook(&config);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("!!! FS : MESSAGE_ADD_HOOK AddCustomHook failed: 0x%X\n", status);
            return status;
        }

        return STATUS_SUCCESS;
    }
    else if (message->type == MESSAGE_HOOK_PROCESS)
    {
        if (message->pid == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        return UserModeHookProcess(message->pid);
    }

    return STATUS_INTERNAL_ERROR;
}

CommHandler *commHandle;
