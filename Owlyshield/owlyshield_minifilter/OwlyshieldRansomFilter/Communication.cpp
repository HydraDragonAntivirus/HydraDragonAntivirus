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
// INDEPENDENT DRIVER OBJECT
// -------------------------
// This module uses IoCreateDriver to allocate a completely independent
// DRIVER_OBJECT for the hook notification device.  The minifilter's own
// DriverObject (owned and validated by FltMgr) is NEVER read or written.
// This is the only safe design: writing any MajorFunction entry on FltMgr's
// DriverObject causes FLTMGR_FILE_SYSTEM (0xF5) because FltMgr internally
// verifies that its own dispatch routines remain installed.
//
// CALL ORDER REQUIREMENT
// ----------------------
// InitHookNotifyDevice has NO ordering dependency on FltRegisterFilter or
// FltStartFiltering.  It creates its own driver object via IoCreateDriver
// and never touches the minifilter's DriverObject.
// CleanupHookNotifyDevice likewise has no ordering dependency relative to
// FltUnregisterFilter.  Call it anywhere in DriverUnload before returning.
// =========================================================================

#define OWLY_HOOK_DEVICE_NAME   L"\\Device\\OwlyshieldHook"
#define OWLY_HOOK_DRIVER_NAME   L"\\Driver\\OwlyshieldHookNotify"
#define OWLY_HOOK_SYMLINK_NAME  L"\\DosDevices\\OwlyshieldHook"

static PDEVICE_OBJECT  g_HookNotifyDevice       = NULL;
static PDRIVER_OBJECT  g_HookNotifyDriverObject = NULL;

// ----------------------------------------------------------------------------
// CompleteIrpInline — complete an IRP synchronously, before returning.
// METHOD_BUFFERED guarantees HOOK_EVENT_DATA is already in sysBuf by the
// time dispatch is called, so no deferred work is needed.
// ----------------------------------------------------------------------------
static NTSTATUS CompleteIrpInline(
    _In_ PIRP     Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Info)
{
    Irp->IoStatus.Status      = Status;
    Irp->IoStatus.Information = Info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

// ----------------------------------------------------------------------------
// HookDeviceCreateClose — IRP_MJ_CREATE / IRP_MJ_CLOSE
// Accept all open/close requests; ZwCreateFile and ObInsertObject both
// generate IRP_MJ_CREATE, which must succeed for the handle to be valid.
// ----------------------------------------------------------------------------
static NTSTATUS HookDeviceCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return CompleteIrpInline(Irp, STATUS_SUCCESS, 0);
}

// ----------------------------------------------------------------------------
// HookDeviceControl — IRP_MJ_DEVICE_CONTROL
//
// Receives HOOK_EVENT_DATA (or the legacy HOOK_EVENT_DATA_WIRE80 subset) from
// the shellcode running inside the hooked user-mode process.
//
// Runs in the hooked thread's context at PASSIVE_LEVEL.
// METHOD_BUFFERED: the I/O manager copies the caller's InputBuffer into
// Irp->AssociatedIrp.SystemBuffer before calling here — no ProbeForRead needed.
//
// Async contract: IoCompleteRequest is called before returning (inline
// completion), so NtDeviceIoControlFile in the shellcode returns STATUS_SUCCESS
// with IoStatusBlock written while the shellcode's stack frame is still live.
//
// Name resolution priority:
//   1. Fully-qualified "module!function" label in the incoming payload.
//   2. ResolveHookNameByEventId (driver-side lookup by EventId).
//   3. Bare (unqualified) name from the payload.
//   4. Empty string — event is still delivered.
// ----------------------------------------------------------------------------
static NTSTATUS HookDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack    = IoGetCurrentIrpStackLocation(Irp);
    ULONG              code     = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG              inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID              sysBuf   = Irp->AssociatedIrp.SystemBuffer;

    if (code != IOCTL_REPORT_HOOK_EVENT)
        return CompleteIrpInline(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);

    // Minimum: legacy wire format (EventType + ProcessId + FunctionName[64] + Arg1)
    typedef struct _HOOK_EVENT_DATA_WIRE80 {
        ULONG      EventType;
        ULONG      ProcessId;
        CHAR       FunctionName[64];
        ULONG_PTR  Arg1;
    } HOOK_EVENT_DATA_WIRE80, *PHOOK_EVENT_DATA_WIRE80;

    if (sysBuf == NULL || inputLen < sizeof(HOOK_EVENT_DATA_WIRE80))
        return CompleteIrpInline(Irp, STATUS_BUFFER_TOO_SMALL, 0);

    ULONG      eventType = 0;
    ULONG      processId = 0;
    ULONG_PTR  rawArg1   = 0;
    ULONG_PTR  rawArg2   = 0;
    WCHAR      convertedName[64] = {0};
    PCWSTR     incomingWideName  = NULL;

    if (inputLen >= sizeof(HOOK_EVENT_DATA))
    {
        // Full current payload
        PHOOK_EVENT_DATA ev = (PHOOK_EVENT_DATA)sysBuf;
        eventType = ev->EventType;
        processId = ev->ProcessId;
        rawArg1   = ev->Arg1;
        rawArg2   = ev->Arg2;

        if (ev->FunctionName[0] != '\0')
        {
            ANSI_STRING    asFunc;
            UNICODE_STRING usFunc;
            RtlInitAnsiString(&asFunc, ev->FunctionName);
            usFunc.Buffer         = convertedName;
            usFunc.Length         = 0;
            usFunc.MaximumLength  = sizeof(convertedName);
            if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&usFunc, &asFunc, FALSE)))
            {
                convertedName[RTL_NUMBER_OF(convertedName) - 1] = L'\0';
                incomingWideName = convertedName;
            }
        }
    }
    else
    {
        // Legacy wire80 payload
        PHOOK_EVENT_DATA_WIRE80 ev80 = (PHOOK_EVENT_DATA_WIRE80)sysBuf;
        eventType = ev80->EventType;
        processId = ev80->ProcessId;
        rawArg1   = ev80->Arg1;
        rawArg2   = 0;

        if (ev80->FunctionName[0] != '\0')
        {
            ANSI_STRING    asFunc;
            UNICODE_STRING usFunc;
            RtlInitAnsiString(&asFunc, ev80->FunctionName);
            usFunc.Buffer         = convertedName;
            usFunc.Length         = 0;
            usFunc.MaximumLength  = sizeof(convertedName);
            if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&usFunc, &asFunc, FALSE)))
            {
                convertedName[RTL_NUMBER_OF(convertedName) - 1] = L'\0';
                incomingWideName = convertedName;
            }
        }
    }

    // Resolve the best function name available
    WCHAR   resolvedName[MAX_FILE_NAME_LENGTH] = {0};
    PCWSTR  functionName = L"";

    BOOLEAN incomingHasName  = (incomingWideName != NULL && incomingWideName[0] != L'\0');
    BOOLEAN incomingQualified = incomingHasName && (wcschr(incomingWideName, L'!') != NULL);

    if (incomingQualified)
    {
        // Trust fully-qualified "module!function" labels directly
        functionName = incomingWideName;
    }
    else if (ResolveHookNameByEventId(eventType, resolvedName, RTL_NUMBER_OF(resolvedName)) &&
             resolvedName[0] != L'\0')
    {
        functionName = resolvedName;
    }
    else if (incomingHasName)
    {
        functionName = incomingWideName;
    }

    DbgPrint("FSFilter: Hook event PID=%lu Type=%lu Name=%ws Arg1=0x%p Arg2=0x%p\n",
             processId, eventType, functionName, (PVOID)rawArg1, (PVOID)rawArg2);

    // Deliver to the classification pipeline (ProcessProtection.cpp).
    // Also enqueue for user-mode delivery via MESSAGE_GET_OPS.
    OnKernelApiEvent(eventType, processId, processId, functionName, rawArg1, rawArg2);

    return CompleteIrpInline(Irp, STATUS_SUCCESS, 0);
}

// ----------------------------------------------------------------------------
// HookNotifyDriverUnload — fires when the I/O manager drops the last
// reference to g_HookNotifyDriverObject after IoDeleteDevice.
// ----------------------------------------------------------------------------
static VOID HookNotifyDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("!!! HookDevice: DriverUnload\n");
}

// ----------------------------------------------------------------------------
// HookNotifyDriverInit — IoCreateDriver callback.
//
// Receives a fresh DRIVER_OBJECT completely independent of the minifilter's
// DriverObject.  FltMgr never sees this object, so writing MajorFunction
// entries here cannot cause FLTMGR_FILE_SYSTEM (0xF5).
// ----------------------------------------------------------------------------
static NTSTATUS HookNotifyDriverInit(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    g_HookNotifyDriverObject = DriverObject;
    DriverObject->DriverUnload = HookNotifyDriverUnload;

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = HookDeviceCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = HookDeviceCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HookDeviceControl;

    UNICODE_STRING devName, symName;
    RtlInitUnicodeString(&devName, OWLY_HOOK_DEVICE_NAME);
    RtlInitUnicodeString(&symName, OWLY_HOOK_SYMLINK_NAME);

    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_HookNotifyDevice);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("!!! HookDevice: IoCreateDevice failed 0x%X\n", status);
        return status;
    }

    g_HookNotifyDevice->Flags |=  DO_BUFFERED_IO;
    g_HookNotifyDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("!!! HookDevice: IoCreateSymbolicLink failed 0x%X\n", status);
        IoDeleteDevice(g_HookNotifyDevice);
        g_HookNotifyDevice = NULL;
        return status;
    }

    DbgPrint("!!! HookDevice: Ready at %S\n", OWLY_HOOK_DEVICE_NAME);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
// InitHookNotifyDevice — public entry point, called from DriverEntry.
//
// IoCreateDriver allocates a fully independent DRIVER_OBJECT and calls
// HookNotifyDriverInit synchronously.  The minifilter's DriverObject
// (owned by FltMgr) is NEVER touched — no MajorFunction entries are
// replaced, so FLTMGR_FILE_SYSTEM (0xF5) cannot occur.
//
// No ordering dependency on FltRegisterFilter or FltStartFiltering.
// ----------------------------------------------------------------------------
NTSTATUS InitHookNotifyDevice(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    UNICODE_STRING driverName;
    RtlInitUnicodeString(&driverName, OWLY_HOOK_DRIVER_NAME);

    NTSTATUS status = IoCreateDriver(&driverName, HookNotifyDriverInit);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("!!! HookDevice: IoCreateDriver failed 0x%X\n", status);
        g_HookNotifyDevice       = NULL;
        g_HookNotifyDriverObject = NULL;
    }
    return status;
}

// ----------------------------------------------------------------------------
// CleanupHookNotifyDevice — called from DriverUnload.
// No ordering constraint relative to FltUnregisterFilter.
// ----------------------------------------------------------------------------
VOID CleanupHookNotifyDevice(VOID)
{
    if (g_HookNotifyDevice == NULL)
        return;

    UNICODE_STRING symName;
    RtlInitUnicodeString(&symName, OWLY_HOOK_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symName);

    IoDeleteDevice(g_HookNotifyDevice);
    g_HookNotifyDevice       = NULL;
    g_HookNotifyDriverObject = NULL;

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
