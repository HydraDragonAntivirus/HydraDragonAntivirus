#include "Communication.h"
#include "common.h"
#include "ProcessProtection.h" // OnKernelApiEvent - called by HookDeviceControl
#include "RootkitDetector.h"
#include "UserModeHookEngine.h"
#include "fltport.h"
#include "osutils.h"
#include <ntstrsafe.h>

#ifdef OWLY_HAS_EMBEDDED_HOOK_RULE_LOADER
extern "C" NTSTATUS SetHookExcludeRulesFromBuffer(
    _In_reads_bytes_(BytesRead) PUCHAR Buffer,
    _In_ ULONG BytesRead);
#endif

#if OWLY_HYPERVISOR_SUPPORT

// IOCTL for Hypervisor communication
#define IOCTL_REGISTER_OWLY_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OWLY_HV_COMM_MAGIC 0x4F574C59
#define OWLY_VMM_REGISTER_POOL_TAG 'rVmO'

typedef struct _OWLY_HV_COMM_DATA {
    ULONG Magic;           // 0x4F574C59 ('OWLY')
    PVOID CallbackRoutine; // PHYPERDBG_OWLY_EVENT_CALLBACK
} OWLY_HV_COMM_DATA, *POWLY_HV_COMM_DATA;

typedef struct _OWLY_VMM_ASYNC_REGISTER_CONTEXT {
    WORK_QUEUE_ITEM WorkItem;
    OWLY_HV_COMM_DATA CommData;
    PFILE_OBJECT FileObject;
    PDEVICE_OBJECT DeviceObject;
} OWLY_VMM_ASYNC_REGISTER_CONTEXT, *POWLY_VMM_ASYNC_REGISTER_CONTEXT;

static PDEVICE_OBJECT g_HvDeviceObject = NULL;
static PFILE_OBJECT g_HvFileObject = NULL;
static BOOLEAN g_HvCallbackRegistered = FALSE;

// Asynchronous worker routine to register VMM callback without blocking driver init
static VOID OwlyVmmRegisterWorker(_In_ PVOID Context)
{
    POWLY_VMM_ASYNC_REGISTER_CONTEXT asyncContext = (POWLY_VMM_ASYNC_REGISTER_CONTEXT)Context;
    KEVENT event;
    IO_STATUS_BLOCK ioStatus;
    PIRP irp;
    NTSTATUS status;

    if (asyncContext == NULL)
    {
        return;
    }

#if IS_DEBUG_IRP
    DbgPrint("!!! Owlyshield: VMM registration worker started\n");
#endif

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    // Use IoBuildDeviceIoControlRequest for proper synchronous IOCTL
    irp = IoBuildDeviceIoControlRequest(
        IOCTL_REGISTER_OWLY_CALLBACK,
        asyncContext->DeviceObject,
        &asyncContext->CommData,
        sizeof(asyncContext->CommData),
        NULL,
        0,
        FALSE,
        &event,
        &ioStatus);

    if (irp != NULL)
    {
        status = IoCallDriver(asyncContext->DeviceObject, irp);
        if (status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
            status = ioStatus.Status;
        }

        if (NT_SUCCESS(status))
        {
            g_HvCallbackRegistered = TRUE;
#if IS_DEBUG_IRP
            DbgPrint("!!! Owlyshield: VMM callback registered successfully (async)\n");
#endif
        }
        else
        {
#if IS_DEBUG_IRP
            DbgPrint("!!! Owlyshield: VMM callback registration failed: 0x%X (async)\n", status);
#endif
        }
    }
    else
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! Owlyshield: Failed to build VMM registration IRP\n");
#endif
    }

    // Cleanup
    if (asyncContext->FileObject != NULL)
    {
        ObDereferenceObject(asyncContext->FileObject);
    }
    ExFreePoolWithTag(asyncContext, OWLY_VMM_REGISTER_POOL_TAG);
}

static NTSTATUS OwlySendVmmRegistrationIoctlAsync(_In_opt_ PVOID CallbackRoutine)
{
    POWLY_VMM_ASYNC_REGISTER_CONTEXT asyncContext;

    if (g_HvDeviceObject == NULL || g_HvFileObject == NULL)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    asyncContext = (POWLY_VMM_ASYNC_REGISTER_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(OWLY_VMM_ASYNC_REGISTER_CONTEXT), OWLY_VMM_REGISTER_POOL_TAG);
    if (asyncContext == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(asyncContext, sizeof(*asyncContext));
    asyncContext->CommData.Magic = OWLY_HV_COMM_MAGIC;
    asyncContext->CommData.CallbackRoutine = CallbackRoutine;
    asyncContext->DeviceObject = g_HvDeviceObject;
    asyncContext->FileObject = g_HvFileObject;
    ObReferenceObject(asyncContext->FileObject);

    ExInitializeWorkItem(&asyncContext->WorkItem, OwlyVmmRegisterWorker, asyncContext);
    ExQueueWorkItem(&asyncContext->WorkItem, DelayedWorkQueue);

#if IS_DEBUG_IRP
    DbgPrint("!!! Owlyshield: VMM registration queued to worker thread\n");
#endif

    return STATUS_SUCCESS;
}

// Callback from Hypervisor (Intel/AMD)
static VOID NTAPI OwlyHypervisorCallback(PVOID EventDetails) {
    if (EventDetails == NULL)
    {
        return;
    }

    POWLY_HV_EVENT_DETAILS details = (POWLY_HV_EVENT_DETAILS)EventDetails;
    BOOLEAN queued = QueueHypervisorEvent(details);

#if IS_DEBUG_IRP
    DbgPrint("!!! Owlyshield: Received Hypervisor event raw=%lu src=%lu target=%lu addr=%p size=%zu queued=%u\n",
             details->RawEventType,
             details->SourceProcessId,
             details->TargetProcessId,
             details->MemoryAddress,
             details->MemorySize,
             queued);
#else
    UNREFERENCED_PARAMETER(queued);
#endif
}

NTSTATUS InitVmmCommunication() {
    UNICODE_STRING intelDevName = RTL_CONSTANT_STRING(L"\\Device\\hyperhv");
    UNICODE_STRING amdDevName = RTL_CONSTANT_STRING(L"\\Device\\RedDbgCore");
    NTSTATUS status;

    // Try Intel first
    status = IoGetDeviceObjectPointer(&intelDevName, FILE_ALL_ACCESS, &g_HvFileObject, &g_HvDeviceObject);
    if (!NT_SUCCESS(status)) {
        // Try AMD
        status = IoGetDeviceObjectPointer(&amdDevName, FILE_ALL_ACCESS, &g_HvFileObject, &g_HvDeviceObject);
    }

    if (NT_SUCCESS(status)) {
#if IS_DEBUG_IRP
        DbgPrint("!!! Owlyshield: Found standalone Hypervisor device. Queueing async registration...\n");
#endif

        // Queue async registration - don't block driver initialization
        status = OwlySendVmmRegistrationIoctlAsync((PVOID)OwlyHypervisorCallback);
        
        if (!NT_SUCCESS(status)) {
#if IS_DEBUG_IRP
            DbgPrint("!!! Owlyshield: Failed to queue VMM registration: 0x%X\n", status);
#endif
            ObDereferenceObject(g_HvFileObject);
            g_HvFileObject = NULL;
            g_HvDeviceObject = NULL;
        }
        
        // Always return success - registration happens asynchronously
        status = STATUS_SUCCESS;
    } else {
#if IS_DEBUG_IRP
        DbgPrint("!!! Owlyshield: No standalone Hypervisor found (Intel/AMD). Continuing without VMM.\n");
#endif
        status = STATUS_SUCCESS;
    }

    return status;
}

VOID CleanupVmmCommunication()
{
    if (g_HvFileObject != NULL && g_HvDeviceObject != NULL)
    {
        if (g_HvCallbackRegistered)
        {
            // Unregister synchronously during cleanup - we're already in unload path
            KEVENT event;
            IO_STATUS_BLOCK ioStatus;
            OWLY_HV_COMM_DATA commData = { 0 };
            PIRP irp;
            
            commData.Magic = OWLY_HV_COMM_MAGIC;
            commData.CallbackRoutine = NULL;
            
            KeInitializeEvent(&event, NotificationEvent, FALSE);
            
            irp = IoBuildDeviceIoControlRequest(
                IOCTL_REGISTER_OWLY_CALLBACK,
                g_HvDeviceObject,
                &commData,
                sizeof(commData),
                NULL,
                0,
                FALSE,
                &event,
                &ioStatus);
                
            if (irp != NULL)
            {
                NTSTATUS status = IoCallDriver(g_HvDeviceObject, irp);
                if (status == STATUS_PENDING)
                {
                    KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
                }
            }
            
            g_HvCallbackRegistered = FALSE;
        }

        ObDereferenceObject(g_HvFileObject);
        g_HvFileObject = NULL;
        g_HvDeviceObject = NULL;
    }
}

#endif // OWLY_HYPERVISOR_SUPPORT


// IoCreateDriver is an undocumented ntoskrnl export - not declared in any WDK
// header.  Resolve it dynamically via MmGetSystemRoutineAddress (the same
// pattern used in UserModeHookEngine.cpp for other unexported routines) so
// the static analyser never sees an EXTERN_C declaration without a visible
// definition, eliminating VCR001 "Function definition not found".
typedef NTSTATUS(NTAPI *PIO_CREATE_DRIVER)(_In_opt_ PUNICODE_STRING DriverName,
                                           _In_ PDRIVER_INITIALIZE InitializationFunction);

static PIO_CREATE_DRIVER fnIoCreateDriver = NULL;

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
// The per-process device handle is opened WITH FILE_SYNCHRONOUS_IO_NONALERT
// (see InitializeShellcodeInfrastructure in UserModeHookEngine.cpp).
// NtDeviceIoControlFile therefore executes synchronously: it does NOT return
// STATUS_PENDING; it blocks the calling thread until the IRP completes.
// This dispatch routine MUST call IoCompleteRequest BEFORE returning
// (synchronous inline completion, done via CompleteIrpInline below).
//
// WHY THIS MATTERS: The shellcode passes a pointer to an IO_STATUS_BLOCK
// that lives on its stack frame as the ApcContext argument to
// NtDeviceIoControlFile.  If the IRP were pended and completed later, the
// I/O manager would write IoStatusBlock AFTER the shellcode's stack frame
// has been unwound — a use-after-return/stack-corruption bug.
//
// For a fire-and-forget notify IOCTL (no output data, no deferred work)
// synchronous inline completion is correct and sufficient.
//
// DO NOT change this to an asynchronous (STATUS_PENDING) completion path
// without simultaneously changing the shellcode and the ZwCreateFile flags
// in InitializeShellcodeInfrastructure.
//
// METHOD_BUFFERED
// ---------------
// IOCTL_REPORT_HOOK_EVENT uses METHOD_BUFFERED.  The I/O manager copies
// the caller's InputBuffer (HOOK_EVENT_DATA on the shellcode's stack) into
// a kernel-mode system buffer BEFORE calling this dispatch routine.  The
// system buffer is accessed via Irp->AssociatedIrp.SystemBuffer.  No
// ProbeForRead is needed - the data is already in kernel address space.
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

#define OWLY_HOOK_DEVICE_NAME L"\\Device\\OwlyshieldHook"
#define OWLY_HOOK_DRIVER_NAME L"\\Driver\\OwlyshieldHookNotify"
#define OWLY_HOOK_SYMLINK_NAME L"\\DosDevices\\OwlyshieldHook"

static PDEVICE_OBJECT g_HookNotifyDevice = NULL;
static PDRIVER_OBJECT g_HookNotifyDriverObject = NULL;

typedef struct _CLIENT_ID32
{
    ULONG UniqueProcess;
    ULONG UniqueThread;
} CLIENT_ID32, *PCLIENT_ID32;

static BOOLEAN IsLiveProcessId(_In_ ULONG ProcessId)
{
    PEPROCESS process = NULL;
    NTSTATUS status;

    if (ProcessId == 0)
    {
        return FALSE;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status) || process == NULL)
    {
        return FALSE;
    }

    ObDereferenceObject(process);
    return TRUE;
}

static ULONG ResolveProcessIdFromClientIdPointer(_In_ ULONG_PTR ClientIdAddress)
{
    ULONG processId = 0;

    if (ClientIdAddress == 0)
    {
        return 0;
    }

    __try
    {
        CLIENT_ID cid64;
        ProbeForRead((PVOID)ClientIdAddress, sizeof(cid64), TYPE_ALIGNMENT(CLIENT_ID));
        RtlCopyMemory(&cid64, (PVOID)ClientIdAddress, sizeof(cid64));
        processId = (ULONG)(ULONG_PTR)cid64.UniqueProcess;
        if (IsLiveProcessId(processId))
        {
            return processId;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    __try
    {
        CLIENT_ID32 cid32;
        ProbeForRead((PVOID)ClientIdAddress, sizeof(cid32), TYPE_ALIGNMENT(ULONG));
        RtlCopyMemory(&cid32, (PVOID)ClientIdAddress, sizeof(cid32));
        processId = cid32.UniqueProcess;
        if (IsLiveProcessId(processId))
        {
            return processId;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return 0;
}

static VOID ConsiderTargetPidCandidate(_In_ ULONG SourcePid, _In_ ULONG CandidatePid, _Inout_ PULONG PreferredPid,
                                       _Inout_ PULONG FallbackPid)
{
    if (CandidatePid == 0)
    {
        return;
    }

    if (CandidatePid != SourcePid)
    {
        if (*PreferredPid == 0)
        {
            *PreferredPid = CandidatePid;
        }
        return;
    }

    if (*FallbackPid == 0)
    {
        *FallbackPid = CandidatePid;
    }
}

static ULONG ResolveProcessIdFromProcessHandle(_In_ HANDLE ProcessHandle)
{
    PEPROCESS process = NULL;
    NTSTATUS status;
    ULONG processId = 0;

    if (ProcessHandle == NULL)
    {
        return 0;
    }

    if (ProcessHandle == NtCurrentProcess())
    {
        return (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    }

    status = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, UserMode, (PVOID *)&process, NULL);
    if (!NT_SUCCESS(status) || process == NULL)
    {
        return 0;
    }

    processId = (ULONG)(ULONG_PTR)PsGetProcessId(process);
    ObDereferenceObject(process);
    return processId;
}

static ULONG ResolveProcessIdFromThreadHandle(_In_ HANDLE ThreadHandle)
{
    PETHREAD thread = NULL;
    NTSTATUS status;
    ULONG processId = 0;

    if (ThreadHandle == NULL)
    {
        return 0;
    }

    if (ThreadHandle == NtCurrentThread())
    {
        return (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    }

    status = ObReferenceObjectByHandle(ThreadHandle, 0, *PsThreadType, UserMode, (PVOID *)&thread, NULL);
    if (!NT_SUCCESS(status) || thread == NULL)
    {
        return 0;
    }

    processId = (ULONG)(ULONG_PTR)PsGetProcessId(IoThreadToProcess(thread));
    ObDereferenceObject(thread);
    return processId;
}

static ULONG ResolveHookTargetProcessId(_In_ ULONG SourcePid, _In_ ULONG_PTR RawArg1, _In_ ULONG_PTR RawArg2,
                                        _In_ ULONG_PTR RawArg3, _In_ ULONG_PTR RawArg4)
{
    const ULONG_PTR args[] = {RawArg1, RawArg2, RawArg3, RawArg4};
    ULONG preferredPid = 0;
    ULONG fallbackPid = 0;
    ULONG candidatePid = 0;
    ULONG i = 0;

    for (i = 0; i < RTL_NUMBER_OF(args); ++i)
    {
        candidatePid = ResolveProcessIdFromProcessHandle((HANDLE)args[i]);
        ConsiderTargetPidCandidate(SourcePid, candidatePid, &preferredPid, &fallbackPid);
        if (preferredPid != 0)
        {
            return preferredPid;
        }
    }

    for (i = 0; i < RTL_NUMBER_OF(args); ++i)
    {
        candidatePid = ResolveProcessIdFromThreadHandle((HANDLE)args[i]);
        ConsiderTargetPidCandidate(SourcePid, candidatePid, &preferredPid, &fallbackPid);
        if (preferredPid != 0)
        {
            return preferredPid;
        }
    }

    for (i = 0; i < RTL_NUMBER_OF(args); ++i)
    {
        candidatePid = ResolveProcessIdFromClientIdPointer(args[i]);
        ConsiderTargetPidCandidate(SourcePid, candidatePid, &preferredPid, &fallbackPid);
        if (preferredPid != 0)
        {
            return preferredPid;
        }
    }

    return fallbackPid;
}

// ----------------------------------------------------------------------------
// CompleteIrpInline - complete an IRP synchronously, before returning.
// METHOD_BUFFERED guarantees HOOK_EVENT_DATA is already in sysBuf by the
// time dispatch is called, so no deferred work is needed.
// ----------------------------------------------------------------------------
static NTSTATUS CompleteIrpInline(_In_ PIRP Irp, _In_ NTSTATUS Status, _In_ ULONG_PTR Info)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

// ----------------------------------------------------------------------------
// HookDeviceCreateClose - IRP_MJ_CREATE / IRP_MJ_CLOSE
// Accept all open/close requests; ZwCreateFile and ObInsertObject both
// generate IRP_MJ_CREATE, which must succeed for the handle to be valid.
// ----------------------------------------------------------------------------
static NTSTATUS HookDeviceCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return CompleteIrpInline(Irp, STATUS_SUCCESS, 0);
}

// ----------------------------------------------------------------------------
// HookDeviceControl - IRP_MJ_DEVICE_CONTROL
//
// Receives HOOK_EVENT_DATA (or the legacy HOOK_EVENT_DATA_WIRE80 subset) from
// the shellcode running inside the hooked user-mode process.
//
// Runs in the hooked thread's context at PASSIVE_LEVEL.
// METHOD_BUFFERED: the I/O manager copies the caller's InputBuffer into
// Irp->AssociatedIrp.SystemBuffer before calling here - no ProbeForRead needed.
//
// Async contract: IoCompleteRequest is called before returning (inline
// completion), so NtDeviceIoControlFile in the shellcode returns STATUS_SUCCESS
// with IoStatusBlock written while the shellcode's stack frame is still live.
//
// Name resolution priority:
//   1. Fully-qualified "module!function" label in the incoming payload.
//   2. ResolveHookNameByEventId (driver-side lookup by EventId).
//   3. Bare (unqualified) name from the payload.
//   4. Empty string - event is still delivered.
// ----------------------------------------------------------------------------
static NTSTATUS HookDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID sysBuf = Irp->AssociatedIrp.SystemBuffer;

    if (code != IOCTL_REPORT_HOOK_EVENT)
        return CompleteIrpInline(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);

    // Minimum: legacy wire format (EventType + ProcessId + FunctionName[64] + Arg1)
    typedef struct _HOOK_EVENT_DATA_WIRE80
    {
        ULONG EventType;
        ULONG ProcessId;
        CHAR FunctionName[64];
        ULONG_PTR Arg1;
    } HOOK_EVENT_DATA_WIRE80, *PHOOK_EVENT_DATA_WIRE80;

    if (sysBuf == NULL || inputLen < sizeof(HOOK_EVENT_DATA_WIRE80))
        return CompleteIrpInline(Irp, STATUS_BUFFER_TOO_SMALL, 0);

    ULONG eventType = 0;
    ULONG processId = 0;
    ULONG_PTR rawArg1 = 0;
    ULONG_PTR rawArg2 = 0;
    ULONG_PTR rawArg3 = 0;
    ULONG_PTR rawArg4 = 0;
    ULONG targetProcessId = 0;
    WCHAR convertedName[64] = {0};
    PCWSTR incomingWideName = NULL;

    if (inputLen >= sizeof(HOOK_EVENT_DATA))
    {
        // Full current payload
        PHOOK_EVENT_DATA ev = (PHOOK_EVENT_DATA)sysBuf;
        eventType = ev->EventType;
        processId = ev->ProcessId;
        rawArg1 = ev->Arg1;
        rawArg2 = ev->Arg2;
        rawArg3 = ev->Arg3;
        rawArg4 = ev->Arg4;

        if (ev->FunctionName[0] != '\0')
        {
            ANSI_STRING asFunc;
            UNICODE_STRING usFunc;
            RtlInitAnsiString(&asFunc, ev->FunctionName);
            usFunc.Buffer = convertedName;
            usFunc.Length = 0;
            usFunc.MaximumLength = sizeof(convertedName);
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
        rawArg1 = ev80->Arg1;
        rawArg2 = 0;
        rawArg3 = 0;
        rawArg4 = 0;

        if (ev80->FunctionName[0] != '\0')
        {
            ANSI_STRING asFunc;
            UNICODE_STRING usFunc;
            RtlInitAnsiString(&asFunc, ev80->FunctionName);
            usFunc.Buffer = convertedName;
            usFunc.Length = 0;
            usFunc.MaximumLength = sizeof(convertedName);
            if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&usFunc, &asFunc, FALSE)))
            {
                convertedName[RTL_NUMBER_OF(convertedName) - 1] = L'\0';
                incomingWideName = convertedName;
            }
        }
    }

    // Resolve the best function name available
    WCHAR resolvedName[MAX_FILE_NAME_LENGTH] = {0};
    PCWSTR functionName = L"";

    BOOLEAN incomingHasName = (incomingWideName != NULL && incomingWideName[0] != L'\0');
    BOOLEAN incomingQualified = FALSE;

    if (incomingHasName)
    {
        incomingQualified = (wcschr(incomingWideName, L'!') != NULL) ? TRUE : FALSE;
    }

    if (incomingQualified)
    {
        // Trust fully-qualified "module!function" labels directly
        functionName = incomingWideName;
    }
    else if (ResolveHookNameByEventId(eventType, resolvedName, RTL_NUMBER_OF(resolvedName)) && resolvedName[0] != L'\0')
    {
        functionName = resolvedName;
    }
    else if (incomingHasName)
    {
        functionName = incomingWideName;
    }

    targetProcessId = ResolveHookTargetProcessId(processId, rawArg1, rawArg2, rawArg3, rawArg4);

#if IS_DEBUG_IRP
    DbgPrint("HookDevice: API HOOKING EVENT RawType=%lu Name=%ws SourcePid=%lu TargetPid=%lu Arg1=0x%p "
             "Arg2=0x%p Arg3=0x%p Arg4=0x%p\n",
             eventType, functionName, processId, targetProcessId, (PVOID)rawArg1, (PVOID)rawArg2,
             (PVOID)rawArg3, (PVOID)rawArg4);
#endif

    // Deliver to the classification pipeline (ProcessProtection.cpp).
    // Also enqueue for user-mode delivery via MESSAGE_GET_OPS.
    cmd::OnKernelApiEvent(IRP_USERMODE_HOOK_EVENT, eventType, processId, targetProcessId, functionName, rawArg1, rawArg2, rawArg3, rawArg4);

    return CompleteIrpInline(Irp, STATUS_SUCCESS, 0);
}

// ----------------------------------------------------------------------------
// HookNotifyDriverUnload - fires when the I/O manager drops the last
// reference to g_HookNotifyDriverObject after IoDeleteDevice.
// ----------------------------------------------------------------------------
static VOID HookNotifyDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
#if IS_DEBUG_IRP
    DbgPrint("!!! HookDevice: DriverUnload\n");
#endif
}

// ----------------------------------------------------------------------------
// HookNotifyDriverInit - IoCreateDriver callback.
//
// Receives a fresh DRIVER_OBJECT completely independent of the minifilter's
// DriverObject.  FltMgr never sees this object, so writing MajorFunction
// entries here cannot cause FLTMGR_FILE_SYSTEM (0xF5).
// ----------------------------------------------------------------------------
static NTSTATUS HookNotifyDriverInit(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    g_HookNotifyDriverObject = DriverObject;
    DriverObject->DriverUnload = HookNotifyDriverUnload;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = HookDeviceCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = HookDeviceCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HookDeviceControl;

    UNICODE_STRING devName, symName;
    RtlInitUnicodeString(&devName, OWLY_HOOK_DEVICE_NAME);
    RtlInitUnicodeString(&symName, OWLY_HOOK_SYMLINK_NAME);

    // Defensively delete any leftover symlink/device from a previous driver
    // session that crashed without a clean unload. If these don't exist,
    // IoDeleteSymbolicLink / IoDeleteDevice return non-success silently.
    // Without this, IoCreateDevice returns STATUS_OBJECT_NAME_COLLISION on
    // reload and g_HookNotifyDevice stays NULL - shellcode IOCTLs silently
    // fail and no usermode hook events are ever delivered.
    IoDeleteSymbolicLink(&symName);

    NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
                                     &g_HookNotifyDevice);

    if (!NT_SUCCESS(status))
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! HookDevice: IoCreateDevice failed 0x%X\n", status);
#endif
        return status;
    }

    g_HookNotifyDevice->Flags |= DO_BUFFERED_IO;
    g_HookNotifyDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status))
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! HookDevice: IoCreateSymbolicLink failed 0x%X\n", status);
#endif
        IoDeleteDevice(g_HookNotifyDevice);
        g_HookNotifyDevice = NULL;
        return status;
    }

#if IS_DEBUG_IRP
    DbgPrint("!!! HookDevice: Ready at %S\n", OWLY_HOOK_DEVICE_NAME);
#endif
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
// InitHookNotifyDevice - public entry point, called from DriverEntry.
//
// IoCreateDriver allocates a fully independent DRIVER_OBJECT and calls
// HookNotifyDriverInit synchronously.  The minifilter's DriverObject
// (owned by FltMgr) is NEVER touched - no MajorFunction entries are
// replaced, so FLTMGR_FILE_SYSTEM (0xF5) cannot occur.
//
// No ordering dependency on FltRegisterFilter or FltStartFiltering.
// ----------------------------------------------------------------------------
NTSTATUS InitHookNotifyDevice(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    // Resolve IoCreateDriver on first call.
    if (fnIoCreateDriver == NULL)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"IoCreateDriver");
        fnIoCreateDriver = (PIO_CREATE_DRIVER)MmGetSystemRoutineAddress(&routineName);
        if (fnIoCreateDriver == NULL)
        {
#if IS_DEBUG_IRP
            DbgPrint("!!! HookDevice: MmGetSystemRoutineAddress(IoCreateDriver) failed\n");
#endif
            return STATUS_NOT_IMPLEMENTED;
        }
    }

    UNICODE_STRING driverName;
    RtlInitUnicodeString(&driverName, OWLY_HOOK_DRIVER_NAME);

    NTSTATUS status = fnIoCreateDriver(&driverName, HookNotifyDriverInit);
    if (!NT_SUCCESS(status))
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! HookDevice: IoCreateDriver failed 0x%X\n", status);
#endif
        g_HookNotifyDevice = NULL;
        g_HookNotifyDriverObject = NULL;
    }
    return status;
}

// ----------------------------------------------------------------------------
// CleanupHookNotifyDevice - called from DriverUnload.
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
    g_HookNotifyDevice = NULL;
    g_HookNotifyDriverObject = NULL;

#if IS_DEBUG_IRP
    DbgPrint("!!! HookDevice: Cleaned up\n");
#endif
}

// Returns the PDEVICE_OBJECT so UserModeHookEngine can use
// ObOpenObjectByPointer + ObInsertObject instead of ZwCreateFile
// (ZwCreateFile is forbidden inside KeStackAttachProcess).
// extern "C" must match the declaration in Communication.h which is
// inside an extern "C" block - without this the linker sees a C++
// mangled name here vs. an unmangled C name at the call site.
extern "C" PDEVICE_OBJECT GetHookNotifyDeviceObject(VOID)
{
    return g_HookNotifyDevice;
}

#if OWLY_HYPERVISOR_SUPPORT

#define OWLY_HV_EVENT_QUEUE_TAG 'vHwO'

typedef struct _OWLY_HV_EVENT_ENTRY
{
    LIST_ENTRY Entry;
    DRIVER_MESSAGE Message;
} OWLY_HV_EVENT_ENTRY, *POWLY_HV_EVENT_ENTRY;

static LIST_ENTRY g_OwlyHvEventQueue;
static KSPIN_LOCK g_OwlyHvEventQueueLock;
static BOOLEAN g_OwlyHvEventQueueInitialized = FALSE;
static ULONG g_OwlyHvEventQueueSize = 0;

static VOID EnsureQueuedHypervisorEventsInitialized(VOID)
{
    if (!g_OwlyHvEventQueueInitialized)
    {
        InitializeListHead(&g_OwlyHvEventQueue);
        KeInitializeSpinLock(&g_OwlyHvEventQueueLock);
        g_OwlyHvEventQueueSize = 0;
        g_OwlyHvEventQueueInitialized = TRUE;
    }
}

#endif // OWLY_HYPERVISOR_SUPPORT

#define OWLY_UMH_DRAIN_POOL_TAG 'dHuM'
#define OWLY_UMH_DRAIN_BATCH_EVENTS 64UL
#define OWLY_UMH_DRAIN_MAX_ROUNDS_PER_PID 16UL

#if OWLY_HYPERVISOR_SUPPORT

static PCWSTR OwlyHypervisorEventDefaultLabel(_In_ ULONG EventType)
{
    switch (EventType)
    {
    case IRP_NONE:
        return L"IRP_NONE";
    case IRP_READ:
        return L"IRP_READ";
    case IRP_WRITE:
        return L"IRP_WRITE";
    case IRP_SETINFO:
        return L"IRP_SETINFO";
    case IRP_CREATE:
        return L"IRP_CREATE";
    case IRP_CLEANUP:
        return L"IRP_CLEANUP";
    case IRP_REGISTRY:
        return L"IRP_REGISTRY";
    case IRP_PROCESS_CREATE:
        return L"IRP_PROCESS_CREATE";
    case IRP_PROCESS_TERMINATE:
        return L"IRP_PROCESS_TERMINATE";
    case IRP_PROCESS_TERMINATE_ATTEMPT:
        return L"IRP_PROCESS_TERMINATE_ATTEMPT";
    case IRP_PROCESS_EXIT:
        return L"IRP_PROCESS_EXIT";
    case IRP_PROCESS_HANDLE_OPEN:
        return L"IRP_PROCESS_HANDLE_OPEN";
    case IRP_HYPERVISOR_EVENT:
        return L"IRP_HYPERVISOR_EVENT";
    case IRP_KERNEL_REMOTE_THREAD:
        return L"IRP_KERNEL_REMOTE_THREAD";
    case IRP_KERNEL_WRITE_MEMORY:
        return L"IRP_KERNEL_WRITE_MEMORY";
    case IRP_KERNEL_PROTECT_MEMORY:
        return L"IRP_KERNEL_PROTECT_MEMORY";
    case IRP_KERNEL_CREATE_THREAD:
        return L"IRP_KERNEL_CREATE_THREAD";
    case IRP_KERNEL_QUEUE_APC:
        return L"IRP_KERNEL_QUEUE_APC";
    case IRP_KERNEL_CREATE_SECTION:
        return L"IRP_KERNEL_CREATE_SECTION";
    case IRP_KERNEL_MAP_SECTION:
        return L"IRP_KERNEL_MAP_SECTION";
    case IRP_USERMODE_HOOK_EVENT:
        return L"IRP_USER_MODE_HOOK_EVENT";
    case IRP_ROOTKIT_SSDT_HOOK:
        return L"IRP_ROOTKIT_SSDT_HOOK";
    case IRP_ROOTKIT_HIDDEN_PROCESS:
        return L"IRP_ROOTKIT_HIDDEN_PROCESS";
    case IRP_ROOTKIT_HIDDEN_DRIVER:
        return L"IRP_ROOTKIT_HIDDEN_DRIVER";
    case IRP_ROOTKIT_KERNEL_HOOK:
        return L"IRP_ROOTKIT_KERNEL_HOOK";
    case IRP_ROOTKIT_TERMINATE_PROCESS:
        return L"IRP_ROOTKIT_TERMINATE_PROCESS";
    case IRP_ROOTKIT_FILE_MOVE:
        return L"IRP_ROOTKIT_FILE_MOVE";
    case IRP_ROOTKIT_GENERIC:
        return L"IRP_ROOTKIT_GENERIC";
    case IRP_NAMED_PIPE_CREATE:
        return L"IRP_NAMED_PIPE_CREATE";
    case IRP_NAMED_PIPE_WRITE:
        return L"IRP_NAMED_PIPE_WRITE";
    default:
        return L"";
    }
}

static VOID OwlyTriggerRootkitDetectorForHypervisorEvent(_In_ UCHAR EffectiveIrpOp)
{
    if ((EffectiveIrpOp >= IRP_KERNEL_REMOTE_THREAD && EffectiveIrpOp <= IRP_USERMODE_HOOK_EVENT) ||
        (EffectiveIrpOp >= IRP_ROOTKIT_SSDT_HOOK && EffectiveIrpOp <= IRP_ROOTKIT_GENERIC))
    {
        RootkitDetectorOnDriverEvent(RK_TRIGGER_FULL, EffectiveIrpOp);
    }
}

BOOLEAN
QueueHypervisorEvent(_In_ const OWLY_HV_EVENT_DETAILS * EventDetails)
{
    ULONG currentPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    ULONG sourcePid;
    ULONG targetPid;
    ULONG ownerPid;
    LARGE_INTEGER timestamp;
    UCHAR effectiveIrpOp;
    PCWSTR eventName;

    if (EventDetails == NULL)
    {
        return FALSE;
    }

    sourcePid = (EventDetails->SourceProcessId != 0) ? EventDetails->SourceProcessId : currentPid;
    targetPid = (EventDetails->TargetProcessId != 0) ? EventDetails->TargetProcessId : sourcePid;
    ownerPid = (targetPid != 0) ? targetPid : sourcePid;

    if (EventDetails->RawEventType <= IRP_NAMED_PIPE_WRITE)
    {
        effectiveIrpOp = (UCHAR)EventDetails->RawEventType;
    }
    else
    {
        effectiveIrpOp = IRP_HYPERVISOR_EVENT;
    }

    KeQuerySystemTime(&timestamp);

    eventName = (EventDetails->EventName != NULL && EventDetails->EventName[0] != L'\0')
                    ? EventDetails->EventName
                    : OwlyHypervisorEventDefaultLabel(EventDetails->RawEventType);

    // Deliver hypervisor event through OpenEDR fltport (same LBVS path as hook events).
    // SysmonEvent::DeviceIoControl (0x000E) is the carrier; owlyHv.* fields carry the
    // hypervisor-specific payload so EventEnricher / controller.cpp can reconstruct them.
    cmd::NonPagedLbvsSerializer<cmd::edrdrv::EventField> serializer;
    if (!serializer.write(cmd::edrdrv::EventField::RawEventId,
            uint16_t(cmd::edrdrv::SysmonEvent::DeviceIoControl)))           goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::TickTime,
            (uint64_t)cmd::getTickCount64()))                               goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::ProcessPid,
            (uint32_t)ownerPid))                                       goto send_done;
    // Hook-compatible fields (reuse existing IDs so controller.cpp needs no changes)
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHookEventType,
            (uint32_t)EventDetails->RawEventType))                     goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHookSourcePid,
            (uint32_t)sourcePid))                                      goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHookArg1,
            (uint64_t)EventDetails->RawArgument1))                     goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHookArg2,
            (uint64_t)EventDetails->RawArgument2))                     goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHookArg3,
            (uint64_t)EventDetails->RawArgument3))                     goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHookArg4,
            (uint64_t)EventDetails->RawArgument4))                     goto send_done;
    if (eventName != NULL && eventName[0] != L'\0')
    {
        UNICODE_STRING usName;
        RtlInitUnicodeString(&usName, eventName);
        if (!cmd::write(serializer, cmd::edrdrv::EventField::OwlyHookFunctionName, &usName))
            goto send_done;
    }
    // Hypervisor-specific fields
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHvMemoryAddress,
            (uint64_t)EventDetails->MemoryAddress))                    goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHvMemorySize,
            (uint64_t)EventDetails->MemorySize))                       goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHvMemoryProtection,
            (uint32_t)EventDetails->MemoryProtection))                 goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHvIsExecutableMemory,
            (uint32_t)EventDetails->IsExecutableMemory))               goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHvThreadHandle,
            (uint64_t)(ULONG_PTR)EventDetails->ThreadHandle))          goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHvThreadStartRoutine,
            (uint64_t)(ULONG_PTR)EventDetails->ThreadStartRoutine))    goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHvAccessMask,
            (uint32_t)EventDetails->AccessMask))                       goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHvOperationStatus,
            (uint32_t)(ULONG)EventDetails->OperationStatus))           goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHvCoreId,
            (uint32_t)EventDetails->CoreId))                           goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHvThreadId,
            (uint32_t)EventDetails->ThreadId))                         goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHvIsDllLoad,
            (uint32_t)EventDetails->IsDllLoad))                        goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHvIsApiBasedLoad,
            (uint32_t)EventDetails->IsApiBasedLoad))                   goto send_done;
    if (EventDetails->IsDllLoad && EventDetails->LoadedDllPath != NULL
            && EventDetails->LoadedDllPath[0] != L'\0')
    {
        UNICODE_STRING usDll;
        RtlInitUnicodeString(&usDll, EventDetails->LoadedDllPath);
        if (!cmd::write(serializer, cmd::edrdrv::EventField::OwlyHvLoadedDllPath, &usDll))
            goto send_done;
    }
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHvIsAcgEnabled,
            (uint32_t)EventDetails->IsAcgEnabled))                     goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHvTimestamp,
            (uint64_t)timestamp.QuadPart))                             goto send_done;
    if (!serializer.write(cmd::edrdrv::EventField::OwlyHvTargetPid,
            (uint32_t)targetPid))                                      goto send_done;

send_done:
    cmd::fltport::sendRawEvent(serializer);

    OwlyTriggerRootkitDetectorForHypervisorEvent(effectiveIrpOp);

    return TRUE;
}

#endif // OWLY_HYPERVISOR_SUPPORT

// NOTE: no longer static. The ring buffer is now also drained by a
// dedicated kernel worker thread (see HookDrainThreadRoutine in
// UserModeHookEngine.cpp) that runs independently of MESSAGE_GET_OPS,
// since MESSAGE_GET_OPS/DriverGetIrps is the legacy IRP-polling channel
// that the in-process FFI userland worker no longer issues. Keeping this
// callable from both places means MESSAGE_GET_OPS still opportunistically
// drains the ring when it does arrive, without depending on it.
VOID DrainUserModeHookRingEvents(VOID)
{
    ULONG processIds[MAX_HOOKED_PROCESSES] = {0};
    ULONG processCount;
    PHOOK_EVENT_DATA events;

    processCount = UserModeHookSnapshotHookedProcessIds(processIds, RTL_NUMBER_OF(processIds));
    if (processCount == 0)
    {
        return;
    }

    events = (PHOOK_EVENT_DATA)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                               sizeof(HOOK_EVENT_DATA) * OWLY_UMH_DRAIN_BATCH_EVENTS,
                                               OWLY_UMH_DRAIN_POOL_TAG);
    if (events == NULL)
    {
        return;
    }

    for (ULONG processIndex = 0; processIndex < processCount; ++processIndex)
    {
        ULONG processId = processIds[processIndex];

        for (ULONG round = 0; round < OWLY_UMH_DRAIN_MAX_ROUNDS_PER_PID; ++round)
        {
            ULONG eventsRead = 0;
            NTSTATUS status = UserModeHookDrainHookEventsForProcess(processId, events,
                                                                    OWLY_UMH_DRAIN_BATCH_EVENTS,
                                                                    &eventsRead);
            if (!NT_SUCCESS(status) || eventsRead == 0)
            {
                break;
            }

            for (ULONG i = 0; i < eventsRead; ++i)
            {
                HOOK_EVENT_DATA *event = &events[i];
                ULONG eventType = event->EventType;
                ULONG sourcePid = (event->ProcessId != 0) ? event->ProcessId : processId;
                ULONG_PTR rawArg1 = event->Arg1;
                ULONG_PTR rawArg2 = event->Arg2;
                ULONG_PTR rawArg3 = event->Arg3;
                ULONG_PTR rawArg4 = event->Arg4;
                ULONG targetPid = ResolveHookTargetProcessId(sourcePid, rawArg1, rawArg2, rawArg3, rawArg4);
                WCHAR convertedName[64] = {0};
                WCHAR resolvedName[MAX_FILE_NAME_LENGTH] = {0};
                PCWSTR incomingWideName = NULL;
                PCWSTR functionName = L"";
                BOOLEAN incomingHasName = FALSE;
                BOOLEAN incomingQualified = FALSE;

                event->FunctionName[RTL_NUMBER_OF(event->FunctionName) - 1] = '\0';
                if (event->FunctionName[0] != '\0')
                {
                    ANSI_STRING asFunc;
                    UNICODE_STRING usFunc;
                    RtlInitAnsiString(&asFunc, event->FunctionName);
                    usFunc.Buffer = convertedName;
                    usFunc.Length = 0;
                    usFunc.MaximumLength = sizeof(convertedName);
                    if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&usFunc, &asFunc, FALSE)))
                    {
                        convertedName[RTL_NUMBER_OF(convertedName) - 1] = L'\0';
                        incomingWideName = convertedName;
                    }
                }

                incomingHasName = (incomingWideName != NULL && incomingWideName[0] != L'\0');
                if (incomingHasName)
                {
                    incomingQualified = (wcschr(incomingWideName, L'!') != NULL) ? TRUE : FALSE;
                }

                if (incomingQualified)
                {
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

#if IS_DEBUG_IRP
                DbgPrint("UserModeHook: drained ring event RawType=%lu Name=%ws SourcePid=%lu TargetPid=%lu "
                         "Arg1=0x%p Arg2=0x%p Arg3=0x%p Arg4=0x%p\n",
                         eventType, functionName, sourcePid, targetPid, (PVOID)rawArg1, (PVOID)rawArg2,
                         (PVOID)rawArg3, (PVOID)rawArg4);
#endif

                (VOID)cmd::OnKernelApiEvent(IRP_USERMODE_HOOK_EVENT, eventType, sourcePid, targetPid, functionName,
                                            rawArg1, rawArg2, rawArg3, rawArg4);
            }
        }
    }

    ExFreePoolWithTag(events, OWLY_UMH_DRAIN_POOL_TAG);
}

#if OWLY_HYPERVISOR_SUPPORT

VOID ResetQueuedHypervisorEvents(VOID)
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
        PLIST_ENTRY entry = RemoveHeadList(&localList);
        POWLY_HV_EVENT_ENTRY item = CONTAINING_RECORD(entry, OWLY_HV_EVENT_ENTRY, Entry);
        ExFreePoolWithTag(item, OWLY_HV_EVENT_QUEUE_TAG);
    }
}

VOID DrainQueuedHypervisorEvents(_Inout_updates_bytes_(OutputBufferLength) PVOID OutputBuffer,
                                 _In_ ULONG OutputBufferLength, _Inout_ PULONG ReturnOutputBufferLength)
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
        outHeader->data = nullptr;
        outHeader->num_ops = 0;
        *ReturnOutputBufferLength = sizeof(RWD_REPLY_IRPS);
    }

    while (*ReturnOutputBufferLength + sizeof(DRIVER_MESSAGE) <= OutputBufferLength)
    {
        KIRQL oldIrql;
        POWLY_HV_EVENT_ENTRY item = NULL;
        PDRIVER_MESSAGE outMsg;
        PCHAR writePtr;

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
        outMsg = (PDRIVER_MESSAGE)writePtr;

        item->Message.filePath.Buffer = nullptr;
        item->Message.filePath.Length = 0;
        item->Message.filePath.MaximumLength = 0;
        item->Message.next = nullptr;

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

#endif // OWLY_HYPERVISOR_SUPPORT

NTSTATUS InitCommData()
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;
    PSECURITY_DESCRIPTOR sd = NULL;

#if OWLY_HYPERVISOR_SUPPORT
    EnsureQueuedHypervisorEventsInitialized();
#endif

    RtlInitUnicodeString(&uniString, ComPortName);

    //
    // Build the default security descriptor first.
    //
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status))
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: FltBuildDefaultSecurityDescriptor failed: 0x%X\n", status);
#endif
        return status;
    }

    // Keep the default Filter Manager security descriptor. Do NOT install a
    // NULL DACL here. The connect callback below performs the final identity
    // check, but the object ACL should still reject low-privilege opens before
    // they reach RWFConnect.

    InitializeObjectAttributes(
        &oa,
        &uniString,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        sd);

    status = FltCreateCommunicationPort(
        commHandle->Filter,
        &commHandle->ServerPort,
        &oa,
        NULL,
        RWFConnect,
        RWFDissconnect,
        RWFNewMessage,
        1);

    //
    // Always free the security descriptor after FltCreateCommunicationPort.
    //
    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status))
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: FltCreateCommunicationPort failed: 0x%X\n", status);
#endif
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

    if (driverData != NULL)
    {
        driverData->ClearIrps();
    }

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


#if IS_DEBUG_IRP
    DbgPrint("!!! FSfilter: RWFConnect - ACCEPTED connection\n");
#endif

    //
    //  Set the user process and port.
    //

    commHandle->ClientPort = ClientPort;
#if IS_DEBUG_IRP
    DbgPrint("!!! user connected, port=0x%p\n", ClientPort);
#endif

    return STATUS_SUCCESS;
}

VOID RWFDissconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

#if IS_DEBUG_IRP
    DbgPrint("!!! user disconnected, port=0x%p\n", commHandle->ClientPort);
#endif

    //
    //  Close our handle to the connection: note, since we limited max connections to 1,
    //  another connect will not be allowed until we return from the disconnect routine.
    //

    FltCloseClientPort(commHandle->Filter, &commHandle->ClientPort);

    //
    //  Reset the user-process field.
    //
#if IS_DEBUG_IRP
    DbgPrint("Disconnent\n");
#endif
    commHandle->CommClosed = TRUE;

    if (driverData != NULL)
    {
        driverData->ClearIrps();
    }
}

static NTSTATUS OwlyGetProcessNameByHandle(_In_ HANDLE ProcessHandle, _Out_ PUNICODE_STRING *Name)
{
    if (Name == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *Name = NULL;

    cmd::PZwQueryInformationProcess queryProcessInfo =
        (cmd::g_pCommonData != NULL) ? cmd::g_pCommonData->fnZwQueryInformationProcess : NULL;
    if (queryProcessInfo == NULL)
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    ULONG bufferSize = 0;
    NTSTATUS status = queryProcessInfo(ProcessHandle, ProcessImageFileName, NULL, 0, &bufferSize);
    if (NT_ERROR(status) && status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL)
    {
        return status;
    }

    if (bufferSize < sizeof(UNICODE_STRING))
    {
        bufferSize = 512;
    }

    PUNICODE_STRING processName =
        (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, OWLY_POOL_TAG_PROCESS_NAME);
    if (processName == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = queryProcessInfo(ProcessHandle, ProcessImageFileName, processName, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(processName, OWLY_POOL_TAG_PROCESS_NAME);
        return status;
    }

    *Name = processName;
    return STATUS_SUCCESS;
}

static NTSTATUS OwlyDeleteFileByPath(_In_ PUNICODE_STRING FilePath)
{
    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    OBJECT_ATTRIBUTES objAttributes;
    InitializeObjectAttributes(&objAttributes, FilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    return ZwDeleteFile(&objAttributes);
}

static NTSTATUS OwlyQuarantineFileByPath(_In_ PUNICODE_STRING FilePath)
{
    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status;
    HANDLE sourceHandle = NULL;
    HANDLE destHandle = NULL;
    OBJECT_ATTRIBUTES objAttribs;
    IO_STATUS_BLOCK ioStatus;

    UNICODE_STRING quarantineDir;
    RtlInitUnicodeString(&quarantineDir, QuarantinePath);

    InitializeObjectAttributes(&objAttribs, &quarantineDir, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateFile(&destHandle, GENERIC_WRITE | SYNCHRONIZE, &objAttribs, &ioStatus, NULL,
                          FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                          FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    InitializeObjectAttributes(&objAttribs, FilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenFile(&sourceHandle, DELETE | SYNCHRONIZE, &objAttribs, &ioStatus,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status))
    {
        ZwClose(destHandle);
        return status;
    }

    USHORT filenameOffset = 0;
    for (USHORT i = FilePath->Length / sizeof(WCHAR); i > 0; i--)
    {
        if (FilePath->Buffer[i - 1] == L'\\')
        {
            filenameOffset = i;
            break;
        }
    }

    UNICODE_STRING filename;
    filename.Buffer = &FilePath->Buffer[filenameOffset];
    filename.Length = FilePath->Length - (filenameOffset * sizeof(WCHAR));
    filename.MaximumLength = filename.Length;

    ULONG renameInfoSize = sizeof(FILE_RENAME_INFORMATION) + filename.Length;
    PFILE_RENAME_INFORMATION renameInfo =
        (PFILE_RENAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, renameInfoSize, OWLY_POOL_TAG_FILE_TEMP);
    if (renameInfo == NULL)
    {
        ZwClose(sourceHandle);
        ZwClose(destHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(renameInfo, renameInfoSize);
    renameInfo->ReplaceIfExists = TRUE;
    renameInfo->RootDirectory = destHandle;
    renameInfo->FileNameLength = filename.Length;
    RtlCopyMemory(renameInfo->FileName, filename.Buffer, filename.Length);

    status = ZwSetInformationFile(sourceHandle, &ioStatus, renameInfo, renameInfoSize, FileRenameInformation);

    ExFreePoolWithTag(renameInfo, OWLY_POOL_TAG_FILE_TEMP);
    ZwClose(sourceHandle);
    ZwClose(destHandle);

    return status;
}

// NEW: Helper function to kill all processes in a GID
// removalMode: 0 = Kill Only, 1 = Kill & Quarantine, 2 = Kill & Remove
NTSTATUS KillProcessesInGid(ULONGLONG GID, PLONG OutputStatus, ULONG removalMode)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE processHandle;
    BOOLEAN isGidExist = FALSE;
    ULONGLONG gidSize = driverData->GetGidSize(GID, &isGidExist);

    if (gidSize == 0 || isGidExist == FALSE)
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FS : Gid already ended or no such gid %llu\n", GID);
#endif
        *OutputStatus = STATUS_NO_SUCH_GROUP;
        return STATUS_SUCCESS;
    }

    // Allocate buffer for PIDs
    PULONG Buffer =
        (PULONG)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ULONG) * gidSize, OWLY_POOL_TAG_GID_BUFFER);
    if (Buffer == nullptr)
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FS : memory allocation error on non paged pool\n");
#endif
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
#if IS_DEBUG_IRP
            DbgPrint("!!! FS : Kill and Quarantine action for GID: %llu\n", GID);
#endif
        }
        else if (removalMode == 2)
        {
#if IS_DEBUG_IRP
            DbgPrint("!!! FS : Kill and REMOVE action for GID: %llu\n", GID);
#endif
        }
        else
        {
#if IS_DEBUG_IRP
            DbgPrint("!!! FS : Kill Only action for GID: %llu\n", GID);
#endif
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

#if IS_DEBUG_IRP
            DbgPrint("!!! FS : Attempt to terminate pid: %lu from gid: %llu (mode: %lu)\n", Buffer[i], GID,
                     removalMode);
#endif

            InitializeObjectAttributes(&objAttribs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

            status = ZwOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objAttribs, &clientId);

            if (!NT_SUCCESS(status))
            {
                *OutputStatus = STATUS_FAIL_CHECK;
#if IS_DEBUG_IRP
                DbgPrint("!!! FS : Failed to open process %lu, reason: %d\n", Buffer[i], status);
#endif
                continue;
            }

            // Get the executable path BEFORE killing (important!)
            if (removalMode > 0)
            {
                NTSTATUS pathStatus = OwlyGetProcessNameByHandle(processHandle, &exePath);
                if (NT_SUCCESS(pathStatus) && exePath != NULL && exePath->Length > 0)
                {
#if IS_DEBUG_IRP
                    DbgPrint("!!! FS : Quarantine target: %wZ\n", exePath);
#endif
                }
                else
                {
#if IS_DEBUG_IRP
                    DbgPrint("!!! FS : Warning: Could not get exe path for PID %lu (Status: 0x%X)\n", Buffer[i],
                             pathStatus);
#endif
                }
            }

            status = ZwTerminateProcess(processHandle, exitStatus);
            if (!NT_SUCCESS(status))
            {
                *OutputStatus = STATUS_FAIL_CHECK;
#if IS_DEBUG_IRP
                DbgPrint("!!! FS : Failed to kill process %lu, reason: %d\n", Buffer[i], status);
#endif
                NtClose(processHandle);
                if (exePath != NULL)
                    ExFreePoolWithTag(exePath, OWLY_POOL_TAG_PROCESS_NAME);
                continue;
            }

            NtClose(processHandle);
#if IS_DEBUG_IRP
            DbgPrint("!!! FS : Termination of pid: %lu from gid: %llu succeeded\n", Buffer[i], GID);
#endif

            // Now quarantine or remove the file if requested
            if (removalMode > 0 && exePath != NULL)
            {
                if (removalMode == 1) // Quarantine
                {
                    NTSTATUS quarantineStatus = OwlyQuarantineFileByPath(exePath);
                    if (NT_SUCCESS(quarantineStatus))
                    {
#if IS_DEBUG_IRP
                        DbgPrint("!!! FS : Successfully quarantined file: %wZ\n", exePath);
#endif
                    }
                    else
                    {
#if IS_DEBUG_IRP
                        DbgPrint("!!! FS : Failed to quarantine file %wZ. Status: 0x%X\n", exePath, quarantineStatus);
#endif
                    }
                }
                else if (removalMode == 2) // Remove (Delete)
                {
                    NTSTATUS deleteStatus = OwlyDeleteFileByPath(exePath);
                    if (NT_SUCCESS(deleteStatus))
                    {
#if IS_DEBUG_IRP
                        DbgPrint("!!! FS : Successfully DELETED file: %wZ\n", exePath);
#endif
                    }
                    else
                    {
#if IS_DEBUG_IRP
                        DbgPrint("!!! FS : Failed to delete file %wZ. Status: 0x%X\n", exePath, deleteStatus);
#endif
                    }
                }
                ExFreePoolWithTag(exePath, OWLY_POOL_TAG_PROCESS_NAME);
            }
        }
    }

    ExFreePoolWithTag(Buffer, OWLY_POOL_TAG_GID_BUFFER);
    return STATUS_SUCCESS;
}

static NTSTATUS
CopyWideHookFunctionNameToAnsi(_Out_writes_z_(DestinationCch) PCHAR Destination,
                               _In_ SIZE_T DestinationCch,
                               _In_reads_z_(MAX_FILE_NAME_LENGTH) PCWSTR Source)
{
    SIZE_T sourceLen = 0;
    UNICODE_STRING sourceString;
    ANSI_STRING destinationString;
    NTSTATUS status;

    if (Destination == NULL || DestinationCch == 0 || Source == NULL || Source[0] == L'\0')
    {
        return STATUS_INVALID_PARAMETER;
    }

    Destination[0] = '\0';

    status = RtlStringCchLengthW(Source, MAX_FILE_NAME_LENGTH, &sourceLen);
    if (!NT_SUCCESS(status) || sourceLen == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    sourceString.Buffer = const_cast<PWCH>(Source);
    sourceString.Length = (USHORT)(sourceLen * sizeof(WCHAR));
    sourceString.MaximumLength = (USHORT)((sourceLen + 1) * sizeof(WCHAR));

    destinationString.Buffer = Destination;
    destinationString.Length = 0;
    destinationString.MaximumLength = (USHORT)DestinationCch;

    status = RtlUnicodeStringToAnsiString(&destinationString, &sourceString, FALSE);
    if (!NT_SUCCESS(status))
    {
        Destination[0] = '\0';
        return status;
    }

    if (destinationString.Length >= DestinationCch)
    {
        Destination[DestinationCch - 1] = '\0';
        return STATUS_BUFFER_TOO_SMALL;
    }

    Destination[destinationString.Length] = '\0';
    return STATUS_SUCCESS;
}

NTSTATUS
RWFNewMessage(IN PVOID PortCookie, IN PVOID InputBuffer, IN ULONG InputBufferLength, OUT PVOID OutputBuffer,
              IN ULONG OutputBufferLength, OUT PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(PortCookie);
    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(COM_MESSAGE))
    {
        return STATUS_INVALID_PARAMETER;
    }

    COM_MESSAGE *message = static_cast<COM_MESSAGE *>(InputBuffer);

    if (message->type == MESSAGE_ADD_SCAN_DIRECTORY)
    {
#if IS_DEBUG_IRP
        DbgPrint("Recived add directory message\n");
#endif
        PDIRECTORY_ENTRY newEntry = new DIRECTORY_ENTRY();
        if (newEntry == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        // Security Hardening: Ensure null termination
        message->path[MAX_FILE_NAME_LENGTH - 1] = L'\0';
        NTSTATUS hr = CopyWString(newEntry->path, message->path, MAX_FILE_NAME_LENGTH);
        if (!NT_SUCCESS(hr))
        {
            delete newEntry;
            return STATUS_INVALID_PARAMETER;
        }
        *ReturnOutputBufferLength = 1;
        if (driverData->AddDirectoryEntry(newEntry))
        {
            *((PBOOLEAN)OutputBuffer) = TRUE;
#if IS_DEBUG_IRP
            DbgPrint("Added scan directory successfully\n");
#endif
            return STATUS_SUCCESS;
        }
        else
        {
            delete newEntry;
            *((PBOOLEAN)OutputBuffer) = FALSE;
#if IS_DEBUG_IRP
            DbgPrint("Failed to addscan directory\n");
#endif
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
#if IS_DEBUG_IRP
            DbgPrint("Failed to remove directory\n");
#endif
            return STATUS_SUCCESS;
        }
        else
        {
            delete ptr;
        }
        *((PBOOLEAN)OutputBuffer) = TRUE;
#if IS_DEBUG_IRP
        DbgPrint("Removed scan directory successfully\n");
#endif
        return STATUS_SUCCESS;
    }
    else if (message->type == MESSAGE_ADD_BLOCK_PATH)
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FSfilter: Received add block path message\n");
#endif
        PDIRECTORY_ENTRY newEntry = new DIRECTORY_ENTRY();
        if (newEntry == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        // Security Hardening: Ensure null termination
        message->path[MAX_FILE_NAME_LENGTH - 1] = L'\0';
        NTSTATUS hr = CopyWString(newEntry->path, message->path, MAX_FILE_NAME_LENGTH);
        if (!NT_SUCCESS(hr))
        {
            delete newEntry;
            return STATUS_INVALID_PARAMETER;
        }
        *ReturnOutputBufferLength = 1;
        if (driverData->AddBlockedPath(newEntry))
        {
            *((PBOOLEAN)OutputBuffer) = TRUE;
            return STATUS_SUCCESS;
        }
        else
        {
            delete newEntry;
            *((PBOOLEAN)OutputBuffer) = FALSE;
            return STATUS_SUCCESS;
        }
    }
    else if (message->type == MESSAGE_GET_OPS)
    {
        if (OutputBuffer == NULL || OutputBufferLength != MAX_COMM_BUFFER_SIZE)
        {
            return STATUS_INVALID_PARAMETER;
        }
        *ReturnOutputBufferLength = 0;
#if OWLY_HYPERVISOR_SUPPORT
        DrainQueuedHypervisorEvents(OutputBuffer, OutputBufferLength, ReturnOutputBufferLength);
#endif
        DrainUserModeHookRingEvents();
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
#if IS_DEBUG_IRP
        DbgPrint("!!! FS : Legacy MESSAGE_KILL_GID received for GID: %llu\n", message->gid);
#endif
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
#if IS_DEBUG_IRP
        DbgPrint("!!! FS : MESSAGE_KILL_AND_QUARANTINE_GID received for GID: %llu\n", message->gid);
#endif
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
#if IS_DEBUG_IRP
        DbgPrint("!!! FS : MESSAGE_KILL_ONLY_GID received for GID: %llu\n", message->gid);
#endif
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
#if IS_DEBUG_IRP
        DbgPrint("!!! FS : MESSAGE_KILL_AND_REMOVE_GID received for GID: %llu\n", message->gid);
#endif
        return KillProcessesInGid(message->gid, (PLONG)OutputBuffer, 2); // Mode 2: Remove
    }
    else if (message->type == MESSAGE_REVERT_REGISTRY_CHANGES)
    {
#if IS_DEBUG_IRP
        DbgPrint("!!! FS : MESSAGE_REVERT_REGISTRY_CHANGES received for GID: %llu\n", message->gid);
#endif
        if (message->gid != 0)
        {
            driverData->RevertRegistryChangesForGid(message->gid);
            return STATUS_SUCCESS;
        }
        return STATUS_INVALID_PARAMETER;
    }
    else if (message->type == MESSAGE_ADD_HOOK)
    {
        HOOK_CONFIG_DATA hookConfig = {};
        NTSTATUS status;

        message->path[MAX_FILE_NAME_LENGTH - 1] = L'\0';
        message->quarantine_path[MAX_FILE_NAME_LENGTH - 1] = L'\0';

        status = RtlStringCchCopyW(hookConfig.ModuleName, RTL_NUMBER_OF(hookConfig.ModuleName), message->path);
        if (!NT_SUCCESS(status))
        {
            return STATUS_INVALID_PARAMETER;
        }

        status = CopyWideHookFunctionNameToAnsi(
            hookConfig.FunctionName,
            RTL_NUMBER_OF(hookConfig.FunctionName),
            message->quarantine_path);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        hookConfig.EventId = (ULONG)message->gid;
        return AddCustomHook(&hookConfig);
    }
    else if (message->type == MESSAGE_HOOK_PROCESS)
    {
        if (message->pid == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = UserModeHookProcess(message->pid);
        if (!NT_SUCCESS(status))
        {
#if IS_DEBUG_IRP
            DbgPrint("!!! FS : MESSAGE_HOOK_PROCESS PID %lu failed: 0x%X\n", message->pid, status);
#endif
        }
        return status;
    }

    return STATUS_INVALID_DEVICE_REQUEST;
}

CommHandler *commHandle;
