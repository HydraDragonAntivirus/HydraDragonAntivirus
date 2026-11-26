#include "pch.h"
#include <ntddk.h>

// IOCTL for Hypervisor communication
#define IOCTL_REGISTER_OWLY_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OWLY_HV_COMM_MAGIC           0x4F574C59UL

#define OWLY_HV_RING_CAPACITY        256UL
#define OWLY_HV_RING_MASK            (OWLY_HV_RING_CAPACITY - 1UL)

#define OWLY_HV_EVT_EPT_VIOLATION    0x10UL
#define OWLY_HV_EVT_SYSCALL          0x20UL
#define OWLY_HV_EVT_SYSRET           0x21UL
#define OWLY_HV_EVT_CPUID            0x30UL
#define OWLY_HV_EVT_XSETBV           0x31UL
#define OWLY_HV_EVT_TSC              0x32UL
#define OWLY_HV_EVT_RDMSR            0x40UL
#define OWLY_HV_EVT_WRMSR            0x41UL
#define OWLY_HV_EVT_VMCALL           0x50UL
#define OWLY_HV_EVT_CR_ACCESS        0x60UL
#define OWLY_HV_EVT_HIDDEN_HOOK_MIN  0x90UL
#define OWLY_HV_EVT_HIDDEN_HOOK_MAX  0xA2UL

#define OWLY_MSR_IA32_SYSENTER_EIP   0x00000176ULL
#define OWLY_MSR_IA32_EFER           0xC0000080ULL
#define OWLY_MSR_IA32_LSTAR          0xC0000082ULL
#define OWLY_MSR_IA32_CSTAR          0xC0000083ULL

// Event details structure for Owlyshield communication (exact ABI match with Communication.h)
typedef struct _OWLY_HV_EVENT_DETAILS
{
    ULONG RawEventType;
    ULONG SourceProcessId;
    ULONG TargetProcessId;
    PVOID MemoryAddress;
    SIZE_T MemorySize;
    ULONG MemoryProtection;
    BOOLEAN IsExecutableMemory;
    HANDLE ThreadHandle;
    PVOID ThreadStartRoutine;
    ULONG_PTR RawArgument1;
    ULONG_PTR RawArgument2;
    ULONG_PTR RawArgument3;
    ULONG_PTR RawArgument4;
    ACCESS_MASK AccessMask;
    NTSTATUS OperationStatus;
    _Field_z_ PCWSTR EventName;

    ULONG CoreId;
    ULONG ThreadId;
    ULONGLONG Context;

    // DLL Load Detection
    BOOLEAN IsDllLoad;
    _Field_z_ PCWSTR LoadedDllPath;
    BOOLEAN IsApiBasedLoad;

    // Chromium / ACG Detection
    BOOLEAN IsAcgEnabled;
} OWLY_HV_EVENT_DETAILS, *POWLY_HV_EVENT_DETAILS;

typedef VOID (NTAPI *POWLY_HV_CALLBACK)(POWLY_HV_EVENT_DETAILS EventDetails);

typedef struct _OWLY_HV_COMM_DATA {
    ULONG Magic;           // 0x4F574C59 ('OWLY')
    PVOID CallbackRoutine; // POWLY_HV_CALLBACK
} OWLY_HV_COMM_DATA, *POWLY_HV_COMM_DATA;

typedef struct _OWLY_HV_RING_SLOT {
    volatile LONG Ready; // 0 = empty, 1 = writing, 2 = ready, 3 = draining
    OWLY_HV_EVENT_DETAILS Details;
} OWLY_HV_RING_SLOT;

static OWLY_HV_RING_SLOT g_OwlyEventRing[OWLY_HV_RING_CAPACITY];
static volatile LONG g_OwlyRingWriteIdx = 0;
static ULONG g_OwlyRingReadIdx = 0;
static PVOID volatile g_OwlyCallbackPtr = NULL;
static volatile LONG g_OwlyDrainStop = 0;
static HANDLE g_OwlyDrainThreadHandle = NULL;
static volatile LONG g_VmmInitialized = 0;
static PVOID g_PowerCallbackReg = NULL;
static volatile LONG g_ReinitVmmOnResume = 0;

static BOOLEAN OwlyHvShouldReportEvent(_In_ ULONG EventType, _In_ ULONGLONG Context) {
    if (EventType == OWLY_HV_EVT_CPUID ||
        EventType == OWLY_HV_EVT_XSETBV ||
        EventType == OWLY_HV_EVT_TSC)
    {
        return FALSE;
    }

    if (EventType == OWLY_HV_EVT_WRMSR) {
        return (Context == OWLY_MSR_IA32_SYSENTER_EIP ||
                Context == OWLY_MSR_IA32_EFER ||
                Context == OWLY_MSR_IA32_LSTAR ||
                Context == OWLY_MSR_IA32_CSTAR) ? TRUE : FALSE;
    }

    if (EventType == OWLY_HV_EVT_EPT_VIOLATION ||
        EventType == OWLY_HV_EVT_SYSCALL ||
        EventType == OWLY_HV_EVT_SYSRET ||
        EventType == OWLY_HV_EVT_RDMSR ||
        EventType == OWLY_HV_EVT_VMCALL ||
        EventType == OWLY_HV_EVT_CR_ACCESS ||
        (EventType >= OWLY_HV_EVT_HIDDEN_HOOK_MIN && EventType <= OWLY_HV_EVT_HIDDEN_HOOK_MAX))
    {
        return TRUE;
    }

    return FALSE;
}

static PCWSTR OwlyHvEventLiteralName(_In_ ULONG EventType) {
    if (EventType == OWLY_HV_EVT_WRMSR) {
        return L"WRMSR";
    }
    if (EventType == OWLY_HV_EVT_EPT_VIOLATION) {
        return L"EPT_VIOLATION";
    }
    return L"HYPERVISOR_EVENT";
}

static BOOLEAN HvStartStandaloneVmm(VOID) {
    VMM_CALLBACKS callbacks;

    if (InterlockedCompareExchange(&g_VmmInitialized, 1, 0) != 0) {
        return TRUE;
    }

    RtlZeroMemory(&callbacks, sizeof(callbacks));
    if (!HvInitVmm(&callbacks)) {
        InterlockedExchange(&g_VmmInitialized, 0);
        DbgPrint("!!! hyperhv: HvInitVmm failed (VT-x unsupported or blocked)\n");
        return FALSE;
    }

    BroadcastChangeAllMsrBitmapWriteAllCores(OWLY_MSR_IA32_LSTAR);
    BroadcastChangeAllMsrBitmapWriteAllCores(OWLY_MSR_IA32_CSTAR);
    BroadcastChangeAllMsrBitmapWriteAllCores(OWLY_MSR_IA32_SYSENTER_EIP);
    BroadcastChangeAllMsrBitmapWriteAllCores(OWLY_MSR_IA32_EFER);
    DbgPrint("!!! hyperhv: Standalone VMM started and syscall MSR write traps armed\n");
    return TRUE;
}

static VOID HvStopStandaloneVmm(VOID) {
    if (InterlockedCompareExchange(&g_VmmInitialized, 0, 1) == 1) {
        VmxPerformTermination();
    }
}

static VOID OwlyPowerCallbackRoutine(
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
) {
    UNREFERENCED_PARAMETER(CallbackContext);

    if (Argument1 != (PVOID)(ULONG_PTR)PO_CB_SYSTEM_STATE_LOCK) {
        return;
    }

    if (Argument2 != FALSE) {
        if (InterlockedExchange(&g_ReinitVmmOnResume, 0) == 1) {
            (VOID)HvStartStandaloneVmm();
        }
    } else {
        if (InterlockedCompareExchange(&g_VmmInitialized, 1, 1) == 1) {
            InterlockedExchange(&g_ReinitVmmOnResume, 1);
            HvStopStandaloneVmm();
        }
    }
}

static VOID OwlyRegisterPowerCallback(VOID) {
    UNICODE_STRING objName = RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
    OBJECT_ATTRIBUTES objAttr;
    PCALLBACK_OBJECT callbackObj = NULL;

    InitializeObjectAttributes(&objAttr, &objName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    if (!NT_SUCCESS(ExCreateCallback(&callbackObj, &objAttr, FALSE, TRUE))) {
        return;
    }

    g_PowerCallbackReg = ExRegisterCallback(callbackObj, OwlyPowerCallbackRoutine, NULL);
    ObDereferenceObject(callbackObj);
}

static VOID OwlyUnregisterPowerCallback(VOID) {
    if (g_PowerCallbackReg != NULL) {
        ExUnregisterCallback(g_PowerCallbackReg);
        g_PowerCallbackReg = NULL;
    }
}

static VOID OwlyHvDrainThread(_In_ PVOID Context) {
    LARGE_INTEGER interval;
    UNREFERENCED_PARAMETER(Context);

    interval.QuadPart = -250000LL; // 25ms

    while (InterlockedCompareExchange(&g_OwlyDrainStop, 0, 0) == 0) {
        ULONG batchCount = 0;

        while (batchCount < OWLY_HV_RING_CAPACITY &&
               InterlockedCompareExchange(&g_OwlyDrainStop, 0, 0) == 0)
        {
            BOOLEAN drainedOne = FALSE;
            ULONG offset;

            for (offset = 0; offset < OWLY_HV_RING_CAPACITY; offset++) {
                ULONG idx = (g_OwlyRingReadIdx + offset) & OWLY_HV_RING_MASK;
                if (InterlockedCompareExchange(&g_OwlyEventRing[idx].Ready, 3, 2) == 2) {
                    OWLY_HV_EVENT_DETAILS localDetails;
                    POWLY_HV_CALLBACK cb;

                    RtlCopyMemory(&localDetails, &g_OwlyEventRing[idx].Details, sizeof(localDetails));
                    InterlockedExchange(&g_OwlyEventRing[idx].Ready, 0);
                    g_OwlyRingReadIdx = idx + 1UL;
                    drainedOne = TRUE;
                    batchCount++;

                    cb = (POWLY_HV_CALLBACK)(ULONG_PTR)InterlockedCompareExchangePointer(
                        &g_OwlyCallbackPtr, NULL, NULL);
                    if (cb != NULL) {
                        cb(&localDetails);
                    }
                    break;
                }
            }

            if (!drainedOne) {
                break;
            }
        }

        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DrvDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DrvDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesWritten = 0;

    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_REGISTER_OWLY_CALLBACK) {
        if (Irp->RequestorMode != KernelMode) {
            status = STATUS_ACCESS_DENIED;
        } else if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(OWLY_HV_COMM_DATA)) {
            POWLY_HV_COMM_DATA commData = (POWLY_HV_COMM_DATA)Irp->AssociatedIrp.SystemBuffer;
            if (commData->Magic == OWLY_HV_COMM_MAGIC) {
                InterlockedExchangePointer(&g_OwlyCallbackPtr, commData->CallbackRoutine);
                DbgPrint("!!! hyperhv: Registered Owlyshield callback at %p\n", commData->CallbackRoutine);

                if (commData->CallbackRoutine != NULL) {
                    InterlockedExchange(&g_OwlyDrainStop, 0);
                    if (g_OwlyDrainThreadHandle == NULL) {
                        NTSTATUS thStatus = PsCreateSystemThread(
                            &g_OwlyDrainThreadHandle,
                            THREAD_ALL_ACCESS,
                            NULL,
                            NULL,
                            NULL,
                            OwlyHvDrainThread,
                            NULL
                        );
                        if (!NT_SUCCESS(thStatus)) {
                            g_OwlyDrainThreadHandle = NULL;
                            InterlockedExchangePointer(&g_OwlyCallbackPtr, NULL);
                            status = thStatus;
                        }
                    }

                    if (NT_SUCCESS(status)) {
                        (VOID)HvStartStandaloneVmm();
                    }
                }
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
    } else {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesWritten;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// Helper function to enqueue events from VMX-root / Dispatch paths without calling kernel APIs directly
VOID HvSendEventToOwlyshield(
    _In_ ULONG EventType,
    _In_opt_ PVOID MemoryAddress,
    _In_ SIZE_T MemorySize,
    _In_ ULONG CoreId,
    _In_opt_ ULONGLONG Context
) {
    LONG rawIdx;
    ULONG idx;
    ULONG srcPid;

    if (InterlockedCompareExchangePointer(&g_OwlyCallbackPtr, NULL, NULL) == NULL) {
        return;
    }

    if (!OwlyHvShouldReportEvent(EventType, Context)) {
        return;
    }

    rawIdx = InterlockedIncrement(&g_OwlyRingWriteIdx) - 1;
    idx = ((ULONG)rawIdx) & OWLY_HV_RING_MASK;
    if (InterlockedCompareExchange(&g_OwlyEventRing[idx].Ready, 1, 0) != 0) {
        return;
    }

    RtlZeroMemory(&g_OwlyEventRing[idx].Details, sizeof(g_OwlyEventRing[idx].Details));
    srcPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    g_OwlyEventRing[idx].Details.RawEventType = EventType;
    g_OwlyEventRing[idx].Details.SourceProcessId = srcPid;
    g_OwlyEventRing[idx].Details.TargetProcessId = srcPid;
    g_OwlyEventRing[idx].Details.MemoryAddress = MemoryAddress;
    g_OwlyEventRing[idx].Details.MemorySize = MemorySize;
    g_OwlyEventRing[idx].Details.CoreId = CoreId;
    g_OwlyEventRing[idx].Details.ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    g_OwlyEventRing[idx].Details.Context = Context;
    g_OwlyEventRing[idx].Details.EventName = OwlyHvEventLiteralName(EventType);

    InterlockedExchange(&g_OwlyEventRing[idx].Ready, 2);
}

VOID DrvUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\hyperhv");

    InterlockedExchangePointer(&g_OwlyCallbackPtr, NULL);
    InterlockedExchange(&g_OwlyDrainStop, 1);

    if (g_OwlyDrainThreadHandle != NULL) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -(1LL * 1000LL * 1000LL * 10LL);
        (VOID)ZwWaitForSingleObject(g_OwlyDrainThreadHandle, FALSE, &timeout);
        ZwClose(g_OwlyDrainThreadHandle);
        g_OwlyDrainThreadHandle = NULL;
    }

    OwlyUnregisterPowerCallback();
    HvStopStandaloneVmm();

    IoDeleteSymbolicLink(&symLink);
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
    DbgPrint("!!! hyperhv: Standalone driver unloaded.\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\hyperhv");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\hyperhv");
    PDEVICE_OBJECT deviceObject = NULL;

    RtlZeroMemory(g_OwlyEventRing, sizeof(g_OwlyEventRing));

#if DBG
    DriverObject->DriverUnload = DrvUnload;
#else
    DriverObject->DriverUnload = NULL;
#endif
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DrvDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DrvDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvDispatchDeviceControl;

    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("!!! hyperhv: IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("!!! hyperhv: IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    OwlyRegisterPowerCallback();
    DbgPrint("!!! hyperhv: Standalone driver loaded successfully.\n");
    return STATUS_SUCCESS;
}
