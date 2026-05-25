#include "pch.h"
#include <ntddk.h>

// IOCTL for Hypervisor communication
#define IOCTL_REGISTER_OWLY_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Event details structure for Owlyshield communication
typedef struct _OWLY_HV_EVENT_DETAILS
{
    ULONG RawEventType;
    ULONG SourceProcessId;
    ULONG TargetProcessId;
    PVOID MemoryAddress;
    SIZE_T MemorySize;
    ULONG CoreId;
    ULONG ThreadId;
    ULONGLONG Context;

    // DLL Load Detection
    BOOLEAN IsDllLoad;
    PCWSTR LoadedDllPath;
    BOOLEAN IsApiBasedLoad;

    // ACG Detection
    BOOLEAN IsAcgEnabled;
} OWLY_HV_EVENT_DETAILS, *POWLY_HV_EVENT_DETAILS;

typedef VOID (NTAPI *POWLY_HV_CALLBACK)(POWLY_HV_EVENT_DETAILS EventDetails);

typedef struct _OWLY_HV_COMM_DATA {
    ULONG Magic;           // 0x4F574C59 ('OWLY')
    PVOID CallbackRoutine; // POWLY_HV_CALLBACK
} OWLY_HV_COMM_DATA, *POWLY_HV_COMM_DATA;

// Global callback pointer
POWLY_HV_CALLBACK g_OwlyCallback = NULL;

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
            if (commData->Magic == 0x4F574C59) {
                g_OwlyCallback = commData->CallbackRoutine;
                DbgPrint("!!! hyperhv: Registered Owlyshield callback at %p\n", g_OwlyCallback);
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

// Helper function to send events to Owlyshield
VOID HvSendEventToOwlyshield(
    _In_ ULONG EventType,
    _In_opt_ PVOID MemoryAddress,
    _In_ SIZE_T MemorySize,
    _In_ ULONG CoreId,
    _In_opt_ ULONGLONG Context
) {
    if (g_OwlyCallback == NULL) {
        return;
    }

    OWLY_HV_EVENT_DETAILS details = {0};
    details.RawEventType = EventType;
    details.MemoryAddress = MemoryAddress;
    details.MemorySize = MemorySize;
    details.CoreId = CoreId;
    details.Context = Context;
    details.SourceProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    details.ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();

    // Call the registered callback
    g_OwlyCallback(&details);
}

VOID DrvUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\hyperhv");
    IoDeleteSymbolicLink(&symLink);
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
    g_OwlyCallback = NULL;
    DbgPrint("!!! hyperhv: Standalone driver unloaded.\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\hyperhv");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\hyperhv");
    PDEVICE_OBJECT deviceObject = NULL;

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

    DbgPrint("!!! hyperhv: Standalone driver loaded successfully.\n");
    return STATUS_SUCCESS;
}
