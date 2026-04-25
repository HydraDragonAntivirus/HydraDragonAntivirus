#include "DriverCommon.h"
#include "ProtectBoot.h"

#include <fltKernel.h>
#include <ntdddisk.h>
#include <ntddscsi.h>

#ifndef IOCTL_DISK_FORMAT_TRACKS
#define IOCTL_DISK_FORMAT_TRACKS \
    CTL_CODE(IOCTL_DISK_BASE, 0x0006, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

#ifndef IOCTL_DISK_FORMAT_TRACKS_EX
#define IOCTL_DISK_FORMAT_TRACKS_EX \
    CTL_CODE(IOCTL_DISK_BASE, 0x000B, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

//
// This file blocks dangerous user-mode disk-management IOCTLs.
// It reuses your existing SendMessageToUser path.
// It does NOT create a second alert pipe.
//

static
BOOLEAN
ProtectBoot_IsDangerousDiskIoctl(
    _In_ ULONG IoControlCode
    )
{
    switch (IoControlCode)
    {
    case IOCTL_DISK_SET_DRIVE_LAYOUT_EX:
    case IOCTL_SCSI_PASS_THROUGH_DIRECT:
    case IOCTL_DISK_FORMAT_TRACKS:
    case IOCTL_DISK_FORMAT_TRACKS_EX:
        return TRUE;

    default:
        return FALSE;
    }
}

extern "C"
FLT_PREOP_CALLBACK_STATUS
ProtectBoot_PreDeviceControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data == NULL || Data->Iopb == NULL)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Do not interfere with kernel-mode storage stack operations.
    //
    if (Data->RequestorMode == KernelMode)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // IsProcessTrusted() uses pageable-style operations/path lookup/cache locks.
    // Only call it at PASSIVE_LEVEL. At higher IRQL, avoid false blocking.
    //
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    const ULONG ioControlCode =
        Data->Iopb->Parameters.DeviceIoControl.Common.IoControlCode;

    if (!ProtectBoot_IsDangerousDiskIoctl(ioControlCode))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    const HANDLE pid = PsGetCurrentProcessId();

    if (IsProcessTrusted(pid))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    UNICODE_STRING msg = RTL_CONSTANT_STRING(L"Disk_Wiper_Attempt");

    SendMessageToUser(
        4001,
        (ULONG)(ULONG_PTR)pid,
        msg.Buffer,
        msg.Length
        );

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;

    return FLT_PREOP_COMPLETE;
}
